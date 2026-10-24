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

	// 4. the flagged lines themselves
	if blocked && len(v.VulnerableLines) > 0 && code != "" {
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
