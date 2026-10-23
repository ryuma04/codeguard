package main

// Detailed, human-readable verdict "card" for the terminal: the same facts the web UI
// shows (verdict, risk bar with threshold, language, latency, reasons, per-category
// scores, flagged source lines). Colours only on a real terminal; NO_COLOR turns them off.

import (
	"fmt"
	"io"
	"os"
	"sort"
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
	s := strings.ReplaceAll(c, "_", " ")
	return strings.ToUpper(s[:1]) + s[1:]
}

func printCard(w io.Writer, p palette, v *Verdict, code, name string) {
	color, mark := p.green, "ALLOW"
	if v.Verdict == "block" {
		color, mark = p.red, "BLOCK"
	}
	rule := p.dim + strings.Repeat("─", 64) + p.reset
	fmt.Fprintln(w, rule)
	if name != "" {
		fmt.Fprintf(w, "%s%s%s\n", p.dim, name, p.reset)
	}
	fmt.Fprintf(w, "%s%s %s %s   risk %s%.3f%s\n", color+p.bold, "▌", mark, p.reset, p.bold, v.RiskScore, p.reset)
	fmt.Fprintf(w, "%s%s%s  %sthreshold %.2f%s\n", color, bar(v.RiskScore, 40, blockThreshold), p.reset, p.dim, blockThreshold, p.reset)
	facts := []string{"language " + p.bold + v.CodeLanguage + p.reset}
	if v.LatencyMS > 0 {
		facts = append(facts, fmt.Sprintf("engine %s%.2f ms%s", p.bold, v.LatencyMS, p.reset))
	}
	if v.RoundTripMS > 0 {
		facts = append(facts, fmt.Sprintf("round-trip %s%.2f ms%s", p.bold, v.RoundTripMS, p.reset))
	}
	if v.DecodedLayers > 0 {
		facts = append(facts, fmt.Sprintf("decoded layers %s%d%s", p.bold, v.DecodedLayers, p.reset))
	}
	fmt.Fprintln(w, strings.Join(facts, p.dim+"  ·  "+p.reset))

	if v.Reason != "" {
		title := "Why"
		if v.Verdict != "block" {
			title = "Notes"
		}
		fmt.Fprintf(w, "\n%s%s%s\n", p.bold, title, p.reset)
		for _, r := range strings.Split(v.Reason, "; ") {
			fmt.Fprintf(w, "  • %s\n", r)
		}
	}

	if len(v.CategoryScores) > 0 || len(v.Categories) > 0 {
		scores := map[string]float64{}
		for k, s := range v.CategoryScores {
			scores[k] = s
		}
		for _, c := range v.Categories {
			if _, ok := scores[c]; !ok {
				scores[c] = v.RiskScore
			}
		}
		cats := make([]string, 0, len(scores))
		for c := range scores {
			cats = append(cats, c)
		}
		sort.Slice(cats, func(i, j int) bool { return scores[cats[i]] > scores[cats[j]] })
		fmt.Fprintf(w, "\n%sCategories%s\n", p.bold, p.reset)
		for _, c := range cats {
			cc := p.dim
			if scores[c] >= blockThreshold {
				cc = p.red
			} else if scores[c] >= 0.3 {
				cc = p.yellow
			}
			fmt.Fprintf(w, "  %s%-24s %s %.2f%s\n", cc, prettyCategory(c), bar(scores[c], 16, 0), scores[c], p.reset)
		}
	}

	if len(v.VulnerableLines) > 0 && code != "" {
		lines := strings.Split(strings.ReplaceAll(code, "\r\n", "\n"), "\n")
		fmt.Fprintf(w, "\n%sFlagged lines%s\n", p.bold, p.reset)
		for i, n := range v.VulnerableLines {
			if i == 10 {
				fmt.Fprintf(w, "  %s… %d more%s\n", p.dim, len(v.VulnerableLines)-10, p.reset)
				break
			}
			if n < 1 || n > len(lines) {
				continue
			}
			text := strings.TrimRight(lines[n-1], " \t")
			if r := []rune(text); len(r) > 100 {
				text = string(r[:100]) + "…"
			}
			fmt.Fprintf(w, "  %s%4d%s │ %s\n", p.red, n, p.reset, text)
		}
	}
	fmt.Fprintln(w, rule)
}
