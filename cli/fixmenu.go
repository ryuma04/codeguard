package main

// What happens when `codeguard run` / `exec` blocks code at an interactive terminal:
//
//	[e] Edit and re-check   open a copy in the user's editor; when it is closed, check it again
//	[v] View code           numbered lines, flagged lines marked
//	[b] Block (default)     stop, exit 2
//
// There is no "ask an AI to fix it" here: CodeGuard itself never calls an LLM. In scripts, CI or with
// piped input there is no menu at all (hard block), so nothing hangs waiting for a key.
// CODEGUARD_NO_PROMPT=1 or --no-prompt disables the menu; CODEGUARD_PROMPT=1 forces it (tests).

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var stdinReader = bufio.NewReader(os.Stdin)

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func promptAllowed(noPrompt bool) bool {
	if noPrompt || os.Getenv("CODEGUARD_NO_PROMPT") == "1" {
		return false
	}
	return os.Getenv("CODEGUARD_PROMPT") == "1" || (isTerminal(os.Stdin) && isTerminal(os.Stderr))
}

func readChoice(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	line, err := stdinReader.ReadString('\n')
	if err != nil && line == "" {
		return "" // EOF: treat as the safe default
	}
	return strings.ToLower(strings.TrimSpace(line))
}

// editorCommand returns the user's editor as argv (it must wait until the file is closed).
func editorCommand(path string) []string {
	for _, env := range []string{"CODEGUARD_EDITOR", "VISUAL", "EDITOR"} {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			return append(splitCommand(v), path)
		}
	}
	if code, err := exec.LookPath("code"); err == nil {
		return []string{code, "--wait", path}
	}
	if runtime.GOOS == "windows" {
		return []string{"notepad.exe", path}
	}
	for _, e := range []string{"nano", "vim", "vi"} {
		if p, err := exec.LookPath(e); err == nil {
			return []string{p, path}
		}
	}
	return nil
}

// splitCommand splits "editor --flag" and `"C:\Program Files\x\ed.exe" -w` into argv.
func splitCommand(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case r == ' ' && !inQuote:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// editInEditor writes code to a temp file with the given extension, opens the editor, and returns
// the edited text once the editor exits.
func editInEditor(code, ext string) (string, error) {
	f, err := os.CreateTemp("", "codeguard_edit_*"+ext)
	if err != nil {
		return "", err
	}
	path := f.Name()
	defer os.Remove(path)
	if _, err := f.WriteString(code); err != nil {
		f.Close()
		return "", err
	}
	f.Close()
	argv := editorCommand(path)
	if argv == nil {
		return "", fmt.Errorf("no editor found; set CODEGUARD_EDITOR (e.g. \"code --wait\")")
	}
	fmt.Fprintf(os.Stderr, "Opening %s in %s. Save and close it to continue...\n", path, filepath.Base(argv[0]))
	ed := exec.Command(argv[0], argv[1:]...)
	ed.Stdin, ed.Stdout, ed.Stderr = os.Stdin, os.Stderr, os.Stderr
	if err := ed.Run(); err != nil {
		if _, isExit := err.(*exec.ExitError); !isExit {
			return "", fmt.Errorf("cannot start the editor: %w", err)
		}
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

func viewCode(p palette, code string, flagged []int) {
	marked := map[int]bool{}
	for _, n := range flagged {
		marked[n] = true
	}
	for i, line := range strings.Split(strings.ReplaceAll(code, "\r\n", "\n"), "\n") {
		if marked[i+1] {
			fmt.Fprintf(os.Stderr, "%s>> %4d │ %s%s\n", p.red, i+1, line, p.reset)
		} else {
			fmt.Fprintf(os.Stderr, "   %4d │ %s\n", i+1, line)
		}
	}
	fmt.Fprintf(os.Stderr, "%s(>> = flagged by CodeGuard)%s\n", p.dim, p.reset)
}

// blockMenu runs the edit / view / block loop for one blocked item. It returns the edited code and
// true once an edited version passes CodeGuard, or false if the user blocks (or gives no answer).
func blockMenu(c *client, p palette, name, code, ext string, v *Verdict) (string, bool) {
	for {
		choice := readChoice(fmt.Sprintf(" %sWhat now?%s  %se%s edit & re-check   %sv%s view code   %sb%s block %s(default)%s\n > ",
			p.bold, p.reset, p.bold+p.yellow, p.reset, p.bold+p.yellow, p.reset, p.bold+p.yellow, p.reset, p.dim, p.reset))
		switch choice {
		case "v", "view":
			viewCode(p, code, v.VulnerableLines)
		case "e", "edit":
			edited, err := editInEditor(code, ext)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%scodeguard: %v%s\n", p.yellow, err, p.reset)
				continue
			}
			if strings.TrimSpace(edited) == strings.TrimSpace(code) {
				fmt.Fprintln(os.Stderr, "codeguard: no changes made.")
				continue
			}
			nv, err := c.analyzeDetail(edited)
			if err != nil {
				nv = failClosed(err)
			}
			printCard(os.Stderr, p, nv, edited, name+" (your edit)")
			if nv.Verdict == "allow" {
				return edited, true
			}
			fmt.Fprintf(os.Stderr, "%scodeguard: your edit is still blocked.%s\n", p.red, p.reset)
			code, v = edited, nv
		default: // "b", "block", "", EOF, anything else: the safe answer
			return "", false
		}
	}
}

// extFor picks the temp-file extension so the editor highlights the right language.
func extFor(name string) string {
	if e := filepath.Ext(name); e != "" && !strings.ContainsAny(e, " <>") {
		return e
	}
	if runtime.GOOS == "windows" {
		return ".cmd"
	}
	return ".sh"
}

// shellCommand runs an edited command line through the platform shell.
func shellCommand(line string) *exec.Cmd {
	if runtime.GOOS == "windows" {
		return exec.Command("cmd", "/C", line)
	}
	return exec.Command("sh", "-c", line)
}
