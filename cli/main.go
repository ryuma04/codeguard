// codeguard: single-binary client and execution gate for the CodeGuard engine.
//
// The detection engine stays warm in Python (python -m codeguard.api); this CLI
// talks to it over localhost HTTP, so a check costs a few milliseconds instead of
// starting a Python process per check.
//
//	codeguard scan  <file|->                 print the verdict JSON; exit 2 on block
//	codeguard scan  <files|dirs|globs...>    one line per file + summary; exit 2 if any block
//	codeguard scan  -c "<code>"              scan inline code
//	codeguard run   <file> [args...]         exec with the interpreter picked from the extension
//	codeguard i                              interactive: paste snippets or file paths, one after another
//	codeguard exec  [--file F] -- <cmd...>   scan, then run <cmd> ONLY on allow
//	codeguard bench <dir|file.jsonl>         replay snippets, report latency
//	codeguard health                         check the engine is reachable
//
// Fail closed: if the engine is unreachable, times out or answers garbage, scan
// and exec treat it as a block. Standard library only.
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	exitAllow = 0
	exitBlock = 2
	exitUsage = 64
)

// Verdict mirrors the fixed response schema (plus latency_ms).
type Verdict struct {
	Verdict         string   `json:"verdict"`
	RiskScore       float64  `json:"risk_score"`
	Categories      []string `json:"categories"`
	CodeLanguage    string   `json:"code_language"`
	Reason          string   `json:"reason,omitempty"`
	VulnerableLines []int    `json:"vulnerable_lines,omitempty"`
	LatencyMS       float64  `json:"latency_ms,omitempty"`
	// Only filled by analyzeDetail (engine debug view), for the terminal card.
	CategoryScores map[string]float64 `json:"category_scores,omitempty"`
	DecodedLayers  int                `json:"decoded_layers,omitempty"`
	Evidence       []Evidence         `json:"evidence,omitempty"`
	RoundTripMS    float64            `json:"-"`
}

// Evidence is one chain explaining a block (engine debug view): source -> sink, encoded -> decoded -> exec, ...
type Evidence struct {
	Category string         `json:"category"`
	Reason   string         `json:"reason"`
	Weight   float64        `json:"weight"`
	Steps    []EvidenceStep `json:"steps"`
}

type EvidenceStep struct {
	Line  int    `json:"line"`
	Role  string `json:"role"` // source | encoded | decoded | carrier | step | sink | finding
	Label string `json:"label"`
	Via   string `json:"via,omitempty"`
	Code  string `json:"code,omitempty"`
}

type client struct {
	url  string
	http *http.Client
}

func newClient(url string, timeout time.Duration) *client {
	return &client{url: strings.TrimRight(url, "/"), http: &http.Client{Timeout: timeout}}
}

func (c *client) analyze(code string) (*Verdict, error) { return c.post(code, false) }

// analyzeDetail also asks for per-category scores and measures the round trip.
func (c *client) analyzeDetail(code string) (*Verdict, error) {
	t := time.Now()
	v, err := c.post(code, true)
	if v != nil {
		v.RoundTripMS = float64(time.Since(t).Microseconds()) / 1000
	}
	return v, err
}

func (c *client) post(code string, debug bool) (*Verdict, error) {
	body, _ := json.Marshal(map[string]string{"code": code})
	endpoint := c.url + "/analyze"
	if debug {
		endpoint += "?debug=1"
	}
	resp, err := c.http.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("engine returned HTTP %d", resp.StatusCode)
	}
	var v Verdict
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, fmt.Errorf("bad response: %w", err)
	}
	if v.Verdict != "allow" && v.Verdict != "block" {
		return nil, fmt.Errorf("bad verdict %q", v.Verdict)
	}
	return &v, nil
}

// failClosed turns any engine error into a block verdict.
func failClosed(err error) *Verdict {
	return &Verdict{Verdict: "block", RiskScore: 1, Categories: []string{}, CodeLanguage: "unknown",
		Reason: "guard unavailable, failing closed: " + err.Error()}
}

func defaultURL() string {
	if u := os.Getenv("CODEGUARD_URL"); u != "" {
		return u
	}
	return "http://127.0.0.1:8000"
}

func readSource(path string) (string, error) {
	if path == "-" {
		b, err := io.ReadAll(os.Stdin)
		return string(b), err
	}
	b, err := os.ReadFile(path)
	return string(b), err
}

// printJSON prints the schema response; the human-readable view is printCard (card.go).
func printJSON(v *Verdict) {
	out, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(out))
}

// ---------------------------------------------------------------- scan
func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	url := fs.String("url", defaultURL(), "engine URL")
	timeout := fs.Duration("timeout", 2*time.Second, "per-check timeout")
	pretty := fs.Bool("pretty", false, "human-readable output instead of JSON")
	inline := fs.String("c", "", "scan this code string instead of a file")
	verbose := fs.Bool("v", false, "with several files: full detail card for each")
	graph := fs.Bool("graph", false, "show only the evidence chain: how the code reaches the flagged behaviour")
	fs.Parse(args)
	c := newClient(*url, *timeout)
	if *inline != "" || (fs.NArg() == 1 && !isMulti(fs.Arg(0))) {
		code, name := *inline, ""
		if code == "" {
			var err error
			if code, err = readSource(fs.Arg(0)); err != nil {
				fmt.Fprintln(os.Stderr, "read:", err)
				return exitUsage
			}
			name = fs.Arg(0)
		}
		card := *pretty || *inline != "" || *graph
		var v *Verdict
		var err error
		if card {
			v, err = c.analyzeDetail(code)
		} else {
			v, err = c.analyze(code)
		}
		if err != nil {
			v = failClosed(err)
		}
		if *graph {
			printGraph(os.Stdout, paletteFor(os.Stdout), v, name)
		} else if card {
			printCard(os.Stdout, paletteFor(os.Stdout), v, code, name)
		} else {
			printJSON(v)
		}
		if v.Verdict == "block" {
			return exitBlock
		}
		return exitAllow
	}
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: codeguard scan [--pretty] <file|-> | <files|dirs|globs...> | -c \"<code>\"")
		return exitUsage
	}
	files, err := expandTargets(fs.Args())
	if err != nil || len(files) == 0 {
		fmt.Fprintln(os.Stderr, "scan: no files found:", err)
		return exitUsage
	}
	return scanMany(c, files, *verbose)
}

// isMulti: a single argument that names a folder or a glob pattern is scanned file by file.
func isMulti(arg string) bool {
	if st, err := os.Stat(arg); err == nil {
		return st.IsDir()
	}
	return strings.ContainsAny(arg, "*?[")
}

var skipDirs = map[string]bool{".git": true, "__pycache__": true, "node_modules": true, ".next": true}

// expandTargets turns files, folders (walked) and glob patterns (expanded here, since
// cmd.exe and PowerShell don't) into a list of readable text files.
func expandTargets(args []string) ([]string, error) {
	var out []string
	for _, a := range args {
		paths := []string{a}
		if _, err := os.Stat(a); err != nil && strings.ContainsAny(a, "*?[") {
			if paths, err = filepath.Glob(a); err != nil {
				return nil, err
			}
		}
		for _, p := range paths {
			st, err := os.Stat(p)
			if err != nil {
				return nil, err
			}
			if !st.IsDir() {
				out = append(out, p)
				continue
			}
			filepath.WalkDir(p, func(f string, d os.DirEntry, err error) error {
				if err != nil {
					return nil
				}
				if d.IsDir() {
					if skipDirs[d.Name()] {
						return filepath.SkipDir
					}
					return nil
				}
				if info, e := d.Info(); e == nil && info.Size() <= 512<<10 {
					out = append(out, f)
				}
				return nil
			})
		}
	}
	return out, nil
}

func scanMany(c *client, files []string, verbose bool) int {
	blocked, allowed, failed := 0, 0, 0
	var lat []float64
	p := paletteFor(os.Stdout)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			fmt.Printf("ERROR  %s: %v\n", f, err)
			failed++
			continue
		}
		if bytes.IndexByte(b[:min(len(b), 8000)], 0) >= 0 {
			continue // binary file
		}
		v, err := c.analyzeDetail(string(b))
		if err != nil {
			v = failClosed(err)
			failed++
		}
		lat = append(lat, v.LatencyMS)
		mark := p.green + "ALLOW" + p.reset
		if v.Verdict == "block" {
			mark = p.red + "BLOCK" + p.reset
			blocked++
		} else {
			allowed++
		}
		if verbose {
			printCard(os.Stdout, p, v, string(b), f)
			continue
		}
		fmt.Printf("%s  %.2f  %-10s  %s", mark, v.RiskScore, v.CodeLanguage, f)
		if len(v.Categories) > 0 {
			fmt.Printf("  [%s]", strings.Join(v.Categories, ", "))
		}
		fmt.Println()
		if v.Verdict == "block" && v.Reason != "" {
			fmt.Printf("       reason: %s\n", v.Reason)
		}
	}
	sort.Float64s(lat)
	fmt.Printf("\n%d scanned: %d blocked, %d allowed, %d errors  (engine p50 %.2f ms)\n",
		blocked+allowed, blocked, allowed, failed, pct(lat, 50))
	if blocked > 0 {
		return exitBlock
	}
	return exitAllow
}

// ---------------------------------------------------------------- run
// interpreterFor picks the interpreter from the file extension.
func interpreterFor(path string) []string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".py":
		if p := os.Getenv("PYTHON"); p != "" {
			return []string{p}
		}
		if _, err := exec.LookPath("python"); err != nil {
			return []string{"python3"}
		}
		return []string{"python"}
	case ".sh", ".bash":
		return []string{"bash"}
	case ".js", ".mjs", ".cjs":
		return []string{"node"}
	case ".ps1":
		return []string{"powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File"}
	case ".rb":
		return []string{"ruby"}
	case ".php":
		return []string{"php"}
	}
	return nil
}

func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	url := fs.String("url", defaultURL(), "engine URL")
	fs.Parse(args)
	if fs.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: codeguard run <file.py|.sh|.js|.ps1|...> [args...]")
		return exitUsage
	}
	file := fs.Arg(0)
	interp := interpreterFor(file)
	if interp == nil {
		fmt.Fprintf(os.Stderr, "codeguard: don't know how to run %q; use: codeguard exec -- <cmd> %s\n", file, file)
		return exitUsage
	}
	execArgs := append([]string{"--url", *url, "--card", "--file", file, "--"}, interp...)
	return cmdExec(append(append(execArgs, file), fs.Args()[1:]...))
}

func showCard(c *client, code, name string) {
	v, err := c.analyzeDetail(code)
	if err != nil {
		v = failClosed(err)
	}
	printCard(os.Stdout, paletteFor(os.Stdout), v, code, name)
}

// ---------------------------------------------------------------- interactive
// Scans snippets one after another without retyping commands. A line that names an
// existing file scans that file; otherwise paste code and end it with a line "." .
func cmdInteractive(args []string) int {
	fs := flag.NewFlagSet("i", flag.ExitOnError)
	url := fs.String("url", defaultURL(), "engine URL")
	timeout := fs.Duration("timeout", 2*time.Second, "per-check timeout")
	fs.Parse(args)
	c := newClient(*url, *timeout)
	fmt.Println("codeguard interactive. Paste code and finish with a line containing only \".\",")
	fmt.Println("or type a file/folder path. \"q\" or Ctrl+C to quit.")
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	var buf []string
	for {
		if len(buf) == 0 {
			fmt.Print("\ncodeguard> ")
		}
		if !sc.Scan() {
			return 0
		}
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.Trim(strings.TrimSpace(line), `"'`)
		if len(buf) == 0 {
			if trimmed == "" {
				continue
			}
			if trimmed == "q" || trimmed == "quit" || trimmed == "exit" {
				return 0
			}
			if st, err := os.Stat(trimmed); err == nil {
				if !st.IsDir() {
					if b, err := os.ReadFile(trimmed); err == nil {
						showCard(c, string(b), trimmed)
					}
				} else if files, err := expandTargets([]string{trimmed}); err == nil {
					scanMany(c, files, false)
				}
				continue
			}
		}
		if strings.TrimSpace(line) != "." {
			buf = append(buf, line)
			continue
		}
		showCard(c, strings.Join(buf, "\n"), "")
		buf = buf[:0]
	}
}

// ---------------------------------------------------------------- exec
// Scans the code that is about to run, and starts the child process ONLY on allow.
// What is scanned: every --file given; otherwise every argument after -- that is
// an existing file; otherwise the command line itself (treated as shell).
func cmdExec(args []string) int {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	url := fs.String("url", defaultURL(), "engine URL")
	timeout := fs.Duration("timeout", 2*time.Second, "per-check timeout")
	var files multiFlag
	fs.Var(&files, "file", "file to scan before running (repeatable)")
	card := fs.Bool("card", false, "print the full verdict card (stderr) before running")
	noPrompt := fs.Bool("no-prompt", false, "never show the edit/block menu; a block just exits 2")
	fs.Parse(args)
	cmd := fs.Args()
	if len(cmd) == 0 {
		fmt.Fprintln(os.Stderr, "usage: codeguard exec [--file F] -- <command> [args...]")
		return exitUsage
	}

	targets := []string(files)
	if len(targets) == 0 {
		for _, a := range cmd[1:] {
			if st, err := os.Stat(a); err == nil && !st.IsDir() {
				targets = append(targets, a)
			}
		}
	}
	type item struct{ name, code string }
	var items []item
	for _, t := range targets {
		code, err := readSource(t)
		if err != nil {
			fmt.Fprintln(os.Stderr, "codeguard: cannot read", t, "-", err, "(blocking)")
			return exitBlock
		}
		items = append(items, item{t, code})
	}
	if len(items) == 0 {
		items = append(items, item{"<command line>", strings.Join(cmd, " ")})
	}

	c := newClient(*url, *timeout)
	p := paletteFor(os.Stderr)
	interactive := promptAllowed(*noPrompt)
	editedLine := "" // set when the user edited the command line itself
	for _, it := range items {
		var v *Verdict
		var err error
		if *card || interactive {
			v, err = c.analyzeDetail(it.code)
		} else {
			v, err = c.analyze(it.code)
		}
		if err != nil {
			v = failClosed(err)
		}
		if *card {
			printCard(os.Stderr, p, v, it.code, it.name)
		}
		if v.Verdict == "allow" {
			if *card {
				fmt.Fprintf(os.Stderr, "%scodeguard: allowed%s\n", p.green, p.reset)
			} else {
				fmt.Fprintf(os.Stderr, "codeguard: allow %s (risk=%.2f, %.1fms)\n", it.name, v.RiskScore, v.LatencyMS)
			}
			continue
		}
		if !*card {
			fmt.Fprintf(os.Stderr, "codeguard: BLOCKED %s, command was NOT started\n", it.name)
			fmt.Fprintf(os.Stderr, "  risk=%.2f categories=%v lines=%v\n  reason: %s\n", v.RiskScore, v.Categories, v.VulnerableLines, v.Reason)
		}
		if !interactive {
			if *card {
				fmt.Fprintf(os.Stderr, "%scodeguard: BLOCKED, command was NOT started%s\n", p.red+p.bold, p.reset)
			}
			return exitBlock
		}
		edited, ok := blockMenu(c, p, it.name, it.code, extFor(it.name), v)
		if !ok {
			fmt.Fprintf(os.Stderr, "%scodeguard: blocked by you, command was NOT started%s\n", p.red+p.bold, p.reset)
			return exitBlock
		}
		if it.name == "<command line>" {
			editedLine = edited
			continue
		}
		// An edited file passed. Save it over the original, or run a temporary copy and leave the original as it was.
		runPath := it.name
		if readChoice(fmt.Sprintf("Save your changes to %s? [y/N] ", it.name)) == "y" {
			if err := os.WriteFile(it.name, []byte(edited), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, "codeguard: cannot save:", err, "(blocking)")
				return exitBlock
			}
		} else {
			tmp, err := os.CreateTemp(filepath.Dir(it.name), "codeguard_edited_*"+extFor(it.name))
			if err != nil {
				fmt.Fprintln(os.Stderr, "codeguard: cannot write the edited copy:", err, "(blocking)")
				return exitBlock
			}
			tmp.WriteString(edited)
			tmp.Close()
			defer os.Remove(tmp.Name())
			runPath = tmp.Name()
		}
		found := false
		for i := range cmd {
			if cmd[i] == it.name {
				cmd[i], found = runPath, true
			}
		}
		if !found && runPath != it.name {
			fmt.Fprintf(os.Stderr, "codeguard: the command does not name %s directly, so only a saved version can be used (blocking)\n", it.name)
			return exitBlock
		}
	}
	if *card || interactive {
		fmt.Fprintf(os.Stderr, "%scodeguard: running: %s%s\n%s\n", p.green, strings.Join(cmd, " "), p.reset, p.dim+strings.Repeat("─", 64)+p.reset)
	}

	child := exec.Command(cmd[0], cmd[1:]...)
	if editedLine != "" {
		child = shellCommand(editedLine)
	}
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "codeguard: cannot start command:", err)
		return 127
	}
	return 0
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// ---------------------------------------------------------------- bench
func loadBench(path string, maxSize int64) ([]string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var out []string
	if st.IsDir() {
		err = filepath.WalkDir(path, func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			if info, e := d.Info(); e == nil && info.Size() <= maxSize {
				if b, e := os.ReadFile(p); e == nil {
					out = append(out, string(b))
				}
			}
			return nil
		})
		return out, err
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if strings.HasSuffix(path, ".jsonl") {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 16<<20)
		for sc.Scan() {
			var rec map[string]any
			if json.Unmarshal(sc.Bytes(), &rec) == nil {
				for _, k := range []string{"code", "snippet", "content"} {
					if s, ok := rec[k].(string); ok {
						out = append(out, s)
						break
					}
				}
			}
		}
		return out, sc.Err()
	}
	b, err := io.ReadAll(f)
	return []string{string(b)}, err
}

func pct(xs []float64, p float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	i := int(p/100*float64(len(xs)-1) + 0.5)
	return xs[i]
}

func cmdBench(args []string) int {
	fs := flag.NewFlagSet("bench", flag.ExitOnError)
	url := fs.String("url", defaultURL(), "engine URL")
	timeout := fs.Duration("timeout", 10*time.Second, "per-check timeout")
	workers := fs.Int("c", 4, "concurrent requests")
	rounds := fs.Int("n", 1, "times to replay the whole set")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: codeguard bench [-c 4] [-n 1] <dir|file.jsonl|file>")
		return exitUsage
	}
	snippets, err := loadBench(fs.Arg(0), 512<<10)
	if err != nil || len(snippets) == 0 {
		fmt.Fprintln(os.Stderr, "bench: nothing to replay:", err)
		return exitUsage
	}
	c := newClient(*url, *timeout)
	jobs := make(chan string)
	var mu sync.Mutex
	var client, server []float64
	blocks, errs := 0, 0
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for code := range jobs {
				t := time.Now()
				v, err := c.analyze(code)
				ms := float64(time.Since(t).Microseconds()) / 1000
				mu.Lock()
				if err != nil {
					errs++
				} else {
					client = append(client, ms)
					server = append(server, v.LatencyMS)
					if v.Verdict == "block" {
						blocks++
					}
				}
				mu.Unlock()
			}
		}()
	}
	for r := 0; r < *rounds; r++ {
		for _, s := range snippets {
			jobs <- s
		}
	}
	close(jobs)
	wg.Wait()
	wall := time.Since(start)
	sort.Float64s(client)
	sort.Float64s(server)
	n := len(client)
	fmt.Printf("requests=%d  errors=%d  blocked=%d  allowed=%d  workers=%d\n", n+errs, errs, blocks, n-blocks, *workers)
	fmt.Printf("throughput: %.0f checks/s  (wall %.2fs)\n", float64(n)/wall.Seconds(), wall.Seconds())
	fmt.Printf("round-trip ms: p50=%.2f p95=%.2f p99=%.2f max=%.2f\n", pct(client, 50), pct(client, 95), pct(client, 99), pct(client, 100))
	fmt.Printf("engine ms:     p50=%.2f p95=%.2f p99=%.2f max=%.2f\n", pct(server, 50), pct(server, 95), pct(server, 99), pct(server, 100))
	if errs > 0 {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------- health
func cmdHealth(args []string) int {
	fs := flag.NewFlagSet("health", flag.ExitOnError)
	url := fs.String("url", defaultURL(), "engine URL")
	fs.Parse(args)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Get(strings.TrimRight(*url, "/") + "/health")
	if err != nil {
		fmt.Println("DOWN:", err)
		return 1
	}
	resp.Body.Close()
	fmt.Printf("UP: %s (HTTP %d)\n", *url, resp.StatusCode)
	return 0
}

func usage() {
	fmt.Fprint(os.Stderr, `codeguard: pre-execution gate for AI-generated code

  codeguard scan  [--pretty] <file|->              verdict JSON, exit 2 on block
  codeguard scan  <files|folders|globs...>         one line per file + summary
  codeguard scan  -c "<code>"                      scan inline code
  codeguard run   <file> [args]                    run file (python/bash/node/...) only if allowed
  codeguard i                                      interactive: paste snippets or paths, one by one
  codeguard exec  [--file F] -- <command> [args]   run command only if allowed
  codeguard bench [-c 4] [-n 1] <dir|file.jsonl>   latency / throughput
  codeguard health                                 is the engine up?

Engine URL: --url, or $CODEGUARD_URL, default http://127.0.0.1:8000
Start the engine with: python -m codeguard.api --port 8000
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(exitUsage)
	}
	var code int
	switch os.Args[1] {
	case "scan":
		code = cmdScan(os.Args[2:])
	case "exec":
		code = cmdExec(os.Args[2:])
	case "run":
		code = cmdRun(os.Args[2:])
	case "i", "interactive":
		code = cmdInteractive(os.Args[2:])
	case "bench":
		code = cmdBench(os.Args[2:])
	case "health":
		code = cmdHealth(os.Args[2:])
	default:
		usage()
		code = exitUsage
	}
	os.Exit(code)
}
