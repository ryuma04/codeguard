// codeguard: single-binary client and execution gate for the CodeGuard engine.
//
// The detection engine stays warm in Python (python -m codeguard.api); this CLI
// talks to it over localhost HTTP, so a check costs a few milliseconds instead of
// starting a Python process per check.
//
//	codeguard scan  <file|->                 print the verdict JSON; exit 2 on block
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
}

type client struct {
	url  string
	http *http.Client
}

func newClient(url string, timeout time.Duration) *client {
	return &client{url: strings.TrimRight(url, "/"), http: &http.Client{Timeout: timeout}}
}

func (c *client) analyze(code string) (*Verdict, error) {
	body, _ := json.Marshal(map[string]string{"code": code})
	resp, err := c.http.Post(c.url+"/analyze", "application/json", bytes.NewReader(body))
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

func printVerdict(v *Verdict, asJSON bool) {
	if asJSON {
		out, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(out))
		return
	}
	mark := "ALLOW"
	if v.Verdict == "block" {
		mark = "BLOCK"
	}
	fmt.Printf("%s  risk=%.2f  lang=%s  latency=%.1fms\n", mark, v.RiskScore, v.CodeLanguage, v.LatencyMS)
	if len(v.Categories) > 0 {
		fmt.Printf("  categories: %s\n", strings.Join(v.Categories, ", "))
	}
	if len(v.VulnerableLines) > 0 {
		fmt.Printf("  lines: %v\n", v.VulnerableLines)
	}
	if v.Reason != "" {
		fmt.Printf("  reason: %s\n", v.Reason)
	}
}

// ---------------------------------------------------------------- scan
func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	url := fs.String("url", defaultURL(), "engine URL")
	timeout := fs.Duration("timeout", 2*time.Second, "per-check timeout")
	pretty := fs.Bool("pretty", false, "human-readable output instead of JSON")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: codeguard scan [--url U] [--pretty] <file|->")
		return exitUsage
	}
	code, err := readSource(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		return exitUsage
	}
	v, err := newClient(*url, *timeout).analyze(code)
	if err != nil {
		v = failClosed(err)
	}
	printVerdict(v, !*pretty)
	if v.Verdict == "block" {
		return exitBlock
	}
	return exitAllow
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
	for _, it := range items {
		v, err := c.analyze(it.code)
		if err != nil {
			v = failClosed(err)
		}
		if v.Verdict != "allow" {
			fmt.Fprintf(os.Stderr, "codeguard: BLOCKED %s, command was NOT started\n", it.name)
			fmt.Fprintf(os.Stderr, "  risk=%.2f categories=%v lines=%v\n  reason: %s\n", v.RiskScore, v.Categories, v.VulnerableLines, v.Reason)
			return exitBlock
		}
		fmt.Fprintf(os.Stderr, "codeguard: allow %s (risk=%.2f, %.1fms)\n", it.name, v.RiskScore, v.LatencyMS)
	}

	child := exec.Command(cmd[0], cmd[1:]...)
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
