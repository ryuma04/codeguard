#!/usr/bin/env node
// `codeguard` command: one entry point for the engine, UI, demos, tests and the Go CLI gate.
// Install once from the repo root with `npm link`; then run `codeguard <command>` from any folder.
// Node standard library only. Works from cmd.exe, PowerShell, Git Bash, macOS and Linux.
const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const WIN = process.platform === "win32";
const PY = process.env.PYTHON || (WIN ? "python" : "python3");
const BIN = path.join(ROOT, "cli", WIN ? "codeguard.exe" : "codeguard");
const URL = process.env.CODEGUARD_URL || "http://127.0.0.1:8000";

const HELP = `codeguard: pre-execution safety layer for AI-generated code

Checking code (paths are relative to your current folder)
  codeguard scan <file>                 verdict card: risk, reasons, categories, flagged lines (never runs it)
  codeguard scan <files|dirs|globs>     one line per file + summary (-v: a card per file)
  codeguard scan -c "<code>"            check inline code
  codeguard scan --json <file>          raw schema JSON
  codeguard run <file> [args]           verdict card, then run it (python/bash/node/...) only if allowed
  codeguard exec -- <command> [args]    gate any command: runs only if allowed
  codeguard i                           interactive: paste snippets (end with a "." line) or type paths

Services
  codeguard start                       engine + web UI together (Ctrl+C stops both)
  codeguard engine                      engine only (http://127.0.0.1:8000)
  codeguard ui                          web UI only (http://localhost:3000)
  codeguard health                      is the engine up?

Demos and tests
  codeguard demo                        all three interception proofs
  codeguard demo safe | unsafe          gate one half of the demo pair live
  codeguard demo heal                   self-healing loop proof
  codeguard test                        regressions + self-healing edge cases + holdout
  codeguard test plugin | stress        Claude Code plugin hook checks | robustness under odd input and load
  codeguard bench [dir|file.jsonl]      latency / throughput

  codeguard build                       rebuild the Go gate binary (cli/)
  codeguard help                        this text

Engine address: $CODEGUARD_URL (default ${URL})`;

function run(cmd, args, opts = {}) {
  const r = spawnSync(cmd, args, { cwd: opts.cwd || ROOT, stdio: "inherit", shell: opts.shell || false, env: opts.env || process.env });
  if (r.error) {
    console.error(`cannot start ${cmd}: ${r.error.message}`);
    return 127;
  }
  return r.status ?? 1;
}

function buildCli() {
  console.log("building cli/ (go build)...");
  return run("go", ["build", "-o", path.basename(BIN), "."], { cwd: path.join(ROOT, "cli") }) ||
    (fs.existsSync(BIN) ? 0 : 1);
}

// The Go gate runs in the caller's folder, so relative paths mean what the user typed.
function cli(args, opts = {}) {
  if (!fs.existsSync(BIN) && buildCli() !== 0) {
    console.error("The Go gate is not built and `go build` failed. Install Go, then: codeguard build");
    return 1;
  }
  return run(BIN, args, { cwd: opts.cwd || process.cwd(), env: opts.env });
}

// The demo pair writes its marker file here instead of into the repo.
const demoEnv = () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), "codeguard_demo_"));
  console.log(`marker folder: ${out}`);
  return { ...process.env, CODEGUARD_DEMO_OUT: out };
};

function engineUp(timeoutMs = 1000) {
  return new Promise((resolve) => {
    const req = http.get(URL + "/health", { timeout: timeoutMs }, (res) => { res.resume(); resolve(res.statusCode === 200); });
    req.on("error", () => resolve(false));
    req.on("timeout", () => { req.destroy(); resolve(false); });
  });
}

// Engine + UI together, output prefixed; Ctrl+C stops both.
async function start() {
  const children = [];
  const launch = (name, cmd, args, opts = {}) => {
    const p = spawn(cmd, args, { cwd: ROOT, shell: opts.shell || false, env: process.env });
    const tag = (s) => s.toString().split(/\r?\n/).filter(Boolean).forEach((l) => console.log(`[${name}] ${l}`));
    p.stdout.on("data", tag);
    p.stderr.on("data", tag);
    p.on("exit", (code) => console.log(`[${name}] exited (${code})`));
    children.push(p);
  };
  const stop = () => { children.forEach((p) => { try { p.kill(); } catch {} }); process.exit(0); };
  process.on("SIGINT", stop);
  process.on("SIGTERM", stop);

  if (await engineUp()) {
    console.log(`[engine] already running at ${URL}`);
  } else {
    launch("engine", PY, ["-m", "codeguard.api", "--port", "8000"]);
    for (let i = 0; i < 60 && !(await engineUp()); i++) await new Promise((r) => setTimeout(r, 500));
  }
  if (!fs.existsSync(BIN)) buildCli();
  if (!fs.existsSync(path.join(ROOT, "ui", "node_modules"))) {
    console.log("[ui] installing dependencies (first run)...");
    run("npm", ["--prefix", "ui", "install"], { shell: WIN });
  }
  launch("ui", "npm", ["--prefix", "ui", "run", "dev"], { shell: WIN });
  console.log("\nEngine: " + URL + "   UI: http://localhost:3000   (Ctrl+C stops both)\n");
}

const py = (...scripts) => scripts.reduce((code, s) => code || run(PY, s.split(" ")), 0);

const DEMOS = {
  all: () => py("demo/intercept_check.py", "demo/cli_gate_check.py", "demo/heal_check.py"),
  intercept: () => py("demo/intercept_check.py"),
  gate: () => py("demo/cli_gate_check.py"),
  heal: () => py("demo/heal_check.py"),
  safe: () => cli(["run", "demo/gate/safe_snippet.py"], { cwd: ROOT, env: demoEnv() }),
  unsafe: () => cli(["run", "demo/gate/unsafe_snippet.py"], { cwd: ROOT, env: demoEnv() }),
};

const TESTS = {
  all: () => py("eval/regressions.py", "eval/heal_tests.py", "eval/evaluate.py"),
  regressions: () => py("eval/regressions.py"),
  holdout: () => py("eval/evaluate.py"),
  heal: () => py("eval/heal_tests.py"),
  plugin: () => py("plugin/test_hook.py"),
  stress: () => run(PY, ["eval/stress_test.py", "--url", URL]),
};

function sub(table, kind) {
  return ([which = "all"]) => {
    if (table[which]) return table[which]();
    console.error(`unknown ${kind} "${which}". Choose: ${Object.keys(table).join(", ")}`);
    return 64;
  };
}

function scan(args) {
  // A single file gets the full card; --json gives the raw schema response instead.
  if (args.includes("--json")) return cli(["scan", ...args.filter((a) => a !== "--json")]);
  return cli(["scan", "--pretty", ...args]);
}

const COMMANDS = {
  scan,
  run: (a) => cli(["run", ...a]),
  exec: (a) => cli(["exec", ...a]),
  i: () => cli(["i"]),
  interactive: () => cli(["i"]),
  health: () => cli(["health"]),
  bench: (a) => cli(["bench", ...(a.length ? a : [path.join(ROOT, "eval")])]),
  start,
  engine: () => run(PY, ["-m", "codeguard.api", "--port", "8000"]),
  ui: () => run("npm", ["--prefix", "ui", "run", "dev"], { shell: WIN }),
  build: buildCli,
  demo: sub(DEMOS, "demo"),
  test: sub(TESTS, "test"),
  help: () => { console.log(HELP); return 0; },
};

(async () => {
  const [name, ...args] = process.argv.slice(2);
  if (!name || name === "-h" || name === "--help") {
    console.log(HELP);
    process.exit(name ? 0 : 64);
  }
  if (!COMMANDS[name]) {
    console.error(`codeguard: unknown command "${name}"\n`);
    console.log(HELP);
    process.exit(64);
  }
  const code = await COMMANDS[name](args);
  if (typeof code === "number") process.exit(code);
})();
