// Short task names for the demo and day-to-day use: `npm run <task>` (see package.json).
// Node standard library only. Works from cmd.exe, PowerShell, Git Bash, macOS and Linux.
const { spawn, spawnSync } = require("child_process");
const fs = require("fs");
const http = require("http");
const path = require("path");

const ROOT = path.join(__dirname, "..");
const WIN = process.platform === "win32";
const PY = process.env.PYTHON || (WIN ? "python" : "python3");
const BIN = path.join(ROOT, "cli", WIN ? "codeguard.exe" : "codeguard");
const URL = process.env.CODEGUARD_URL || "http://127.0.0.1:8000";

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

function cli(args, env) {
  if (!fs.existsSync(BIN) && buildCli() !== 0) {
    console.error("CLI not built and `go build` failed. Install Go, then: npm run build");
    return 1;
  }
  return run(BIN, args, { env });
}

// The demo pair writes its marker file here instead of into the repo.
const demoEnv = () => {
  const out = fs.mkdtempSync(path.join(require("os").tmpdir(), "codeguard_demo_"));
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

const tasks = {
  start,
  engine: () => run(PY, ["-m", "codeguard.api", "--port", "8000"]),
  ui: () => run("npm", ["--prefix", "ui", "run", "dev"], { shell: WIN }),
  build: buildCli,
  cg: (a) => cli(a),                                   // any CLI command: npm run cg -- bench eval/
  scan: (a) => cli(["scan", "--pretty", ...a]),        // files, folders, globs, or -c "<code>"
  gate: (a) => cli(["run", ...a]),                     // run a file only if CodeGuard allows it
  i: () => cli(["i"]),
  health: () => cli(["health"]),
  bench: (a) => cli(["bench", ...(a.length ? a : ["eval/"])]),
  safe: () => cli(["run", "demo/gate/safe_snippet.py"], demoEnv()),
  unsafe: () => cli(["run", "demo/gate/unsafe_snippet.py"], demoEnv()),
  demo: () => run(PY, ["demo/intercept_check.py"]) || run(PY, ["demo/cli_gate_check.py"]),
  check: () => run(PY, ["eval/regressions.py"]) || run(PY, ["eval/evaluate.py"]),
  "plugin-test": () => run(PY, ["plugin/test_hook.py"]),
};

(async () => {
  const [name, ...args] = process.argv.slice(2);
  if (!tasks[name]) {
    console.error(`unknown task "${name}". Tasks: ${Object.keys(tasks).join(", ")}`);
    process.exit(64);
  }
  const code = await tasks[name](args);
  if (typeof code === "number") process.exit(code);
})();
