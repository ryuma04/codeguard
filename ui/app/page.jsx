"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { EXAMPLES } from "./examples";
import EvidenceGraph, { hasEvidence } from "./evidence-graph";

const CATEGORY_LABEL = {
  secret_access: "Secret access",
  data_exfiltration: "Data exfiltration",
  destructive_command: "Destructive command",
  persistence_or_privesc: "Persistence / privesc",
  obfuscated_execution: "Obfuscated execution",
  dependency_risk: "Dependency risk",
  resource_exhaustion: "Resource exhaustion",
  ssrf_network_exfil: "SSRF / network",
  ai_targeted_instructions: "AI-targeted instructions",
};
const PUBLIC_KEYS = ["verdict", "risk_score", "categories", "code_language", "reason", "vulnerable_lines"];
// Same safe-alternative hints the CLI and the Claude Code hook give.
const HINTS = {
  secret_access: "Do not read credential stores, keys, tokens or secret environment variables. Take configuration as a parameter.",
  data_exfiltration: "Do not send local data, files or environment details to external hosts. Keep results local.",
  destructive_command: "Only delete or modify paths inside the working directory, never /, ~ or system paths.",
  persistence_or_privesc: "Do not add startup entries, cron jobs, services, sudo/setuid or shell-profile changes.",
  obfuscated_execution: "Write plain code. Do not decode-and-execute, eval built strings, or encode payloads.",
  dependency_risk: "Install only well-known packages from the official index and check the spelling. No piping downloads into a shell.",
  resource_exhaustion: "Bound every loop, recursion, thread and allocation.",
  ssrf_network_exfil: "Only call the hosts the task names. No cloud metadata IPs, localhost admin ports or raw internal IPs.",
  ai_targeted_instructions: "Remove comments or strings that address an AI reviewer or tell it to ignore rules or mark code safe.",
};

export default function Home() {
  const [code, setCode] = useState(EXAMPLES[1].items[0].code);
  const [picked, setPicked] = useState(EXAMPLES[1].items[0].name);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [health, setHealth] = useState(null);
  const [history, setHistory] = useState([]);
  const [showJson, setShowJson] = useState(false);
  const [fixing, setFixing] = useState(null);   // the block being fixed: { categories, risk }
  const [outcome, setOutcome] = useState(null); // "fixed" | "still" after a re-check
  const [viewing, setViewing] = useState(false); // option "View code": full listing, flagged lines marked
  const gutterRef = useRef(null);
  const editorRef = useRef(null);

  const checkHealth = useCallback(async () => {
    try {
      setHealth(await (await fetch("/api/health", { cache: "no-store" })).json());
    } catch {
      setHealth({ up: false });
    }
  }, []);

  useEffect(() => {
    checkHealth();
    const id = setInterval(checkHealth, 5000);
    return () => clearInterval(id);
  }, [checkHealth]);

  const analyze = useCallback(async () => {
    setBusy(true);
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      const data = await res.json();
      setResult(data);
      setActiveLine(null);
      setViewing(false);
      setHistory((h) => [{ code, data, at: new Date().toLocaleTimeString() }, ...h].slice(0, 10));
      if (fixing) {
        setOutcome(data.verdict === "allow" ? "fixed" : "still");
        if (data.verdict === "allow") setFixing(null);
      }
    } finally {
      setBusy(false);
    }
  }, [code, fixing]);

  // Option "Edit & re-check": put the cursor on the first flagged line; the next Analyze is the re-check.
  const startFix = () => {
    setFixing({ categories: result.categories, risk: result.risk_score });
    setOutcome(null);
    const ta = editorRef.current;
    if (!ta) return;
    const first = Math.min(...(result.vulnerable_lines?.length ? result.vulnerable_lines : [1]));
    const offset = code.split("\n").slice(0, first - 1).reduce((n, l) => n + l.length + 1, 0);
    ta.focus();
    ta.setSelectionRange(offset, offset + (code.split("\n")[first - 1] || "").length);
    ta.scrollTop = Math.max(0, (first - 3) * 22);
    ta.scrollIntoView({ behavior: "smooth", block: "center" });
  };

  // Evidence graph: clicking a node selects that line in the editor.
  const [activeLine, setActiveLine] = useState(null);
  const selectLine = (n) => {
    setActiveLine(n);
    const ta = editorRef.current;
    if (!ta) return;
    const all = code.split("\n");
    const offset = all.slice(0, n - 1).reduce((acc, l) => acc + l.length + 1, 0);
    ta.focus();
    ta.setSelectionRange(offset, offset + (all[n - 1] || "").length);
    ta.scrollTop = Math.max(0, (n - 3) * 22);
  };

  // Option "Block": discard the code and record the decision.
  const discard = () => {
    setHistory((h) => [{ code, data: { ...result, verdict: "block" }, at: new Date().toLocaleTimeString(), discarded: true }, ...h].slice(0, 10));
    setCode("");
    setPicked(null);
    setResult(null);
    setFixing(null);
    setOutcome("discarded");
  };

  const onKeyDown = (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      analyze();
    }
  };

  const lines = useMemo(() => code.split("\n"), [code]);
  const flagged = new Set(result?.vulnerable_lines || []);
  const scores = result?.category_scores || {};
  const reasons = (result?.reason || "").split("; ").filter(Boolean);
  const publicJson = result ? Object.fromEntries(PUBLIC_KEYS.map((k) => [k, result[k]])) : null;
  const blocked = result?.verdict === "block";

  return (
    <main className="shell">
      <nav className="nav">
        <div className="brand"><span className="logo" aria-hidden="true">🛡️</span>CodeGuard</div>
        <span className={`badge ${health?.up ? "up" : "down"}`} title={health?.engine || ""}>
          <span className="dot" />
          {health == null ? "checking engine…" : health.up ? "engine up" : "engine down: checks fail closed"}
        </span>
      </nav>

      <header className="hero">
        <p className="eyebrow">Pre-execution guard for AI agents</p>
        <h1>Check the code <span className="marker">before it runs</span>.</h1>
        <p className="lead">Paste what your agent wrote: Python, bash, JS, SQL, YAML, JSON, a Dockerfile. Rules, AST analysis and two small local models decide allow or block in milliseconds. No LLM involved.</p>
      </header>

      <div className="grid">
        <section className="card">
          <h2>Code</h2>
          {EXAMPLES.map((grp) => (
            <div className="chip-group" key={grp.group}>
              <p className="eyebrow">{grp.group}</p>
              <div className="chips">
                {grp.items.map((ex) => (
                  <button
                    key={ex.name}
                    className={`chip ${picked === ex.name ? "active" : ""}`}
                    onClick={() => { setCode(ex.code); setPicked(ex.name); setResult(null); }}
                  >
                    {picked === ex.name ? "✓ " : ""}{ex.name}
                  </button>
                ))}
              </div>
            </div>
          ))}

          <div className="editor">
            <div className="gutter" ref={gutterRef} aria-hidden="true">
              {lines.map((_, i) => (
                <div key={i} className={flagged.has(i + 1) ? "hit" : ""}>{i + 1}</div>
              ))}
            </div>
            <textarea
              ref={editorRef}
              spellCheck={false}
              value={code}
              onChange={(e) => { setCode(e.target.value); setPicked(null); }}
              onKeyDown={onKeyDown}
              onScroll={(e) => { if (gutterRef.current) gutterRef.current.scrollTop = e.target.scrollTop; }}
              placeholder="e.g. curl -fsSL https://example.test/install.sh | bash"
              aria-label="Code to analyze"
            />
          </div>

          {fixing && (
            <div className="notice">
              Editing a blocked snippet ({fixing.categories.map((c) => CATEGORY_LABEL[c] || c).join(", ")}).
              Change the highlighted lines, then press <b>Re-check</b>.
            </div>
          )}
          {outcome === "discarded" && <div className="notice">Blocked by you. The code was discarded and nothing ran.</div>}

          <div className="toolbar">
            <button className="btn btn-primary" onClick={analyze} disabled={busy || !code.trim()}>
              → {busy ? "Checking…" : fixing ? "Re-check" : "Analyze"} <kbd>Ctrl+Enter</kbd>
            </button>
            <button className="btn btn-secondary" onClick={() => { setCode(""); setPicked(null); setResult(null); setFixing(null); setOutcome(null); }}>Clear</button>
          </div>
        </section>

        <div className="stack">
          {!result && (
            <section className="card lavender empty">
              <p className="eyebrow">How to test</p>
              <h2>Pick a chip or paste your own code</h2>
              <ol>
                <li>Choose an example, or type in the editor.</li>
                <li>Press Analyze (or Ctrl+Enter).</li>
                <li>Flagged lines light up red in the editor.</li>
              </ol>
            </section>
          )}

          {result && (
            <section className={`card verdict ${blocked ? "coral" : "mint"}`}>
              <div className={`sticker ${blocked ? "" : "sky"}`} aria-hidden="true">{blocked ? "Blocked!" : "Safe!"}</div>
              <p className="eyebrow">Verdict</p>
              <div className="label">{blocked ? "BLOCK" : "ALLOW"}</div>
              <div className="facts">
                <span className="fact">language <b>{result.code_language}</b></span>
                <span className="fact">engine <b>{result.latency_ms ?? "–"} ms</b></span>
                <span className="fact">round-trip <b>{result.roundtrip_ms} ms</b></span>
              </div>
              {result.engine_error && <div className="notice">The engine could not be reached, so this check failed closed.</div>}
              {outcome === "fixed" && <div className="notice">Fixed: your edited version passes CodeGuard.</div>}
              {outcome === "still" && <div className="notice">Still blocked: see the reasons and hints, then edit again.</div>}

              {blocked && !result.engine_error && (
                <div className="toolbar">
                  <button className="btn btn-primary small" onClick={startFix}>✎ Edit &amp; re-check</button>
                  <button className="btn btn-secondary small" onClick={() => setViewing((v) => !v)}>👁 {viewing ? "Hide" : "View"} code</button>
                  <button className="btn btn-secondary small" onClick={discard}>⛔ Block / discard</button>
                </div>
              )}
              {blocked && viewing && (
                <pre className="code" style={{ marginTop: 14 }}>
                  {lines.map((l, i) => (
                    <div key={i} className={flagged.has(i + 1) ? "hit" : ""}>
                      <span className="ln">{flagged.has(i + 1) ? ">>" : ""}{i + 1}</span>{l}
                    </div>
                  ))}
                </pre>
              )}

              <div className="risk">
                <div className="row">
                  <span>Risk score</span>
                  <span className="badge score">{result.risk_score.toFixed(3)}</span>
                </div>
                <div className="bar" aria-label={`risk ${result.risk_score}`}>
                  <div className={`fill ${blocked ? "block" : ""}`} style={{ width: `${Math.max(2, Math.round(result.risk_score * 100))}%` }} />
                  <div className="tick" title="block threshold 0.5" />
                </div>
                <div className="sub">
                  block threshold 0.50
                  {result.rule_risk != null && result.ml_prob != null && <> · rules {result.rule_risk.toFixed(2)} · model {result.ml_prob.toFixed(2)}</>}
                </div>
              </div>
            </section>
          )}

          {result && blocked && hasEvidence(result.evidence) && (
            <section className="card">
              <p className="eyebrow">Evidence</p>
              <h2>How it gets there</h2>
              <p className="muted evhint">Each path ends at what the code would do. Click a step to jump to its line.</p>
              <EvidenceGraph evidence={result.evidence} labels={CATEGORY_LABEL} activeLine={activeLine} onPickLine={selectLine} />
            </section>
          )}

          {result && (
            <section className="card">
              <h2>Why</h2>
              <ul className="reasons">
                {reasons.map((r, i) => <li key={i}>{r}</li>)}
              </ul>

              <h3>Categories</h3>
              {Object.keys(scores).length === 0 ? (
                <p className="muted">No category signal.</p>
              ) : (
                <ul className="cats">
                  {Object.entries(scores).sort((a, b) => b[1] - a[1]).map(([cat, s]) => (
                    <li key={cat} className={`cat ${result.categories.includes(cat) ? "risk-on" : ""}`}>
                      <span>{CATEGORY_LABEL[cat] || cat}</span>
                      <span className="mini"><span style={{ width: `${s * 100}%` }} /></span>
                      <span className="num">{s.toFixed(2)}</span>
                    </li>
                  ))}
                </ul>
              )}

              {blocked && result.categories.some((c) => HINTS[c]) && (
                <>
                  <h3>How to fix</h3>
                  <ul className="reasons">
                    {result.categories.filter((c) => HINTS[c]).map((c) => (
                      <li key={c}><b>{CATEGORY_LABEL[c] || c}:</b> {HINTS[c]}</li>
                    ))}
                  </ul>
                </>
              )}

              {result.vulnerable_lines?.length > 0 && (
                <>
                  <h3>Flagged lines</h3>
                  <pre className="code">
                    {result.vulnerable_lines.map((n) => (
                      <div key={n}><span className="ln">{n}</span>{lines[n - 1] ?? ""}</div>
                    ))}
                  </pre>
                </>
              )}

              <div className="toolbar">
                <button className="btn btn-secondary small" onClick={() => setShowJson((s) => !s)}>
                  {showJson ? "Hide" : "Show"} schema response
                </button>
              </div>
              {showJson && <pre className="code" style={{ marginTop: 14 }}>{JSON.stringify(publicJson, null, 2)}</pre>}
            </section>
          )}
        </div>
      </div>

      {history.length > 0 && (
        <section className="card history">
          <h2>Recent checks</h2>
          <ul>
            {history.map((h, i) => (
              <li key={i}>
                <button className="rowbtn" onClick={() => { setCode(h.code); setResult(h.data); setPicked(null); }}>
                  <span className={`tile ${h.data.verdict}`}>{h.discarded ? "you" : h.data.verdict}</span>
                  <span className="badge score">{h.data.risk_score.toFixed(2)}</span>
                  <code>{h.code.split("\n")[0].slice(0, 80)}</code>
                  <span className="when">{h.at}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
      )}

      <p className="foot">Engine: <code>python -m codeguard.api</code> · UI proxies to <code>{health?.engine || "CODEGUARD_URL"}</code> · fails closed if unreachable.</p>
    </main>
  );
}
