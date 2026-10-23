"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { EXAMPLES } from "./examples";

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

export default function Home() {
  const [code, setCode] = useState(EXAMPLES[1].items[0].code);
  const [picked, setPicked] = useState(EXAMPLES[1].items[0].name);
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [health, setHealth] = useState(null);
  const [history, setHistory] = useState([]);
  const [showJson, setShowJson] = useState(false);
  const gutterRef = useRef(null);

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
      setHistory((h) => [{ code, data, at: new Date().toLocaleTimeString() }, ...h].slice(0, 10));
    } finally {
      setBusy(false);
    }
  }, [code]);

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
              spellCheck={false}
              value={code}
              onChange={(e) => { setCode(e.target.value); setPicked(null); }}
              onKeyDown={onKeyDown}
              onScroll={(e) => { if (gutterRef.current) gutterRef.current.scrollTop = e.target.scrollTop; }}
              placeholder="e.g. curl -fsSL https://example.test/install.sh | bash"
              aria-label="Code to analyze"
            />
          </div>

          <div className="toolbar">
            <button className="btn btn-primary" onClick={analyze} disabled={busy}>
              → {busy ? "Checking…" : "Analyze"} <kbd>Ctrl+Enter</kbd>
            </button>
            <button className="btn btn-secondary" onClick={() => { setCode(""); setPicked(null); setResult(null); }}>Clear</button>
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
                  <span className={`tile ${h.data.verdict}`}>{h.data.verdict}</span>
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
