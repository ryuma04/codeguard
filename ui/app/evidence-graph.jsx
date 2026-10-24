"use client";

// "How it gets there": the engine's evidence chains drawn as vertical node graphs.
// Each chain is one path to the flagged behaviour: source -> sink (secret reaches the network),
// encoded -> decoded -> exec (hidden payload), carrier -> embedded code. Clicking a node selects its
// line in the editor and highlights that line in every chain. Styled per design.md.

const ROLE = {
  code: { label: "Code", tone: "paper" },
  effect: { label: "Effect", tone: "coral" },
  source: { label: "Source", tone: "butter" },
  encoded: { label: "Encoded", tone: "lavender" },
  decoded: { label: "Decoded", tone: "lavender" },
  carrier: { label: "Carrier", tone: "sky" },
  step: { label: "Step", tone: "paper" },
  sink: { label: "Sink", tone: "coral" },
  finding: { label: "Finding", tone: "coral" },
};

export function hasEvidence(evidence) {
  return Array.isArray(evidence) && evidence.some((e) => e.steps?.length > 0);
}

// A single finding (e.g. `DROP DATABASE prod;` on one line) has no multi-step path, so draw it as
// the line of code -> what it does, instead of showing nothing.
function expand(e) {
  if (e.steps.length > 1) return e.steps;
  const s = e.steps[0];
  return [
    { line: s.line, role: "code", label: s.line > 0 ? "This line" : "The snippet", code: s.code },
    { line: s.line, role: "effect", label: s.label },
  ];
}

export default function EvidenceGraph({ evidence, labels, activeLine, onPickLine }) {
  const chains = evidence.filter((e) => e.steps?.length > 0).map((e) => ({ ...e, steps: expand(e) }));
  return (
    <div className="evgraph" data-testid="evidence-graph">
      {chains.map((e, ci) => (
        <div className="evchain" key={ci}>
          <p className="evcat">
            <span className="badge score">{e.weight.toFixed(2)}</span> {labels[e.category] || e.category}
          </p>
          <ol className="evsteps">
            {e.steps.map((s, si) => {
              const role = ROLE[s.role] || ROLE.step;
              const on = activeLine != null && s.line === activeLine;
              const next = e.steps[si + 1];
              return (
                <li key={si}>
                  <button
                    type="button"
                    className={`evnode ${role.tone} ${on ? "on" : ""}`}
                    onClick={() => s.line > 0 && onPickLine(s.line)}
                    disabled={!(s.line > 0)}
                    aria-pressed={on}
                    title={s.line > 0 ? `Select line ${s.line} in the editor` : undefined}
                  >
                    <span className="evhead">
                      <span className="evrole">{role.label}</span>
                      {s.line > 0 && <span className="evline">line {s.line}</span>}
                    </span>
                    <span className="evlabel">{s.label}</span>
                    {s.code && s.role !== "decoded" && <code className="evcode">{s.code}</code>}
                  </button>
                  {next && (
                    <div className="evarrow" aria-hidden="true">
                      <span className="evstem" />
                      {next.via && <span className="evvia">via <code>{next.via}</code></span>}
                      <span className="evtip">▼</span>
                    </div>
                  )}
                </li>
              );
            })}
          </ol>
        </div>
      ))}
    </div>
  );
}
