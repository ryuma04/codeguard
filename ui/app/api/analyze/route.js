// Server-side proxy to the Python engine, so the browser never needs CORS and the
// engine URL stays configurable (CODEGUARD_URL). Fails closed: if the engine is
// unreachable the UI receives a "block" verdict with engine_error set.
const ENGINE = (process.env.CODEGUARD_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export async function POST(request) {
  let code = "";
  try {
    const body = await request.json();
    code = typeof body?.code === "string" ? body.code : "";
  } catch {
    return Response.json({ error: "body must be JSON: {\"code\": \"...\"}" }, { status: 400 });
  }
  const t0 = performance.now();
  try {
    const res = await fetch(`${ENGINE}/analyze?debug=1`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code }),
      signal: AbortSignal.timeout(5000),
      cache: "no-store",
    });
    if (!res.ok) throw new Error(`engine HTTP ${res.status}`);
    const data = await res.json();
    return Response.json({ ...data, roundtrip_ms: +(performance.now() - t0).toFixed(2) });
  } catch (err) {
    return Response.json({
      verdict: "block",
      risk_score: 1,
      categories: [],
      code_language: "unknown",
      reason: `guard unavailable, failing closed: ${err.message}`,
      vulnerable_lines: [],
      engine_error: true,
      roundtrip_ms: +(performance.now() - t0).toFixed(2),
    });
  }
}
