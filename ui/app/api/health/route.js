const ENGINE = (process.env.CODEGUARD_URL || "http://127.0.0.1:8000").replace(/\/$/, "");

export async function GET() {
  try {
    const res = await fetch(`${ENGINE}/health`, { signal: AbortSignal.timeout(2000), cache: "no-store" });
    return Response.json({ up: res.ok, engine: ENGINE });
  } catch {
    return Response.json({ up: false, engine: ENGINE });
  }
}
