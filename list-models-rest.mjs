import "dotenv/config";

const KEY = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY || "";
if (!KEY) throw new Error("No GOOGLE_API_KEY set");

const url = "https://generativelanguage.googleapis.com/v1beta/models?key=" + encodeURIComponent(KEY);
const r = await fetch(url);
if (!r.ok) {
  console.error("HTTP", r.status, r.statusText);
  console.error(await r.text());
  process.exit(1);
}
const data = await r.json();
for (const m of (data.models || [])) {
  const name = (m.name || "").replace(/^models\//, "");
  const methods = (m.supportedGenerationMethods || []).join(", ");
  console.log(`${name} -> ${methods}`);
}