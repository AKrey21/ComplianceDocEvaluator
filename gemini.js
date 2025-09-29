// gemini.js (AI Studio only)
import { GoogleGenerativeAI } from "@google/generative-ai";

const API_KEY = process.env.GOOGLE_API_KEY || process.env.GEMINI_API_KEY;
if (!API_KEY) throw new Error("Set GOOGLE_API_KEY (ai.google.dev API key) in .env");

const MODEL_ID = (process.env.GEMINI_MODEL || "gemini-1.5-flash").replace(/-latest|-002$/i, "");
const client = new GoogleGenerativeAI(API_KEY);
const model = client.getGenerativeModel({ model: MODEL_ID });

export async function generateWithGemini(prompt) {
  const r = await model.generateContent(prompt);
  const text = r?.response?.text?.() || r?.response?.text || "";
  return { provider: "ai", model: MODEL_ID, text };
}
