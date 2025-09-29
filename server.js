// server.js
import "dotenv/config";
import express from "express";
import multer from "multer";
import path from "path";
import { fileURLToPath } from "url";
import { analyzeText } from "./analysis.js";
import { parseBufferToText } from "./parser.js";

// ESM-safe __dirname
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();

// Body limits + static hosting for /public
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true, limit: "2mb" }));
app.use(express.static(path.join(__dirname, "public"))); // serves index.html

// Explicit root (optional)
app.get("/", (_req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// Multer (memory) for uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: Number(process.env.MAX_FILE_MB || 15) * 1024 * 1024 }
});

// Analyze uploaded file (no type needed)
app.post("/api/analyze-file", upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    const text = await parseBufferToText(req.file.buffer);
    if (!text || text.trim().length < 20) {
      return res.status(400).json({ error: "Could not extract meaningful text from file" });
    }
    const report = await analyzeText(text);
    res.json(report);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message || "Analysis failed" });
  }
});

// No URL route anymore

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`LegalDoc Risk Rater listening on http://localhost:${port}`);
});
