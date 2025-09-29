// parser.js (Node-safe PDF parsing: no workerSrc)
import * as pdfjs from "pdfjs-dist/legacy/build/pdf.mjs";

// DO NOT set pdfjs.GlobalWorkerOptions.workerSrc in Node.
// We'll disable the worker per-document instead.

/** Convert Buffer/ArrayBuffer/TypedArray → Uint8Array */
function toUint8(data) {
  if (data instanceof Uint8Array && !(data instanceof Buffer)) return data;
  if (data instanceof ArrayBuffer)
    return new Uint8Array(data);
  if (data && data.buffer)
    return new Uint8Array(data.buffer, data.byteOffset || 0, data.byteLength ?? data.length ?? 0);
  return Uint8Array.from(data || []);
}

export async function parseBufferToText(buf) {
  const data = toUint8(buf);
  return readPdfText(data);
}

async function readPdfText(uint8) {
  const doc = await pdfjs.getDocument({
    data: uint8,
    disableWorker: true,     // ← run in-process (no worker needed)
    useWorkerFetch: false,
    isEvalSupported: false
  }).promise;

  let out = [];
  for (let i = 1; i <= doc.numPages; i++) {
    const page = await doc.getPage(i);
    const textContent = await page.getTextContent();
    out.push(textContent.items.map(it => it.str).join(" "));
  }
  return out.join("\n").trim();
}
