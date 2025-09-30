// analysis.js (AU-only, robust JSON + heuristics; with CDSS exemption + soft floors)
import { generateWithGemini } from "./gemini.js";
import config from "./config.js";

/* ---------------- AU-only prompt ---------------- */
const ANALYSIS_PROMPT = `
You are a compliance analyst focused on AUSTRALIA-ONLY obligations.
Assess against: Australian Privacy Principles (APP 1/5/8/11/12/13), ACSC Essential Eight (signals only),
and TGA Clinical Decision Support Software exemption conditions.

Return ONLY a JSON array of findings. Each finding:
{id, theme, title, status, severity, evidence, impact, recommendation, references, confidence}

Guidance:
- theme ∈ {"privacy_app","security_e8","contract_fairness","vendor_sharing","cdss_exemption"}
- If a control/notice is MISSING or NOT DISCLOSED, still create a finding (status="undisclosed", severity="medium", evidence="not found")
- Cite exact lines in 'evidence' using the format: [LINE XXX] <snippet> when available. The line numbers are prepended to each line in the document chunk for easy RAG-like retrieval and accurate citation.
- Keep recommendations AU-ready and actionable; do not include owners or ETAs
- Prefer 6–15 total findings for typical policies
`;

/* ---------------- Public entry ---------------- */
export async function analyzeText(rawText) {
  const { maxTokensPerChunk, overlapChars } = config;
  // NOTE: The implementation of chunkByChar has been updated to include line numbers for RAG-like citation.
  const chunks = chunkByChar(rawText, maxTokensPerChunk, overlapChars);

  let findings = [];
  for (let i = 0; i < chunks.length; i++) {
    const prompt = [
      "<<INSTRUCTIONS>>",
      ANALYSIS_PROMPT,
      "<<SCOPE>> AU only (APPs + Essential Eight + CDSS exemption signals)",
      "<<DOCUMENT_CHUNK>>",
      chunks[i]
    ].join("\n");

    const { text } = await generateWithGemini(prompt);
    const parsed = parseGeminiJson(text);
    if (Array.isArray(parsed)) findings.push(...parsed);
  }

  if (!findings.length) {
    findings = heuristicsAU(rawText);
  } else {
    findings = ensureMinimumAU(findings, rawText);
  }

  const remediation_plan = dedupeRecommendations(findings)
    .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
    .slice(0, 6);

  return aggregate(findings, remediation_plan, rawText);
}

/* ---------------- JSON repair ---------------- */
function parseGeminiJson(text) {
  if (!text || typeof text !== "string") return [];
  try { const j = JSON.parse(text); return Array.isArray(j) ? j : []; } catch {}
  const fence = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  if (fence) { try { const j = JSON.parse(fence[1]); return Array.isArray(j) ? j : []; } catch {} }
  const arrayLike = text.match(/\[[\s\S]*\]/);
  if (arrayLike) { try { const j = JSON.parse(arrayLike[0]); return Array.isArray(j) ? j : []; } catch {} }
  return [];
}

/* ---------------- AU heuristics (fallback & gap-filler) ---------------- */
function heuristicsAU(text) {
  const T = (s) => new RegExp(s, "i").test(text || "");
  const out = [];

  // --- Privacy APPs ---
  if (!T("\\bprivacy policy\\b") && !T("how we manage.*personal information")) {
    out.push(mk("privacy_app", "APP 1 transparency", "undisclosed", "medium",
      "Not found",
      "Lack of clear statement on how personal information is managed (APP 1).",
      "Publish an APP 1-compliant privacy policy covering purpose, types collected, use/disclosure, access/correction, complaints and contact.",
      ["APP 1"], 0.6));
  }

  if (!T("we collect") || !T("why we collect") || !T("how to contact")) {
    out.push(mk("privacy_app", "APP 5 collection notice", "undisclosed", "high",
      "Details of collection notice not clearly present.",
      "APP 5 notice may be incomplete or absent.",
      "Add an APP 5 notice with purposes, fields, disclosures, cross-border, contact.",
      ["APP 5"], 0.7));
  }

  if (!T("overseas") && !T("outside australia") && !T("cross-border")) {
    out.push(mk("privacy_app", "APP 8 cross-border disclosures", "undisclosed", "medium",
      "No explicit mention of disclosures overseas.",
      "If using offshore vendors/cloud, APP 8 accountability may apply.",
      "Disclose countries/types of overseas recipients or state none occur.",
      ["APP 8"], 0.6));
  }

  if (!T("security") || !(T("encryption") || T("mfa") || T("access control") || T("backup") || T("patch"))) {
    out.push(mk("privacy_app", "APP 11 security of personal information", "undisclosed", "high",
      "Security controls not described.",
      "Absence of described measures increases risk.",
      "Document encryption/MFA/least privilege/backups/patch SLAs.",
      ["APP 11","ACSC Essential Eight"], 0.7));
  }

  if (!(T("access your information") || T("request access"))) {
    out.push(mk("privacy_app", "APP 12 access to personal information", "undisclosed", "medium",
      "Access process not described.",
      "Individuals may not know how to obtain info.",
      "Add a process for access requests, ID, timeframes, charges.",
      ["APP 12"], 0.6));
  }
  if (!(T("correction") || T("correct your information"))) {
    out.push(mk("privacy_app", "APP 13 correction of personal information", "undisclosed", "medium",
      "Correction process not described.",
      "Individuals may not know how to correct inaccuracies.",
      "Describe correction process, acknowledgement, timeframes.",
      ["APP 13"], 0.6));
  }

  if (!(T("retention") || T("retain") || T("delete") || T("deletion") || T("destroy"))) {
    out.push(mk("privacy_app", "Retention & deletion", "undisclosed", "medium",
      "No retention/deletion commitments detected.",
      "Data kept without defined periods increases exposure.",
      "State retention periods, secure destruction, triggers.",
      ["APP 11"], 0.6));
  }

  // --- Essential Eight ---
  const e8Signals = [
    ["Patch applications", /(patch|update).*(application|app)/i],
    ["Patch operating systems", /(patch|update).*(operating system|os)/i],
    ["Configure Microsoft Office macro settings", /macro/i],
    ["User application hardening", /hardening|blocklist|disable/i],
    ["Restrict administrative privileges", /admin(istrative)?\s+privilege|least privilege|rbac/i],
    ["Multi-factor authentication", /multi-?factor|mfa|2fa/i],
    ["Regular backups", /backup/i],
    ["Incident response", /incident|breach notification|respond/i]
  ];
  let anySignalFound = false;
  for (const [name, rx] of e8Signals) {
    if (rx.test(text || "")) { anySignalFound = true; continue; }
    out.push(mk("security_e8", `Essential Eight: ${name}`, "undisclosed", "low",
      "Signal not detected in document.",
      `No mention of "${name}" which is recommended ACSC control.`,
      `Publish statement of posture for "${name}".`,
      ["ACSC Essential Eight"], 0.55));
  }
  if (!anySignalFound) {
    out.push(mk("security_e8", "Essential Eight posture", "undisclosed", "medium",
      "No ACSC Essential Eight signals detected.",
      "Security posture unclear.",
      "Publish high-level summary mapping to Essential Eight maturity.",
      ["ACSC Essential Eight"], 0.55));
  }

  // --- CDSS exemption heuristics ---
  if (!T("not.*diagnos") && !T("does not diagnos") && !T("not intended to diagnose")) {
    out.push(mk("cdss_exemption","Non-diagnostic disclaimer","undisclosed","high",
      "No explicit disclaimer found that outputs are not diagnostic.",
      "Without this, TGA may view as regulated medical device.",
      "Add disclaimer: 'This software does not provide a medical diagnosis and must not replace professional judgement.'",
      ["TGA CDSS Exemption Guidance"],0.75));
  }
  if (!T("clinician") && !T("health professional") && !T("doctor review")) {
    out.push(mk("cdss_exemption","Clinician oversight","undisclosed","high",
      "No mention that outputs require clinician review/approval.",
      "CDSS exemption requires clinician retains decision-making.",
      "State: 'Outputs are intended for use by qualified healthcare professionals, who retain responsibility for all decisions.'",
      ["TGA CDSS Exemption"],0.75));
  }
  if (!T("transparent") && !T("rules") && !T("guideline") && !T("threshold")) {
    out.push(mk("cdss_exemption","Transparency of logic","undisclosed","medium",
      "No mention that rules/thresholds are visible.",
      "Opaque logic risks classification as regulated device.",
      "Add language that clinicians can see rules, thresholds, references.",
      ["TGA CDSS Exemption"],0.65));
  }
  if (T("patient") && !T("educational") && !T("read-only") && !T("non-directive")) {
    out.push(mk("cdss_exemption","Patient-facing mode disclaimer","undisclosed","medium",
      "Mentions patient access without clarifying outputs are educational/read-only.",
      "Patient features may trigger regulation unless limited.",
      "Clarify patient mode only shows clinician-approved educational summaries.",
      ["TGA CDSS Exemption"],0.6));
  }
  if (!T("not intended") && !T("not for triage") && !T("not for emergency")) {
    out.push(mk("cdss_exemption","Scope limitations","undisclosed","medium",
      "No explicit limitation against triage/prediction/therapeutic claims.",
      "Absence of scope limitation could classify as device.",
      "Add: 'Not intended for triage, emergency use, disease prediction, or therapeutic purposes.'",
      ["TGA CDSS Exemption"],0.6));
  }

  return out;
}

function ensureMinimumAU(findings, text) {
  // unchanged from before (ensures minimum APP coverage)
  const have = (needle) =>
    findings.some(f => (`${f.theme}:${f.title}` || "").toLowerCase().includes(needle));
  const add = (f) => { if (!findings.some(x => (x.title||"")===(f.title||""))) findings.push(f); };

  if (!have("app 5")) add(mk("privacy_app","APP 5 collection notice","undisclosed","high","Not found",
    "APP 5 notice may be incomplete or absent.","Add an APP 5 notice at collection.",["APP 5"],0.6));

  if (!have("app 11")) add(mk("privacy_app","APP 11 security of personal information","undisclosed","high","Not found",
    "Security controls not described.","Document encryption/MFA/least-privilege/backups/patch SLAs.",["APP 11"],0.65));

  if (!have("access to personal")) add(mk("privacy_app","APP 12 access to personal information","undisclosed","medium","Not found",
    "Access process not described.","Describe how individuals can request access and expected timeframes.",["APP 12"],0.55));

  if (!have("correction")) add(mk("privacy_app","APP 13 correction of personal information","undisclosed","medium","Not found",
    "Correction process not described.","Explain how corrections are handled and acknowledged.",["APP 13"],0.55));

  if (!/retention|retain|delete|destroy|de-?identify/i.test(text||"")) {
    add(mk("privacy_app","Retention & deletion","undisclosed","medium","Not found",
      "No retention/deletion commitments detected.",
      "State retention periods and secure deletion/de-identification triggers.",
      ["APP 11"],0.55));
  }
  return findings;
}

/* ---------------- Scoring & aggregation (SOFTER) ---------------- */
function aggregate(findings, remediation_plan, rawText) {
  const weights = config.weights;

  // Softer penalties
  const severityPenalty = { high: 20, medium: 10, low: 4 };

  // Category soft floors (20 if signals exist)
  const floors = detectSoftFloors(rawText); // {theme: 0|20}

  const categoryMap = {
    privacy_app: 0,
    security_e8: 0,
    cdss_exemption: 0,
    contract_fairness: 0,
    vendor_sharing: 0
  };
  const themeCounters = {};

  for (const f of findings) {
    const theme = f.theme || "other";
    const sev = (f.severity || "low").toLowerCase();
    const pen = severityPenalty[sev] ?? 4;
    themeCounters[theme] = (themeCounters[theme] || 0) + pen;
  }
  for (const theme of Object.keys(categoryMap)) {
    const penalty = themeCounters[theme] || 0;
    const rawScore = Math.max(0, 100 - penalty);
    const floor = floors[theme] ?? 0;
    categoryMap[theme] = Math.max(rawScore, floor);
  }

  const overall = Math.round(
    categoryMap.privacy_app * weights.privacy_app +
    categoryMap.security_e8 * weights.security_e8 +
    categoryMap.cdss_exemption * weights.cdss_exemption +
    categoryMap.contract_fairness * weights.contract_fairness +
    categoryMap.vendor_sharing * weights.vendor_sharing
  );

  return {
    doc: {
      title: inferTitle(rawText),
      source_type: "document",
      jurisdiction_mentions: ["AU"],
      last_updated_detected: detectDates(rawText)
    },
    scores: { overall, weights, ...categoryMap },
    findings,
    remediation_plan
  };
}

/* ---------------- Soft floor detector ---------------- */
function detectSoftFloors(text="") {
  const T = (rx) => new RegExp(rx, "i").test(text);

  const hasPrivacySignals =
    T("\\bprivacy policy\\b|privacy act|personal information|app\\s*\\d+") ||
    T("we collect|why we collect|how to contact|access your information|correction|retention|delete|destroy");

  const hasSecuritySignals =
    T("encryption|mfa|2fa|access control|least privilege|backup|patch|incident|macro|hardening|rbac");

  const hasCdssSignals =
    T("not intended to diagnose|does not diagnose|clinician|health professional|doctor review") ||
    T("educational|read-only|non-directive|guideline|threshold|transparent");

  const hasContractSignals =
    T("limitation of liability|liability is limited|indemnity|indemnify|arbitration|governing law|termination|unilateral|class action");

  const hasVendorSignals =
    T("third part(y|ies)|vendors|processors|sub-processor|share|disclose|stripe|aws|google|overseas|outside australia|cross-border");

  const SOFT = 20;
  return {
    privacy_app: hasPrivacySignals ? SOFT : 0,
    security_e8: hasSecuritySignals ? SOFT : 0,
    cdss_exemption: hasCdssSignals ? SOFT : 0,
    contract_fairness: hasContractSignals ? SOFT : 0,
    vendor_sharing: hasVendorSignals ? SOFT : 0
  };
}

/* ---------------- Utilities ---------------- */
function mk(theme, title, status, severity, evidence, impact, recommendation, references, confidence) {
  return {
    id: "R-" + Math.random().toString(36).slice(2, 8),
    theme, title, status, severity,
    evidence, impact, recommendation, references, confidence
  };
}

// MODIFIED: This function now implements RAG-like indexing/grounding by prepending line numbers.
function chunkByChar(rawText, size, overlap) {
  // 1. Prepend line numbers to the text (RAG-like indexing/grounding)
  const lines = rawText.split('\n');
  const indexedText = lines.map((line, index) => `[LINE ${index + 1}] ${line}`).join('\n');

  // 2. Perform the character-based chunking with overlap on the indexed text
  const out = [];
  let i = 0;
  const step = Math.max(1, size - overlap);
  while (i < (indexedText?.length || 0)) { out.push(indexedText.slice(i, i + size)); i += step; }
  
  return out.length ? out : [indexedText || ""];
}

function dedupeRecommendations(findings) {
  const map = new Map();
  for (const f of findings) {
    const key = (f.recommendation || "").slice(0, 200);
    if (key && !map.has(key)) {
      map.set(key, {
        id: f.id || "R-" + Math.random().toString(36).slice(2, 8),
        title: f.title || key,
        severity: f.severity || "medium",
        recommendation: f.recommendation || ""
      });
    }
  }
  return [...map.values()];
}

function severityRank(s) { return ({ high: 0, medium: 1, low: 2 }[s?.toLowerCase()] ?? 3); }

function inferTitle(t) {
  const m = (t || "").match(/(privacy policy|terms of service|terms and conditions|data processing addendum)/i);
  return m ? m[0] : "Document";
}
function detectDates(t) {
  const m = (t || "").match(/(last updated|effective date)[:\s]*([A-Za-z]{3,9}\s+\d{1,2},\s*\d{4}|\d{4}-\d{2}-\d{2})/i);
  return m ? m[2] : null;
}