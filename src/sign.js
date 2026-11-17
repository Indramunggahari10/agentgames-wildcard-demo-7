// Preflight Doctor — pure HMAC-SHA256 signing / verification diagnostics and
// preflight shape checking for the Agent Games handshake protocol.
//
// Protocol ground truth (skill: zkverify_agent_games): the signature is
// HMAC-SHA256, lowercase hex, no prefix, over the exact raw request body
// bytes, key = the shared secret as UTF-8, carried in the
// x-agent-games-signature header. The preflight response must be exactly
// {ok:true, protocolVersion:'v1'} — any extra field fails.
//
// This module is educational: it signs, verifies, and diagnoses. It never
// calls the real platform, never stores anything, and never logs inputs.
// All byte handling is UTF-8: a text box cannot represent arbitrary raw
// bytes, and that scope limit is stated in the UI.
import { createHmac, timingSafeEqual } from "node:crypto";

export const MAX_BODY_CHARS = 64 * 1024;
export const MAX_SECRET_CHARS = 4 * 1024;

// HMAC-SHA256 over UTF-8 bytes. key and data may be strings (UTF-8) or
// Buffers (raw bytes, used by the RFC 4231 vectors).
export function hmacHex(key, data) {
  const keyBuf = Buffer.isBuffer(key) ? key : Buffer.from(String(key), "utf8");
  const dataBuf = Buffer.isBuffer(data) ? data : Buffer.from(String(data), "utf8");
  return createHmac("sha256", keyBuf).update(dataBuf).digest("hex");
}

// RFC 4231 HMAC-SHA256 test vectors. Expected values are the published
// constants, independently re-checked against Python's hmac module on
// 2026-11-17 (see test file). Keys/data are hex to carry raw bytes exactly.
export const RFC4231_VECTORS = [
  {
    id: "RFC4231-1",
    keyHex: "0b".repeat(20),
    dataHex: Buffer.from("Hi There", "utf8").toString("hex"),
    expected: "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
  },
  {
    id: "RFC4231-2",
    keyHex: Buffer.from("Jefe", "utf8").toString("hex"),
    dataHex: Buffer.from("what do ya want for nothing?", "utf8").toString("hex"),
    expected: "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
  },
  {
    id: "RFC4231-3",
    keyHex: "aa".repeat(20),
    dataHex: "dd".repeat(50),
    expected: "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
  },
];

export function runRfcVectors() {
  return RFC4231_VECTORS.map((v) => {
    const actual = hmacHex(Buffer.from(v.keyHex, "hex"), Buffer.from(v.dataHex, "hex"));
    return { id: v.id, pass: actual === v.expected, expected: v.expected, actual };
  });
}

function isHex(s) {
  return /^[0-9a-fA-F]+$/.test(s);
}

// Format analysis of a claimed signature. The protocol requires exactly 64
// lowercase hex characters; anything else is a protocol failure even when
// the bytes would match (e.g. uppercase hex). Issues are reported, never
// silently repaired.
export function analyzeSignatureFormat(claimed) {
  const issues = [];
  if (typeof claimed !== "string") {
    return { issues: ["signature must be a string"] };
  }
  if (claimed.length === 0) {
    issues.push("empty signature: check the header was read at all");
    return { issues };
  }
  if (claimed !== claimed.trim()) issues.push("surrounding whitespace");
  const trimmed = claimed.trim();
  if (trimmed.startsWith("0x") || trimmed.startsWith("0X")) {
    issues.push("0x prefix: the protocol carries bare hex, no prefix");
  }
  const body = trimmed.replace(/^0[xX]/, "");
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(body) && body.length === 44 && body.includes("=")) {
    issues.push("looks like base64 (44 chars with padding): the protocol uses lowercase hex");
  }
  if (!isHex(body)) {
    issues.push("non-hex characters present");
    return { issues };
  }
  if (body !== body.toLowerCase()) {
    issues.push("uppercase hex: the protocol requires lowercase hex");
  }
  if (body.length !== 64) {
    issues.push(`wrong length: ${body.length} hex chars, HMAC-SHA256 is always 64`);
  }
  return { issues };
}

// Candidate (secret, body) transformations that commonly explain a
// mismatch. Each is labelled a POSSIBLE cause: a mismatch alone cannot
// prove what bytes or secret the sender used.
function variantProbes(secret, body) {
  const probes = [];
  const push = (label, s, b) => {
    if (s !== secret || b !== body) probes.push({ label, secret: s, body: b });
  };
  push("secret with surrounding whitespace trimmed", secret.trim(), body);
  const unquoted = secret.replace(/^"(.*)"$/, "$1").replace(/^'(.*)'$/, "$1");
  push("secret with surrounding quotes removed (copy-paste artifact)", unquoted, body);
  push("body with one trailing newline added", secret, body + "\n");
  if (body.endsWith("\n")) push("body with one trailing newline removed", secret, body.slice(0, -1));
  if (body.endsWith("\r\n")) push("body with trailing CRLF removed", secret, body.slice(0, -2));
  push("body with CRLF line endings converted to LF", secret, body.replace(/\r\n/g, "\n"));
  push("body with LF line endings converted to CRLF", secret, body.replace(/\r\n/g, "\n").replace(/\n/g, "\r\n"));
  if (body.charCodeAt(0) === 0xfeff) push("body with UTF-8 BOM stripped", secret, body.slice(1));
  push("body with UTF-8 BOM prepended", secret, "\uFEFF" + body);
  try {
    const reserialized = JSON.stringify(JSON.parse(body));
    push("body re-serialized through JSON.parse + JSON.stringify", secret, reserialized);
  } catch {
    // Not JSON: re-serialization probe does not apply.
  }
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(secret) && secret.length >= 8) {
    try {
      const decoded = Buffer.from(secret, "base64");
      if (decoded.length > 0) probes.push({ label: "secret decoded from base64 (key bytes, not UTF-8)", secretBuf: decoded, body });
    } catch {
      // Not decodable base64; skip.
    }
  }
  if (/^[0-9a-fA-F]{64}$/.test(secret)) {
    probes.push({ label: "secret decoded from hex (key bytes, not UTF-8)", secretBuf: Buffer.from(secret, "hex"), body });
  }
  return probes;
}

function assertInputs(secret, body) {
  if (typeof secret !== "string") throw new Error("secret must be a string");
  if (typeof body !== "string") throw new Error("body must be a string");
  if (secret.length > MAX_SECRET_CHARS) throw new Error("secret too large (4 KB cap)");
  if (body.length > MAX_BODY_CHARS) throw new Error("body too large (64 KB cap)");
}

export function signRequest({ secret, body }) {
  assertInputs(secret, body);
  const warnings = [];
  if (secret.length === 0) warnings.push("empty secret: HMAC with an empty key is defined, but check the secret was pasted");
  if (body.length === 0) warnings.push("empty body: you are signing zero bytes, not an empty JSON object");
  return { signature: hmacHex(secret, body), warnings };
}

export function verifyRequest({ secret, body, signature }) {
  assertInputs(secret, body);
  if (typeof signature !== "string") throw new Error("signature must be a string");
  const { issues: formatIssues } = analyzeSignatureFormat(signature);
  const expected = hmacHex(secret, body);
  const warnings = [];
  if (secret.length === 0) warnings.push("empty secret: HMAC with an empty key is defined, but check the secret was pasted");
  if (body.length === 0) warnings.push("empty body: you are verifying zero bytes, not an empty JSON object");

  // Exact protocol match first: identical lowercase hex strings.
  if (signature === expected) {
    return { match: true, expected, formatIssues, matchedVariant: null, warnings };
  }
  // Timing-safe byte comparison only when both sides decode to equal-length
  // buffers; used to detect the uppercase-hex case without leaking timing.
  let bytesMatch = false;
  const stripped = signature.trim().replace(/^0[xX]/, "");
  if (isHex(stripped) && stripped.length === 64) {
    try {
      bytesMatch = timingSafeEqual(Buffer.from(stripped, "hex"), Buffer.from(expected, "hex"));
    } catch {
      bytesMatch = false;
    }
  }
  if (bytesMatch) {
    return {
      match: false,
      expected,
      formatIssues: [...formatIssues, "possible cause: the signature bytes match, but the spelling violates the protocol (case, prefix, or whitespace)"],
      matchedVariant: "same bytes, non-protocol spelling",
      warnings,
    };
  }
  // Variant probes: each is a POSSIBLE cause, never a certainty.
  for (const probe of variantProbes(secret, body)) {
    const candidate = probe.secretBuf !== undefined
      ? hmacHex(probe.secretBuf, probe.body)
      : hmacHex(probe.secret, probe.body);
    if (candidate === signature) {
      return {
        match: false,
        expected,
        formatIssues,
        matchedVariant: `possible cause: signature matches ${probe.label}`,
        warnings,
      };
    }
  }
  return { match: false, expected, formatIssues, matchedVariant: null, warnings };
}

// Finds duplicate top-level keys in a JSON object text. JSON.parse silently
// collapses duplicates, so this small scanner walks the raw text tracking
// string state, escapes, and object depth, and records keys seen at depth 1.
export function findDuplicateTopLevelKeys(text) {
  const keys = [];
  const duplicates = [];
  let depth = 0;
  let inString = false;
  let escaped = false;
  let stringStart = -1;
  let i = 0;
  const rootIsObject = text.trimStart().startsWith("{");
  if (!rootIsObject) return duplicates;
  while (i < text.length) {
    const ch = text[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === '"') {
        inString = false;
        if (depth === 1) {
          // A depth-1 string is a key iff the next non-space char is ':'.
          let j = i + 1;
          while (j < text.length && /\s/.test(text[j])) j++;
          if (text[j] === ":") {
            const key = text.slice(stringStart + 1, i);
            if (keys.includes(key) && !duplicates.includes(key)) duplicates.push(key);
            keys.push(key);
          }
        }
      }
      i++;
      continue;
    }
    if (ch === '"') {
      inString = true;
      stringStart = i;
    } else if (ch === "{" || ch === "[") {
      depth++;
    } else if (ch === "}" || ch === "]") {
      depth--;
    }
    i++;
  }
  return duplicates;
}

// Strict preflight shape check: the response must be a non-null, non-array
// object with exactly the own keys {ok, protocolVersion}, ok === true, and
// protocolVersion === 'v1'. Key order and whitespace do not matter for the
// shape (they do matter for signatures). Every deviation is listed; the
// verdict stays a hard fail on any deviation.
export function checkPreflightShape(text) {
  const deviations = [];
  if (typeof text !== "string") return { valid: false, deviations: ["input must be a string"] };
  if (text.length > MAX_BODY_CHARS) return { valid: false, deviations: ["input too large (64 KB cap)"] };
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { valid: false, deviations: ["not valid JSON"] };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { valid: false, deviations: ["top level must be a JSON object"] };
  }
  for (const key of findDuplicateTopLevelKeys(text)) {
    deviations.push(`duplicate key: "${key}" (JSON parsers silently keep the last one)`);
  }
  const keys = Object.keys(parsed);
  for (const key of keys) {
    if (key !== "ok" && key !== "protocolVersion") deviations.push(`extra field: "${key}"`);
  }
  if (!("ok" in parsed)) deviations.push('missing field: "ok"');
  if (!("protocolVersion" in parsed)) deviations.push('missing field: "protocolVersion"');
  if ("ok" in parsed && parsed.ok !== true) {
    deviations.push(`"ok" must be boolean true, got ${JSON.stringify(parsed.ok)}`);
  }
  if ("protocolVersion" in parsed && parsed.protocolVersion !== "v1") {
    deviations.push(`"protocolVersion" must be the string "v1", got ${JSON.stringify(parsed.protocolVersion)}`);
  }
  return { valid: deviations.length === 0, deviations };
}
