// Preflight Doctor tests. Expected HMAC values come from RFC 4231
// (published constants) and from Python's independent hmac implementation
// (non-ASCII, empty/empty, and fox vectors, generated 2026-11-17) — never
// from the module under test.
import test from "node:test";
import assert from "node:assert/strict";
import {
  hmacHex,
  RFC4231_VECTORS,
  runRfcVectors,
  analyzeSignatureFormat,
  signRequest,
  verifyRequest,
  findDuplicateTopLevelKeys,
  checkPreflightShape,
} from "../src/sign.js";
import { createServer } from "../server.js";

const GOOD = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

// --- RFC 4231 vectors -------------------------------------------------

test("RFC 4231 vectors: all three published HMAC-SHA256 cases pass", () => {
  assert.equal(RFC4231_VECTORS.length, 3);
  for (const result of runRfcVectors()) {
    assert.equal(result.pass, true, `${result.id} mismatch: ${result.actual}`);
  }
});

test("HMAC matches Python hmac for non-ASCII secret and body", () => {
  assert.equal(
    hmacHex("s3cr3t-🔑", '{"msg":"café 🚀"}'),
    "561b8acc634fed9f311e4f321783bccbc2bd2de30788e8f409f4848b752839f6",
  );
});

test("HMAC matches Python hmac for empty key and empty data", () => {
  assert.equal(hmacHex("", ""), "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
});

test("HMAC matches the known fox vector", () => {
  assert.equal(
    hmacHex("key", "The quick brown fox jumps over the lazy dog"),
    "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8",
  );
});

// --- sign --------------------------------------------------------------

test("sign is deterministic and lowercase hex", () => {
  const a = signRequest({ secret: "s", body: '{"ok":true}' });
  const b = signRequest({ secret: "s", body: '{"ok":true}' });
  assert.equal(a.signature, b.signature);
  assert.match(a.signature, /^[0-9a-f]{64}$/);
});

test("sign warns on empty secret and empty body", () => {
  assert.equal(signRequest({ secret: "", body: "x" }).warnings.length, 1);
  assert.equal(signRequest({ secret: "s", body: "" }).warnings.length, 1);
  assert.equal(signRequest({ secret: "s", body: "x" }).warnings.length, 0);
});

test("sign rejects oversized inputs and non-strings", () => {
  assert.throws(() => signRequest({ secret: "s", body: "x".repeat(65537) }), /64 KB/);
  assert.throws(() => signRequest({ secret: "s".repeat(4097), body: "x" }), /4 KB/);
  assert.throws(() => signRequest({ secret: 1, body: "x" }), /string/);
});

test("one changed byte changes the whole signature", () => {
  const a = signRequest({ secret: "s", body: '{"ok":true}' }).signature;
  const b = signRequest({ secret: "s", body: '{"ok":true}\n' }).signature;
  assert.notEqual(a, b);
});

// --- signature format analysis -----------------------------------------

test("format: clean 64-char lowercase hex has no issues", () => {
  assert.deepEqual(analyzeSignatureFormat(GOOD).issues, []);
});

test("format: empty signature reports header-read failure", () => {
  assert.match(analyzeSignatureFormat("").issues.join(" "), /empty signature/);
});

test("format: whitespace, 0x prefix, uppercase, length, non-hex each flagged", () => {
  assert.match(analyzeSignatureFormat(" " + GOOD).issues.join(" "), /whitespace/);
  assert.match(analyzeSignatureFormat("0x" + GOOD).issues.join(" "), /0x prefix/);
  assert.match(analyzeSignatureFormat(GOOD.toUpperCase()).issues.join(" "), /lowercase/);
  assert.match(analyzeSignatureFormat(GOOD.slice(0, 32)).issues.join(" "), /wrong length/);
  assert.match(analyzeSignatureFormat("z".repeat(64)).issues.join(" "), /non-hex/);
});

test("format: base64-shaped signature is flagged", () => {
  const b64 = Buffer.from(GOOD, "hex").toString("base64");
  assert.equal(b64.length, 44);
  assert.match(analyzeSignatureFormat(b64).issues.join(" "), /base64/);
});

// --- verify ------------------------------------------------------------

test("verify: exact match succeeds", () => {
  const sig = signRequest({ secret: "s", body: '{"ok":true}' }).signature;
  const result = verifyRequest({ secret: "s", body: '{"ok":true}', signature: sig });
  assert.equal(result.match, true);
  assert.equal(result.matchedVariant, null);
});

test("verify: uppercase hex fails but reports same-bytes spelling cause", () => {
  const sig = signRequest({ secret: "s", body: '{"ok":true}' }).signature;
  const result = verifyRequest({ secret: "s", body: '{"ok":true}', signature: sig.toUpperCase() });
  assert.equal(result.match, false);
  assert.match(result.matchedVariant, /non-protocol spelling/);
});

test("verify: wrong signature fails with no variant", () => {
  const result = verifyRequest({ secret: "s", body: '{"ok":true}', signature: "0".repeat(64) });
  assert.equal(result.match, false);
  assert.equal(result.matchedVariant, null);
});

test("verify: trailing-newline variant is detected as possible cause", () => {
  const sig = signRequest({ secret: "s", body: '{"ok":true}\n' }).signature;
  const result = verifyRequest({ secret: "s", body: '{"ok":true}', signature: sig });
  assert.equal(result.match, false);
  assert.match(result.matchedVariant, /trailing newline added/);
});

test("verify: CRLF-to-LF variant is detected", () => {
  const sig = signRequest({ secret: "s", body: '{\r\n"ok":true\r\n}' }).signature;
  const result = verifyRequest({ secret: "s", body: '{\n"ok":true\n}', signature: sig });
  assert.equal(result.match, false);
  assert.match(result.matchedVariant, /CRLF/);
});

test("verify: BOM variant is detected", () => {
  const sig = signRequest({ secret: "s", body: "\uFEFF{\"ok\":true}" }).signature;
  const result = verifyRequest({ secret: "s", body: '{"ok":true}', signature: sig });
  assert.match(result.matchedVariant, /BOM/);
});

test("verify: re-serialized JSON variant is detected", () => {
  const pretty = '{\n  "b": 2,\n  "a": 1\n}';
  const sig = signRequest({ secret: "s", body: pretty }).signature;
  const result = verifyRequest({ secret: "s", body: '{"b":2,"a":1}', signature: sig });
  // The sender signed pretty JSON; the verifier holds compact JSON. The
  // re-serialization probe re-serializes the verifier's compact body to
  // '{"b":2,"a":1}' (unchanged), so instead check the reverse direction:
  // sender signed compact, verifier holds pretty.
  assert.equal(result.match, false);
  const sig2 = signRequest({ secret: "s", body: '{"b":2,"a":1}' }).signature;
  const result2 = verifyRequest({ secret: "s", body: pretty, signature: sig2 });
  assert.match(result2.matchedVariant, /re-serialized/);
});

test("verify: trimmed-secret and quoted-secret variants are detected", () => {
  const sig = signRequest({ secret: "s", body: "x" }).signature;
  const trimmed = verifyRequest({ secret: "  s\n", body: "x", signature: sig });
  assert.match(trimmed.matchedVariant, /whitespace trimmed/);
  const quoted = verifyRequest({ secret: '"s"', body: "x", signature: sig });
  assert.match(quoted.matchedVariant, /quotes removed/);
});

test("verify: base64-decoded secret variant is detected", () => {
  const rawKey = Buffer.from("c2VjcmV0LWtleQ==", "base64");
  const sig = hmacHex(rawKey, "x");
  const result = verifyRequest({ secret: "c2VjcmV0LWtleQ==", body: "x", signature: sig });
  assert.match(result.matchedVariant, /base64/);
});

test("verify: empty signature fails with a format issue", () => {
  const result = verifyRequest({ secret: "s", body: "x", signature: "" });
  assert.equal(result.match, false);
  assert.match(result.formatIssues.join(" "), /empty signature/);
});

// --- duplicate key scanner ----------------------------------------------

test("duplicate scanner: no duplicates in a normal object", () => {
  assert.deepEqual(findDuplicateTopLevelKeys('{"a":1,"b":2}'), []);
});

test("duplicate scanner: flags a repeated top-level key", () => {
  assert.deepEqual(findDuplicateTopLevelKeys('{"ok":true,"ok":false}'), ["ok"]);
});

test("duplicate scanner: ignores nested duplicates and braces in strings", () => {
  assert.deepEqual(findDuplicateTopLevelKeys('{"a":{"x":1,"x":2},"b":"}{\\"ok\\":"}'), []);
});

test("duplicate scanner: handles escaped quotes in keys", () => {
  assert.deepEqual(findDuplicateTopLevelKeys('{"a\\"b":1,"a\\"b":2}'), ['a\\"b']);
});

// --- preflight shape -----------------------------------------------------

test("shape: exact response is valid, key order and whitespace ignored", () => {
  assert.equal(checkPreflightShape('{"ok":true,"protocolVersion":"v1"}').valid, true);
  assert.equal(checkPreflightShape('{\n  "protocolVersion": "v1",\n  "ok": true\n}').valid, true);
});

test("shape: extra field fails with the field named", () => {
  const result = checkPreflightShape('{"ok":true,"protocolVersion":"v1","agent":"x"}');
  assert.equal(result.valid, false);
  assert.match(result.deviations.join(" "), /extra field: "agent"/);
});

test("shape: missing fields fail", () => {
  assert.match(checkPreflightShape('{"ok":true}').deviations.join(" "), /missing field: "protocolVersion"/);
  assert.match(checkPreflightShape('{"protocolVersion":"v1"}').deviations.join(" "), /missing field: "ok"/);
});

test("shape: wrong values and types fail", () => {
  assert.match(checkPreflightShape('{"ok":"true","protocolVersion":"v1"}').deviations.join(" "), /boolean true/);
  assert.match(checkPreflightShape('{"ok":true,"protocolVersion":1}').deviations.join(" "), /"v1"/);
  assert.match(checkPreflightShape('{"ok":false,"protocolVersion":"v1"}').deviations.join(" "), /boolean true/);
});

test("shape: arrays, null, and invalid JSON fail", () => {
  assert.equal(checkPreflightShape('[1,2]').valid, false);
  assert.equal(checkPreflightShape('null').valid, false);
  assert.match(checkPreflightShape('{oops').deviations.join(" "), /not valid JSON/);
});

test("shape: duplicate keys fail", () => {
  const result = checkPreflightShape('{"ok":true,"ok":true,"protocolVersion":"v1"}');
  assert.equal(result.valid, false);
  assert.match(result.deviations.join(" "), /duplicate key/);
});

// --- HTTP round-trips -----------------------------------------------------

async function withServer(fn) {
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    await fn(base);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("HTTP: health, examples, and vectors endpoints", async () => {
  await withServer(async (base) => {
    const health = await fetch(`${base}/api/health`);
    assert.equal(health.status, 200);
    assert.equal((await health.json()).service, "preflight-doctor");
    const examples = await fetch(`${base}/api/examples`);
    assert.equal(examples.status, 200);
    assert.ok((await examples.json()).examples.length >= 5);
    const vectors = await fetch(`${base}/api/vectors`);
    assert.equal(vectors.status, 200);
    const body = await vectors.json();
    assert.ok(body.vectors.every((v) => v.pass));
  });
});

test("HTTP: index and app.js served with security headers", async () => {
  await withServer(async (base) => {
    const index = await fetch(`${base}/`);
    assert.equal(index.status, 200);
    assert.match(index.headers.get("cache-control"), /no-store/);
    assert.match(index.headers.get("content-security-policy"), /default-src 'self'/);
    assert.match(index.headers.get("content-security-policy"), /script-src 'self'/);
    assert.match(await index.text(), /Preflight Doctor/);
    const app = await fetch(`${base}/app.js`);
    assert.equal(app.status, 200);
    assert.match(app.headers.get("content-type"), /javascript/);
  });
});

test("HTTP: sign and verify round-trip", async () => {
  await withServer(async (base) => {
    const signed = await fetch(`${base}/api/sign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ secret: "s", body: '{"ok":true}' }),
    });
    assert.equal(signed.status, 200);
    const { signature } = await signed.json();
    const verified = await fetch(`${base}/api/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ secret: "s", body: '{"ok":true}', signature }),
    });
    assert.equal(verified.status, 200);
    assert.equal((await verified.json()).match, true);
  });
});

test("HTTP: preflight endpoint round-trip", async () => {
  await withServer(async (base) => {
    const res = await fetch(`${base}/api/preflight`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ text: '{"ok":true,"protocolVersion":"v1","extra":1}' }),
    });
    assert.equal(res.status, 200);
    const body = await res.json();
    assert.equal(body.valid, false);
    assert.match(body.deviations.join(" "), /extra field/);
  });
});

test("HTTP: oversized body gets 413, unknown route 404, bad JSON 400", async () => {
  await withServer(async (base) => {
    const big = await fetch(`${base}/api/sign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ secret: "s", body: "x".repeat(70000) }),
    });
    assert.equal(big.status, 413);
    const missing = await fetch(`${base}/nope`);
    assert.equal(missing.status, 404);
    const bad = await fetch(`${base}/api/sign`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{not json",
    });
    assert.equal(bad.status, 400);
  });
});
