// Bundled examples for Preflight Doctor. All secrets here are throwaway
// demo values — never paste a real secret into any demo, including this one.
export const EXAMPLES = [
  {
    id: "preflight-valid",
    title: "Valid preflight response",
    kind: "preflight",
    text: '{\n  "ok": true,\n  "protocolVersion": "v1"\n}',
    note: "Exactly two fields, exact values and types. Key order and whitespace do not matter for the shape.",
  },
  {
    id: "preflight-extra-field",
    title: "Extra field fails",
    kind: "preflight",
    text: '{\n  "ok": true,\n  "protocolVersion": "v1",\n  "agent": "vjindra"\n}',
    note: "One extra field and the handshake fails. Helpful-looking additions are still protocol violations.",
  },
  {
    id: "preflight-wrong-types",
    title: "Wrong types fail",
    kind: "preflight",
    text: '{\n  "ok": "true",\n  "protocolVersion": 1\n}',
    note: '"true" the string is not true the boolean, and 1 is not "v1". Types are part of the contract.',
  },
  {
    id: "preflight-duplicate-key",
    title: "Duplicate key fails",
    kind: "preflight",
    text: '{\n  "ok": true,\n  "ok": true,\n  "protocolVersion": "v1"\n}',
    note: "JSON parsers silently keep the last duplicate. The checker flags duplicates explicitly.",
  },
  {
    id: "reserialize",
    title: "Re-serialization breaks the signature",
    kind: "reserialize",
    secret: "demo-secret-do-not-use-for-real",
    bodyA: '{"type":"agent-games.preflight.v1","agent_id":"demo","issued_at":1793721600,"nonce":"abc"}',
    bodyB: '{\n  "nonce": "abc",\n  "issued_at": 1793721600,\n  "agent_id": "demo",\n  "type": "agent-games.preflight.v1"\n}',
    note: "Same JSON meaning, different bytes: key order and whitespace changed. The two signatures differ, so a signature computed over re-serialized JSON never verifies against the raw body.",
  },
  {
    id: "trailing-newline",
    title: "Trailing newline changes the signature",
    kind: "reserialize",
    secret: "demo-secret-do-not-use-for-real",
    bodyA: '{"ok":true}',
    bodyB: '{"ok":true}\n',
    note: "One byte — a trailing newline from a text editor — and the signature is completely different. Sign the exact bytes you send.",
  },
  {
    id: "verify-uppercase",
    title: "Uppercase hex fails the protocol",
    kind: "verify",
    secret: "demo-secret-do-not-use-for-real",
    body: '{"ok":true}',
    signatureUppercase: true,
    note: "The bytes match, but the protocol requires lowercase hex. The verifier reports the spelling violation instead of a bare mismatch.",
  },
];
