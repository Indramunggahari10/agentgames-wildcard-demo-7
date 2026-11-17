# Preflight Doctor

Sign, verify, and debug the zkVerify Agent Games handshake — without
guessing why a signature mismatched.

The protocol: the signature is HMAC-SHA256, lowercase hex, no prefix,
computed over the **exact raw request body bytes**, key = the shared
secret as UTF-8, carried in the `x-agent-games-signature` header. The
preflight response must be exactly `{ok: true, protocolVersion: 'v1'}` —
any extra field fails. Most integration failures are not cryptography
failures; they are byte failures: a re-serialized body, a trailing
newline, a CRLF, a BOM, a quoted secret. This tool makes those visible.

## What it does

- **Sign** — paste a secret and raw body text, get the lowercase-hex
  HMAC-SHA256. Warns on empty secrets and empty bodies.
- **Verify** — paste a secret, body, and claimed signature. Reports
  match/mismatch, every format violation (empty, whitespace, `0x`
  prefix, uppercase hex, wrong length, non-hex, base64-shaped), and —
  when a mismatch has a likely explanation — the variant that matches,
  labelled a *possible* cause: trimmed/quoted secret, added or removed
  trailing newline, CRLF/LF conversion, BOM added or stripped, JSON
  re-serialization, base64- or hex-decoded secret. Comparison uses
  `timingSafeEqual` on equal-length buffers.
- **Preflight shape check** — verifies a response is exactly
  `{ok: true, protocolVersion: 'v1'}`: non-null object, exactly those
  two own keys, exact values and types. Every deviation is listed, and
  duplicate top-level keys are flagged explicitly (plain `JSON.parse`
  silently collapses them). Key order and whitespace do not affect the
  shape verdict — they do affect signatures.
- **RFC 4231 vectors** — the server recomputes the three published
  HMAC-SHA256 test vectors on demand, so a broken crypto path shows up
  immediately. Expected values were independently re-checked against
  Python's `hmac` module.
- **Worked examples** — valid/extra-field/wrong-type/duplicate-key
  preflight responses, the re-serialization demo, the trailing-newline
  demo, and the uppercase-hex case.

## Honest scope

Educational only. This tool never calls the real platform, never stores
anything, and never logs what you paste. But it is a hosted server:
whatever you paste is sent to this demo server and processed in memory,
and JavaScript cannot guarantee memory erasure. **Use a disposable test
secret — never your real one.** Inputs are UTF-8 text; a text box cannot
represent arbitrary raw bytes, and a mismatch diagnostic names a
*possible* cause — a mismatch alone cannot prove what bytes or secret
the sender used. A client-side-only build (Web Crypto) would be
stronger on secrecy; the server build was kept for consistency with the
sibling demos and for HTTP-level testing. The tradeoff is stated here
and in the UI banner.

## Endpoints

| Route | Method | Purpose |
|---|---|---|
| `/` | GET | Single-page UI |
| `/api/health` | GET | Liveness |
| `/api/examples` | GET | Bundled examples |
| `/api/vectors` | GET | RFC 4231 vector results |
| `/api/sign` | POST | `{secret, body}` → `{signature, warnings}` |
| `/api/verify` | POST | `{secret, body, signature}` → match + diagnostics |
| `/api/preflight` | POST | `{text}` → `{valid, deviations}` |

Body cap 64 KB (413 beyond it). Responses carry `no-store` and a strict
CSP. No third-party scripts. Zero dependencies — Node built-ins only.

## Run

```sh
npm install
npm start        # listens on $PORT (default 3000)
npm test         # 37 tests: RFC vectors, cross-checked HMAC values,
                 # format/verify/shape cases, HTTP round-trips
```

## License

MIT.
