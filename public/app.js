// Preflight Doctor UI. All server output is rendered with textContent —
// pasted input is never injected as HTML.
"use strict";

async function post(path, payload) {
  const res = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ("HTTP " + res.status));
  return data;
}

function setText(el, text) {
  el.textContent = text;
}

document.getElementById("sign-btn").addEventListener("click", async () => {
  const out = document.getElementById("sign-out");
  try {
    const data = await post("/api/sign", {
      secret: document.getElementById("sign-secret").value,
      body: document.getElementById("sign-body").value,
    });
    let text = "signature:\n" + data.signature;
    if (data.warnings && data.warnings.length) text += "\nwarnings:\n- " + data.warnings.join("\n- ");
    setText(out, text);
  } catch (err) {
    setText(out, "error: " + err.message);
  }
});

document.getElementById("verify-btn").addEventListener("click", async () => {
  const out = document.getElementById("verify-out");
  try {
    const data = await post("/api/verify", {
      secret: document.getElementById("verify-secret").value,
      body: document.getElementById("verify-body").value,
      signature: document.getElementById("verify-sig").value,
    });
    let text = data.match ? "MATCH: signature verifies." : "MISMATCH: signature does not verify.";
    text += "\nexpected (for these inputs):\n" + data.expected;
    if (data.formatIssues && data.formatIssues.length) text += "\nformat issues:\n- " + data.formatIssues.join("\n- ");
    if (data.matchedVariant) text += "\n" + data.matchedVariant;
    if (data.warnings && data.warnings.length) text += "\nwarnings:\n- " + data.warnings.join("\n- ");
    setText(out, text);
  } catch (err) {
    setText(out, "error: " + err.message);
  }
});

document.getElementById("shape-btn").addEventListener("click", async () => {
  const out = document.getElementById("shape-out");
  try {
    const data = await post("/api/preflight", { text: document.getElementById("shape-text").value });
    let text = data.valid ? "VALID: exact preflight shape." : "INVALID: preflight would fail.";
    if (data.deviations && data.deviations.length) text += "\ndeviations:\n- " + data.deviations.join("\n- ");
    setText(out, text);
  } catch (err) {
    setText(out, "error: " + err.message);
  }
});

document.getElementById("vectors-btn").addEventListener("click", async () => {
  const out = document.getElementById("vectors-out");
  try {
    const res = await fetch("/api/vectors");
    const data = await res.json();
    setText(out, data.vectors.map((v) => v.id + ": " + (v.pass ? "PASS" : "FAIL") + "  " + v.actual).join("\n"));
  } catch (err) {
    setText(out, "error: " + err.message);
  }
});

async function loadExamples() {
  const box = document.getElementById("examples");
  try {
    const res = await fetch("/api/examples");
    const data = await res.json();
    box.textContent = "";
    for (const ex of data.examples) {
      const div = document.createElement("div");
      div.className = "example";
      const title = document.createElement("strong");
      title.textContent = ex.title;
      const note = document.createElement("p");
      note.textContent = ex.note;
      const btn = document.createElement("button");
      const out = document.createElement("pre");
      if (ex.kind === "preflight") {
        btn.textContent = "Run shape check";
        btn.addEventListener("click", async () => {
          document.getElementById("shape-text").value = ex.text;
          const data2 = await post("/api/preflight", { text: ex.text });
          setText(out, (data2.valid ? "VALID." : "INVALID.") + (data2.deviations.length ? "\n- " + data2.deviations.join("\n- ") : ""));
        });
        const pre = document.createElement("pre");
        pre.textContent = ex.text;
        div.append(title, pre, note, btn, out);
      } else if (ex.kind === "reserialize") {
        btn.textContent = "Sign both bodies";
        btn.addEventListener("click", async () => {
          const a = await post("/api/sign", { secret: ex.secret, body: ex.bodyA });
          const b = await post("/api/sign", { secret: ex.secret, body: ex.bodyB });
          setText(out, "body A:\n" + a.signature + "\nbody B:\n" + b.signature + "\n" + (a.signature === b.signature ? "SAME (unexpected)" : "DIFFERENT — same meaning, different bytes."));
        });
        const pre = document.createElement("pre");
        pre.textContent = "body A: " + JSON.stringify(ex.bodyA) + "\nbody B: " + JSON.stringify(ex.bodyB);
        div.append(title, pre, note, btn, out);
      } else if (ex.kind === "verify") {
        btn.textContent = "Run verify with uppercase signature";
        btn.addEventListener("click", async () => {
          const signed = await post("/api/sign", { secret: ex.secret, body: ex.body });
          const data2 = await post("/api/verify", { secret: ex.secret, body: ex.body, signature: signed.signature.toUpperCase() });
          setText(out, "match: " + data2.match + "\n- " + data2.formatIssues.join("\n- ") + (data2.matchedVariant ? "\n" + data2.matchedVariant : ""));
        });
        div.append(title, note, btn, out);
      }
      box.appendChild(div);
    }
  } catch (err) {
    setText(box, "failed to load examples: " + err.message);
  }
}

loadExamples();
