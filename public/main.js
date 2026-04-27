// ── Tab switching ─────────────────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach((btn) => {
  btn.addEventListener("click", () => {
    document
      .querySelectorAll(".tab")
      .forEach((t) => t.classList.remove("active"));
    document
      .querySelectorAll(".panel")
      .forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(btn.dataset.target).classList.add("active");
  });
});

// ── Helpers ───────────────────────────────────────────────────────────────────
const v = (id) => document.getElementById(id).value;

function showResult(idPrefix, data) {
  const box = document.getElementById(idPrefix + "-result");
  box.classList.add("visible");
  // strip old sev classes
  box.className = box.className.replace(/sev-\S+/g, "").trim() + " visible";
  if (data.severity) box.classList.add("sev-" + data.severity);

  let out = "";
  if (data.log) out += `📋 LOG    : ${data.log}\n`;
  if (data.severity) out += `⚡ SEVERITY: ${data.severity}\n`;
  if (data.label) out += `🏷  LABEL  : ${data.label}\n`;
  if (data.timestamp) out += `🕐 TIME   : ${data.timestamp}\n`;
  out += "\n── Details ──────────────────────────────\n";

  // print every other key
  const skip = new Set(["log", "severity", "label", "timestamp"]);
  for (const [k, val] of Object.entries(data)) {
    if (skip.has(k)) continue;
    const display =
      typeof val === "object" ? JSON.stringify(val, null, 2) : val;
    out += `${k}: ${display}\n`;
  }
  box.textContent = out;
}

async function send(endpoint, body, method = "POST") {
  // derive result box id from endpoint (replace / with -)
  const idPrefix = endpoint.replace(/\//g, "-");
  const box = document.getElementById(idPrefix + "-result");
  if (box) {
    box.classList.add("visible");
    box.textContent = "Sending…";
  }

  try {
    const opts = { method, headers: { "Content-Type": "application/json" } };
    if (method === "POST") opts.body = JSON.stringify(body);

    const url =
      method === "GET"
        ? `/vuln/${endpoint}?` + new URLSearchParams(body)
        : `/vuln/${endpoint}`;

    const r = await fetch(url, opts);
    const data = await r.json();
    showResult(idPrefix, data);
  } catch (e) {
    if (box) {
      box.textContent = "Error: " + e.message;
    }
  }
}

// ── XSS Reflected (opens page in new tab) ────────────────────────────────────
function openXSSReflected() {
  const input = v("xss-r-input");
  const url = `/vuln/xss-reflected?input=${encodeURIComponent(input)}`;
  const box = document.getElementById("xss-r-result");
  box.classList.add("visible");
  box.textContent = `📋 LOG    : Opening reflected XSS page in new tab\n⚡ SEVERITY: ERROR\n🏷  LABEL  : Web Attack - XSS - Attempted\n\nURL: ${url}\n\nInput echoed unsanitised into HTML response.\nIf payload contains <script> or event handlers, they will execute.`;
  window.open(url, "_blank");
}

// ── XSS Stored – load stored comments ────────────────────────────────────────
async function loadXSSComments() {
  const r = await fetch("/vuln/xss-stored");
  const data = await r.json();
  const box = document.getElementById("xss-s-result");
  box.classList.add("visible");
  box.textContent =
    `Stored comments (${data.comments.length} total):\n\n` +
    data.comments.map((c, i) => `[${i + 1}] ${c}`).join("\n");
}

// ── IDOR ──────────────────────────────────────────────────────────────────────
async function getIDOR() {
  const id = v("idor-id");
  const r = await fetch(`/vuln/idor?id=${id}`);
  const data = await r.json();
  showResult(
    "idor",
    data.error ? { log: data.error, severity: "INFO", label: "IDOR" } : data,
  );
}

// ── Path Traversal ────────────────────────────────────────────────────────────
async function getPath() {
  const file = v("pt-file");
  const r = await fetch(
    `/vuln/path-traversal?file=${encodeURIComponent(file)}`,
  );
  const data = await r.json();
  showResult("path", data);
}

// ── FTP-Patator auto-brute ────────────────────────────────────────────────────
async function autoFTP() {
  const wordlist = [
    "123456",
    "password",
    "admin",
    "letmein",
    "ftppass",
    "ftp123",
  ];
  const username = v("ftp-user");
  const box = document.getElementById("ftp-patator-result");
  box.classList.add("visible");
  box.textContent = `Starting FTP brute-force for "${username}"…\n\n`;
  for (const pw of wordlist) {
    const r = await fetch("/vuln/ftp-patator", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password: pw }),
    });
    const d = await r.json();
    box.textContent += `Trying "${pw}" → ${d.success ? "✅ CRACKED!" : "❌ fail"} (attempt #${d.attempts})\n`;
    if (d.success) {
      box.textContent += "\n🎉 Password found: " + pw;
      break;
    }
    await delay(300);
  }
}

// ── SSH-Patator auto-brute ────────────────────────────────────────────────────
async function autoSSH() {
  const wordlist = [
    "123456",
    "password",
    "admin",
    "letmein",
    "toor",
    "secret123",
  ];
  const username = v("ssh-user");
  const sourceIp = v("ssh-ip");
  const box = document.getElementById("ssh-patator-result");
  box.classList.add("visible");
  box.textContent = `Starting SSH brute-force for "${username}"…\n\n`;
  for (const pw of wordlist) {
    const r = await fetch("/vuln/ssh-patator", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password: pw, sourceIp }),
    });
    const d = await r.json();
    box.textContent += `Trying "${pw}" → ${d.success ? "✅ CRACKED!" : "❌ fail"} (attempt #${d.attempts})\n`;
    if (d.success) {
      box.textContent += "\n🎉 Password found: " + pw;
      break;
    }
    await delay(300);
  }
}

// ── Web Brute Force auto ──────────────────────────────────────────────────────
async function autoWebBrute() {
  const wordlist = [
    "12345678",
    "password1",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "111111",
    "000000",
    "abc123456",
    "1q2w3e4r",
    "q1w2e3r4",
    "pass1234",
    "letmein123",
    "welcome123",
    "adminadmin",
    "root1234",
    "superuser",
    "master123",
    "trustno1",
    "dragon123",
    "football",
    "baseball",
    "monkey123",
    "shadow",
    "sunshine",
    "princess",
    "lovely123",
    "helloWorld",
    "freedom123",
    "whatever",
    "internet",
    "computer",
    "michelle",
    "jessica",
    "charlie",
    "andrew123",
    "daniel123",
    "michael1",
    "jordan23",
    "hunter2",
    "killer123",
    "batman",
    "superman",
    "spiderman",
    "ironman",
    "thomas123",
    "george123",
    "harrypotter",
    "starwars",
    "matrix123",
    "naruto123",
  ];
  const username = v("wb-user");
  const box = document.getElementById("web-brute-result");
  box.classList.add("visible");
  box.textContent = `Starting HTTP brute-force for "${username}"…\n\n`;
  for (const pw of wordlist) {
    const r = await fetch("/vuln/web-bruteforce", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password: pw }),
    });
    const d = await r.json();
    box.textContent += `Trying "${pw}" → ${d.success ? "✅ CRACKED!" : "❌ fail"} (attempt #${d.attempts})\n`;
    if (d.success) {
      box.textContent += "\n🎉 Password found: " + pw;
      break;
    }
    await delay(300);
  }
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));
