// fang-scan — security headers checker.
// Pure auditing logic (parseHeaders, auditHeaders, gradeScore) is exported
// for tests; the browser UI wiring at the bottom is guarded so this module
// also runs under Node. Everything runs locally — headers are never uploaded.

export const SAMPLE_WEAK = `HTTP/1.1 200 OK
Date: Wed, 25 Nov 2026 15:15:00 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Powered-By: PHP/7.4.3
Content-Type: text/html; charset=UTF-8
Content-Security-Policy: default-src * 'unsafe-inline' 'unsafe-eval'
Referrer-Policy: unsafe-url
X-XSS-Protection: 1; mode=block
Cache-Control: public, max-age=86400
Set-Cookie: sessionid=abc123; Path=/
Content-Length: 5123`;

export const SAMPLE_STRONG = `HTTP/2 200
date: Wed, 25 Nov 2026 15:15:00 GMT
content-type: text/html; charset=utf-8
strict-transport-security: max-age=63072000; includeSubDomains; preload
content-security-policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'
x-content-type-options: nosniff
x-frame-options: DENY
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=(), payment=()
x-xss-protection: 0
cache-control: no-store
set-cookie: sessionid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax
content-length: 5123`;

const HSTS_MIN_MAX_AGE = 31536000; // one year, in seconds

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/**
 * Parse raw HTTP response headers into a plain object mapping each
 * lower-cased header name to an array of its values (duplicates kept).
 * Status lines, blank lines and malformed lines are skipped; obsolete
 * line folding (a line starting with whitespace) is joined to the
 * previous value.
 */
export function parseHeaders(raw) {
  const headers = {};
  if (typeof raw !== "string") return headers;

  let lastName = null;
  for (const line of raw.split(/\r\n|\r|\n/)) {
    if (!line.trim()) continue;

    // Folded continuation of the previous header value.
    if (/^[ \t]/.test(line) && lastName) {
      const values = headers[lastName];
      values[values.length - 1] += ` ${line.trim()}`;
      continue;
    }

    if (/^HTTP\/\d/i.test(line.trim())) continue; // status line

    const colon = line.indexOf(":");
    if (colon <= 0) continue;

    const name = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (!name || /\s/.test(name)) continue;

    if (!headers[name]) headers[name] = [];
    headers[name].push(value);
    lastName = name;
  }
  return headers;
}

/** Normalise a string / Map / plain object into the parsed-header shape. */
function normalizeHeaders(input) {
  if (typeof input === "string") return parseHeaders(input);
  const headers = {};
  if (!input) return headers;
  const entries = input instanceof Map ? input.entries() : Object.entries(input);
  for (const [name, value] of entries) {
    const key = String(name).trim().toLowerCase();
    if (!key) continue;
    headers[key] = Array.isArray(value) ? value.map(String) : [String(value)];
  }
  return headers;
}

/** First value of a header (case-insensitive), or undefined. */
export function getHeader(headers, name) {
  const values = headers[String(name).toLowerCase()];
  return values && values.length ? values[0] : undefined;
}

function joined(headers, name) {
  const values = headers[name];
  return values && values.length ? values.join(", ") : null;
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/** Letter grade for a 0–100 score: A ≥90, B ≥80, C ≥70, D ≥60, else F. */
export function gradeScore(score) {
  const value = Math.max(0, Math.min(100, Number(score) || 0));
  if (value >= 90) return "A";
  if (value >= 80) return "B";
  if (value >= 70) return "C";
  if (value >= 60) return "D";
  return "F";
}

/** Weighted score (0–100) from findings: pass = full, warn = half, fail = 0. */
export function computeScore(findings) {
  let earned = 0;
  let possible = 0;
  for (const finding of findings) {
    const weight = finding.weight || 0;
    possible += weight;
    if (finding.status === "pass") earned += weight;
    else if (finding.status === "warn") earned += weight / 2;
  }
  return possible > 0 ? Math.round((earned / possible) * 100) : 0;
}

function finding(id, header, title, weight, status, severity, explanation, fix, value) {
  return { id, header, title, weight, status, severity, explanation, fix, value: value ?? null };
}

// ---------------------------------------------------------------------------
// Individual checks — each returns status pass/warn/fail + explanation + fix
// ---------------------------------------------------------------------------

function checkHsts(headers) {
  const fix = "Strict-Transport-Security: max-age=31536000; includeSubDomains";
  const value = getHeader(headers, "strict-transport-security");
  if (value === undefined) {
    return finding("hsts", "Strict-Transport-Security", "HTTP Strict Transport Security", 15,
      "fail", "high",
      "Missing. Without HSTS, browsers may fall back to plain HTTP and a network attacker can strip TLS (SSL stripping) on the first visit.",
      fix, null);
  }
  const match = value.match(/max-age\s*=\s*"?(\d+)"?/i);
  const maxAge = match ? Number(match[1]) : null;
  if (maxAge === null || maxAge === 0) {
    return finding("hsts", "Strict-Transport-Security", "HTTP Strict Transport Security", 15,
      "fail", "high",
      "Present but max-age is missing or zero, so browsers will not enforce HTTPS.",
      fix, value);
  }
  if (maxAge < HSTS_MIN_MAX_AGE) {
    return finding("hsts", "Strict-Transport-Security", "HTTP Strict Transport Security", 15,
      "warn", "medium",
      `max-age is ${maxAge}s — shorter than the recommended one year (${HSTS_MIN_MAX_AGE}s), so the protection lapses quickly for returning visitors.`,
      fix, value);
  }
  if (!/includesubdomains/i.test(value)) {
    return finding("hsts", "Strict-Transport-Security", "HTTP Strict Transport Security", 15,
      "warn", "medium",
      "max-age is strong, but includeSubDomains is missing — subdomains can still be reached over plain HTTP.",
      fix, value);
  }
  return finding("hsts", "Strict-Transport-Security", "HTTP Strict Transport Security", 15,
    "pass", "info",
    `HTTPS is enforced for ${maxAge}s including subdomains${/preload/i.test(value) ? ", with preload" : ""}.`,
    fix, value);
}

function parseCspDirectives(value) {
  const directives = {};
  for (const part of value.split(";")) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    directives[tokens[0].toLowerCase()] = tokens.slice(1);
  }
  return directives;
}

function checkCsp(headers) {
  const fix = "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'";
  const value = getHeader(headers, "content-security-policy");
  if (value === undefined) {
    return finding("csp", "Content-Security-Policy", "Content Security Policy", 20,
      "fail", "high",
      "Missing. A CSP is the main defence-in-depth against cross-site scripting (XSS) and data injection — without one, any injected script runs with full page privileges.",
      fix, null);
  }
  const directives = parseCspDirectives(value);
  const issues = [];
  if (/'unsafe-inline'/i.test(value)) {
    issues.push("'unsafe-inline' allows inline scripts/styles, which largely defeats XSS protection");
  }
  if (/'unsafe-eval'/i.test(value)) {
    issues.push("'unsafe-eval' allows eval() and similar string-to-code APIs");
  }
  const wildcardIn = Object.entries(directives)
    .filter(([, sources]) => sources.some((s) => s === "*" || s.startsWith("*.")))
    .map(([name]) => name);
  if (wildcardIn.length) {
    issues.push(`wildcard source (*) in ${wildcardIn.join(", ")} lets content load from anywhere`);
  }
  if (!directives["default-src"] && !directives["script-src"]) {
    issues.push("no default-src or script-src directive, so scripts are unrestricted by default");
  }
  if (issues.length) {
    return finding("csp", "Content-Security-Policy", "Content Security Policy", 20,
      "warn", "high",
      `Present but weakened: ${issues.join("; ")}.`,
      fix, value);
  }
  return finding("csp", "Content-Security-Policy", "Content Security Policy", 20,
    "pass", "info",
    "Present with no unsafe-inline, unsafe-eval or wildcard sources.",
    fix, value);
}

function checkContentTypeOptions(headers) {
  const fix = "X-Content-Type-Options: nosniff";
  const value = getHeader(headers, "x-content-type-options");
  if (value === undefined) {
    return finding("xcto", "X-Content-Type-Options", "MIME sniffing protection", 10,
      "fail", "medium",
      "Missing. Browsers may MIME-sniff responses away from the declared Content-Type, which can turn an uploaded file into executable script.",
      fix, null);
  }
  if (value.trim().toLowerCase() === "nosniff") {
    return finding("xcto", "X-Content-Type-Options", "MIME sniffing protection", 10,
      "pass", "info", "Set to nosniff — browsers must respect the declared Content-Type.", fix, value);
  }
  return finding("xcto", "X-Content-Type-Options", "MIME sniffing protection", 10,
    "warn", "medium",
    `Value "${value}" is not "nosniff", so browsers may ignore it.`,
    fix, value);
}

function checkFrameProtection(headers) {
  const fix = "X-Frame-Options: DENY  (or CSP: frame-ancestors 'none')";
  const csp = getHeader(headers, "content-security-policy");
  if (csp && parseCspDirectives(csp)["frame-ancestors"]) {
    return finding("frame", "X-Frame-Options / frame-ancestors", "Clickjacking protection", 10,
      "pass", "info",
      "CSP frame-ancestors controls who may embed this page, which supersedes X-Frame-Options in modern browsers.",
      fix, `frame-ancestors ${parseCspDirectives(csp)["frame-ancestors"].join(" ")}`);
  }
  const value = getHeader(headers, "x-frame-options");
  if (value === undefined) {
    return finding("frame", "X-Frame-Options / frame-ancestors", "Clickjacking protection", 10,
      "fail", "medium",
      "Neither X-Frame-Options nor CSP frame-ancestors is set, so any site can embed this page in a frame and attempt clickjacking.",
      fix, null);
  }
  const normalized = value.trim().toUpperCase();
  if (normalized === "DENY" || normalized === "SAMEORIGIN") {
    return finding("frame", "X-Frame-Options / frame-ancestors", "Clickjacking protection", 10,
      "pass", "info", `Framing is restricted with X-Frame-Options: ${normalized}.`, fix, value);
  }
  return finding("frame", "X-Frame-Options / frame-ancestors", "Clickjacking protection", 10,
    "warn", "medium",
    `Value "${value}" is not DENY or SAMEORIGIN (ALLOW-FROM is obsolete and ignored by modern browsers).`,
    fix, value);
}

function checkReferrerPolicy(headers) {
  const fix = "Referrer-Policy: strict-origin-when-cross-origin";
  const value = getHeader(headers, "referrer-policy");
  if (value === undefined) {
    return finding("referrer", "Referrer-Policy", "Referrer leakage control", 10,
      "warn", "medium",
      "Missing. Modern browsers default to strict-origin-when-cross-origin, but setting the policy explicitly keeps behaviour predictable across browsers and downgrade scenarios.",
      fix, null);
  }
  const tokens = value.toLowerCase().split(",").map((t) => t.trim()).filter(Boolean);
  if (tokens.includes("unsafe-url")) {
    return finding("referrer", "Referrer-Policy", "Referrer leakage control", 10,
      "fail", "high",
      "unsafe-url sends the full URL — including paths and query strings that may contain tokens — to every origin, even over plain HTTP.",
      fix, value);
  }
  const strong = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];
  if (tokens.some((t) => strong.includes(t))) {
    return finding("referrer", "Referrer-Policy", "Referrer leakage control", 10,
      "pass", "info", "Referrer information is limited to the origin (or withheld) for cross-origin requests.", fix, value);
  }
  return finding("referrer", "Referrer-Policy", "Referrer leakage control", 10,
    "warn", "medium",
    `Policy "${value}" can leak full URLs or origins to other sites; prefer strict-origin-when-cross-origin or stricter.`,
    fix, value);
}

function checkPermissionsPolicy(headers) {
  const fix = "Permissions-Policy: camera=(), microphone=(), geolocation=()";
  const value = getHeader(headers, "permissions-policy");
  if (value === undefined) {
    return finding("permissions", "Permissions-Policy", "Browser feature control", 10,
      "warn", "medium",
      "Missing. Without a Permissions-Policy, embedded content and scripts can request powerful features (camera, microphone, geolocation) under the browser defaults.",
      fix, null);
  }
  if (/=\s*\*/.test(value) || /=\s*\(\s*\*/.test(value)) {
    return finding("permissions", "Permissions-Policy", "Browser feature control", 10,
      "warn", "medium",
      "Present, but at least one feature is allowed for all origins (*), which gives embedded third parties broad access.",
      fix, value);
  }
  return finding("permissions", "Permissions-Policy", "Browser feature control", 10,
    "pass", "info", "Present — powerful browser features are explicitly scoped.", fix, value);
}

function checkXssProtection(headers) {
  const fix = "X-XSS-Protection: 0  (rely on a strong Content-Security-Policy instead)";
  const value = getHeader(headers, "x-xss-protection");
  if (value === undefined) {
    return finding("xss-protection", "X-XSS-Protection", "Legacy XSS auditor", 5,
      "pass", "info",
      "Not set — fine. The legacy XSS auditor is deprecated and removed from modern browsers; a strong CSP is the replacement. Informational only.",
      fix, null);
  }
  if (value.trim().startsWith("0")) {
    return finding("xss-protection", "X-XSS-Protection", "Legacy XSS auditor", 5,
      "pass", "info", "Set to 0, disabling the legacy auditor — the recommended value alongside a CSP.", fix, value);
  }
  return finding("xss-protection", "X-XSS-Protection", "Legacy XSS auditor", 5,
    "warn", "low",
    `"${value}" enables the outdated browser XSS auditor, which can itself introduce vulnerabilities and is ignored by modern browsers. Prefer 0 plus a strong CSP.`,
    fix, value);
}

function checkVersionDisclosure(headers) {
  const fix = "Remove or genericise the Server header and drop X-Powered-By (e.g. expose_php = Off)";
  const server = getHeader(headers, "server");
  const poweredBy = getHeader(headers, "x-powered-by");
  const issues = [];
  if (poweredBy !== undefined) {
    issues.push(`X-Powered-By discloses the stack ("${poweredBy}")`);
  }
  if (server !== undefined && /\d/.test(server)) {
    issues.push(`Server discloses a version ("${server}")`);
  }
  if (issues.length) {
    return finding("disclosure", "Server / X-Powered-By", "Version disclosure", 5,
      "warn", "medium",
      `${issues.join(" and ")}. Version banners hand attackers a shortcut to known CVEs for that exact release.`,
      fix, joined(headers, "x-powered-by") || server);
  }
  if (server !== undefined) {
    return finding("disclosure", "Server / X-Powered-By", "Version disclosure", 5,
      "warn", "low",
      `Server header ("${server}") names the software without a version. Low risk, but a generic or absent banner reveals less.`,
      fix, server);
  }
  return finding("disclosure", "Server / X-Powered-By", "Version disclosure", 5,
    "pass", "info", "No Server version banner or X-Powered-By header is exposed.", fix, null);
}

function checkCacheControl(headers) {
  const fix = "Cache-Control: no-store  (for authenticated or otherwise sensitive responses)";
  const value = getHeader(headers, "cache-control");
  if (value === undefined) {
    return finding("cache", "Cache-Control", "Sensitive response caching", 5,
      "warn", "low",
      "Missing. Informational: if this response carries sensitive or authenticated data, set Cache-Control: no-store so shared caches and browsers do not retain it.",
      fix, null);
  }
  const lower = value.toLowerCase();
  if (lower.includes("no-store")) {
    return finding("cache", "Cache-Control", "Sensitive response caching", 5,
      "pass", "info", "no-store prevents the response from being retained by any cache.", fix, value);
  }
  if (lower.includes("private") || lower.includes("no-cache")) {
    return finding("cache", "Cache-Control", "Sensitive response caching", 5,
      "pass", "info", "Caching is limited (private/no-cache); use no-store for the most sensitive responses.", fix, value);
  }
  if (lower.includes("public")) {
    return finding("cache", "Cache-Control", "Sensitive response caching", 5,
      "warn", "low",
      "Marked public, so shared caches may store this response. Fine for static assets — risky if the response is authenticated or personalised. Informational.",
      fix, value);
  }
  return finding("cache", "Cache-Control", "Sensitive response caching", 5,
    "warn", "low",
    "Present without no-store/private/no-cache. Informational: confirm sensitive responses cannot be retained by shared caches.",
    fix, value);
}

function checkCookies(headers) {
  const fix = "Set-Cookie: session=…; Path=/; Secure; HttpOnly; SameSite=Lax";
  const cookies = headers["set-cookie"] || [];
  if (!cookies.length) {
    return finding("cookies", "Set-Cookie", "Cookie security flags", 0,
      "pass", "info",
      "No Set-Cookie headers present, so there are no cookie flags to audit.",
      fix, null);
  }
  const problems = [];
  let hardFailure = false;
  for (const cookie of cookies) {
    const [pair, ...attributes] = cookie.split(";");
    const name = pair.split("=")[0].trim() || "(unnamed)";
    const attrs = attributes.map((a) => a.trim().toLowerCase());
    const missing = [];
    if (!attrs.some((a) => a === "secure")) missing.push("Secure");
    if (!attrs.some((a) => a === "httponly")) missing.push("HttpOnly");
    const sameSite = attrs.find((a) => a.startsWith("samesite"));
    if (!sameSite) missing.push("SameSite");
    if (sameSite && sameSite.replace(/\s+/g, "") === "samesite=none" && !attrs.some((a) => a === "secure")) {
      missing.push("Secure (required with SameSite=None)");
    }
    if (missing.length) {
      problems.push(`"${name}" is missing ${missing.join(", ")}`);
      if (missing.some((m) => m.startsWith("Secure") || m === "HttpOnly")) hardFailure = true;
    }
  }
  // Cookie names only — never echo cookie values back into the report.
  const names = cookies.map((c) => c.split("=")[0].trim()).join(", ");
  if (problems.length) {
    return finding("cookies", "Set-Cookie", "Cookie security flags", 10,
      hardFailure ? "fail" : "warn", hardFailure ? "high" : "medium",
      `Cookie flags incomplete: ${problems.join("; ")}. Secure keeps cookies on HTTPS, HttpOnly blocks script access, and SameSite limits cross-site sending (CSRF).`,
      fix, names);
  }
  return finding("cookies", "Set-Cookie", "Cookie security flags", 10,
    "pass", "info",
    `All ${cookies.length} cookie(s) set Secure, HttpOnly and SameSite.`,
    fix, names);
}

// ---------------------------------------------------------------------------
// Audit entry point
// ---------------------------------------------------------------------------

/**
 * Audit raw headers (string) or an already-parsed header object.
 * Returns { score, grade, findings, summary, headerCount } where each
 * finding has status (pass/warn/fail), severity, explanation and fix.
 */
export function auditHeaders(input) {
  const headers = normalizeHeaders(input);
  const findings = [
    checkHsts(headers),
    checkCsp(headers),
    checkContentTypeOptions(headers),
    checkFrameProtection(headers),
    checkReferrerPolicy(headers),
    checkPermissionsPolicy(headers),
    checkXssProtection(headers),
    checkVersionDisclosure(headers),
    checkCacheControl(headers),
    checkCookies(headers),
  ];
  const score = computeScore(findings);
  const summary = { pass: 0, warn: 0, fail: 0 };
  for (const f of findings) summary[f.status] += 1;
  const headerCount = Object.values(headers).reduce((n, v) => n + v.length, 0);
  return { score, grade: gradeScore(score), findings, summary, headerCount };
}

// ---------------------------------------------------------------------------
// Browser UI (guarded — skipped under Node/tests)
// ---------------------------------------------------------------------------

if (typeof document !== "undefined") {
  const GRADE_NOTES = {
    A: "Fangs sharp — these headers are in great shape.",
    B: "Strong bite. A couple of small gaps to close.",
    C: "Getting there, but an attacker still finds openings.",
    D: "Weak defences — several important headers need work.",
    F: "Wide open. Start with the failing checks below.",
  };

  const els = {
    input: document.getElementById("headers-input"),
    auditBtn: document.getElementById("audit-btn"),
    weakBtn: document.getElementById("sample-weak-btn"),
    strongBtn: document.getElementById("sample-strong-btn"),
    clearBtn: document.getElementById("clear-btn"),
    results: document.getElementById("results"),
    grade: document.getElementById("grade-letter"),
    score: document.getElementById("score-value"),
    note: document.getElementById("grade-note"),
    ring: document.getElementById("score-ring"),
    summary: document.getElementById("summary-chips"),
    parsed: document.getElementById("parsed-count"),
    findings: document.getElementById("findings-list"),
  };

  function chip(text, className) {
    const span = document.createElement("span");
    span.className = `chip ${className}`;
    span.textContent = text;
    return span;
  }

  function renderFinding(f) {
    const card = document.createElement("article");
    card.className = `finding finding-${f.status}`;

    const head = document.createElement("div");
    head.className = "finding-head";
    const title = document.createElement("h3");
    title.textContent = f.title;
    head.append(title, chip(f.status.toUpperCase(), `chip-status-${f.status}`), chip(f.severity, "chip-severity"));
    card.append(head);

    const headerName = document.createElement("p");
    headerName.className = "finding-header";
    headerName.textContent = f.header;
    card.append(headerName);

    const explanation = document.createElement("p");
    explanation.className = "finding-explanation";
    explanation.textContent = f.explanation;
    card.append(explanation);

    if (f.value) {
      const observed = document.createElement("p");
      observed.className = "finding-observed";
      const label = document.createElement("span");
      label.textContent = "Observed: ";
      const code = document.createElement("code");
      code.textContent = f.value;
      observed.append(label, code);
      card.append(observed);
    }

    const fixWrap = document.createElement("p");
    fixWrap.className = "finding-fix";
    const fixLabel = document.createElement("span");
    fixLabel.textContent = "Fix: ";
    const fixCode = document.createElement("code");
    fixCode.textContent = f.fix;
    fixWrap.append(fixLabel, fixCode);
    card.append(fixWrap);

    return card;
  }

  function render(result) {
    els.results.hidden = false;
    els.grade.textContent = result.grade;
    els.score.textContent = String(result.score);
    els.note.textContent = GRADE_NOTES[result.grade];
    els.ring.style.setProperty("--score", String(result.score));
    els.ring.dataset.grade = result.grade;
    els.parsed.textContent = `Parsed ${result.headerCount} header${result.headerCount === 1 ? "" : "s"} · ${result.findings.length} checks`;
    els.summary.replaceChildren(
      chip(`${result.summary.pass} pass`, "chip-status-pass"),
      chip(`${result.summary.warn} warn`, "chip-status-warn"),
      chip(`${result.summary.fail} fail`, "chip-status-fail"),
    );
    els.findings.replaceChildren(...result.findings.map(renderFinding));
  }

  function runAudit() {
    render(auditHeaders(els.input.value));
  }

  els.auditBtn.addEventListener("click", runAudit);
  els.weakBtn.addEventListener("click", () => {
    els.input.value = SAMPLE_WEAK;
    runAudit();
  });
  els.strongBtn.addEventListener("click", () => {
    els.input.value = SAMPLE_STRONG;
    runAudit();
  });
  els.clearBtn.addEventListener("click", () => {
    els.input.value = "";
    els.results.hidden = true;
    els.input.focus();
  });

  // Preload the weak sample so the first paint already shows a full audit.
  els.input.value = SAMPLE_WEAK;
  runAudit();
}
