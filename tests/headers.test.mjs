import { test } from "node:test";
import assert from "node:assert/strict";

import {
  parseHeaders,
  auditHeaders,
  gradeScore,
  SAMPLE_WEAK,
  SAMPLE_STRONG,
} from "../app.js";

function finding(result, id) {
  const found = result.findings.find((f) => f.id === id);
  assert.ok(found, `expected a finding with id "${id}"`);
  return found;
}

// --- Parser ---------------------------------------------------------------

test("parser lower-cases names and trims values", () => {
  const headers = parseHeaders("Content-Type:  text/html ; charset=utf-8 \r\nX-Custom:Value");
  assert.deepEqual(headers["content-type"], ["text/html ; charset=utf-8"]);
  assert.deepEqual(headers["x-custom"], ["Value"]);
});

test("parser keeps duplicate headers as separate values", () => {
  const headers = parseHeaders("Set-Cookie: a=1\nset-cookie: b=2\nSET-COOKIE: c=3");
  assert.deepEqual(headers["set-cookie"], ["a=1", "b=2", "c=3"]);
});

test("parser skips the status line, blank lines and malformed lines", () => {
  const headers = parseHeaders("HTTP/1.1 200 OK\n\nnot a header\nX-Ok: yes\n: nope");
  assert.deepEqual(Object.keys(headers), ["x-ok"]);
});

test("parser joins folded continuation lines", () => {
  const headers = parseHeaders("X-Long: first\n\tsecond");
  assert.deepEqual(headers["x-long"], ["first second"]);
});

test("parser returns an empty object for non-string input", () => {
  assert.deepEqual(parseHeaders(undefined), {});
  assert.deepEqual(parseHeaders(null), {});
  assert.deepEqual(parseHeaders(""), {});
});

// --- Scoring --------------------------------------------------------------

test("strong headers score high and earn an A", () => {
  const result = auditHeaders(SAMPLE_STRONG);
  assert.ok(result.score >= 90, `expected score >= 90, got ${result.score}`);
  assert.equal(result.grade, "A");
  assert.equal(result.summary.fail, 0);
});

test("missing headers score low and earn an F", () => {
  const result = auditHeaders("HTTP/1.1 200 OK\nContent-Type: text/html");
  assert.ok(result.score < 40, `expected score < 40, got ${result.score}`);
  assert.equal(result.grade, "F");
  assert.equal(finding(result, "hsts").status, "fail");
  assert.equal(finding(result, "csp").status, "fail");
});

test("weak sample scores far below the strong sample", () => {
  const weak = auditHeaders(SAMPLE_WEAK);
  const strong = auditHeaders(SAMPLE_STRONG);
  assert.ok(weak.score < strong.score - 50, `weak ${weak.score} vs strong ${strong.score}`);
  assert.equal(weak.grade, "F");
});

test("grade boundaries", () => {
  assert.equal(gradeScore(100), "A");
  assert.equal(gradeScore(90), "A");
  assert.equal(gradeScore(89), "B");
  assert.equal(gradeScore(80), "B");
  assert.equal(gradeScore(79), "C");
  assert.equal(gradeScore(70), "C");
  assert.equal(gradeScore(69), "D");
  assert.equal(gradeScore(60), "D");
  assert.equal(gradeScore(59), "F");
  assert.equal(gradeScore(0), "F");
});

// --- Individual checks ------------------------------------------------------

test("CSP with unsafe-inline and unsafe-eval is flagged", () => {
  const result = auditHeaders("Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval'");
  const csp = finding(result, "csp");
  assert.equal(csp.status, "warn");
  assert.match(csp.explanation, /unsafe-inline/);
  assert.match(csp.explanation, /unsafe-eval/);
});

test("CSP wildcard source is flagged", () => {
  const result = auditHeaders("Content-Security-Policy: script-src *");
  const csp = finding(result, "csp");
  assert.equal(csp.status, "warn");
  assert.match(csp.explanation, /wildcard/);
});

test("cookie without Secure/HttpOnly/SameSite is flagged", () => {
  const result = auditHeaders("Set-Cookie: sessionid=abc123; Path=/");
  const cookies = finding(result, "cookies");
  assert.equal(cookies.status, "fail");
  assert.match(cookies.explanation, /Secure/);
  assert.match(cookies.explanation, /HttpOnly/);
  assert.match(cookies.explanation, /SameSite/);
  // Cookie values must never be echoed into the report.
  assert.ok(!cookies.value.includes("abc123"));
});

test("fully flagged cookie passes", () => {
  const result = auditHeaders("Set-Cookie: sessionid=abc123; Secure; HttpOnly; SameSite=Strict");
  assert.equal(finding(result, "cookies").status, "pass");
});

test("HSTS with a short max-age warns; a year plus subdomains passes", () => {
  const short = auditHeaders("Strict-Transport-Security: max-age=86400; includeSubDomains");
  assert.equal(finding(short, "hsts").status, "warn");

  const noSubdomains = auditHeaders("Strict-Transport-Security: max-age=31536000");
  assert.equal(finding(noSubdomains, "hsts").status, "warn");

  const strong = auditHeaders("Strict-Transport-Security: max-age=31536000; includeSubDomains");
  assert.equal(finding(strong, "hsts").status, "pass");
});

test("CSP frame-ancestors satisfies clickjacking protection without X-Frame-Options", () => {
  const result = auditHeaders("Content-Security-Policy: default-src 'self'; frame-ancestors 'none'");
  assert.equal(finding(result, "frame").status, "pass");
});

test("Referrer-Policy unsafe-url is flagged", () => {
  const result = auditHeaders("Referrer-Policy: unsafe-url");
  const referrer = finding(result, "referrer");
  assert.notEqual(referrer.status, "pass");
  assert.match(referrer.explanation, /unsafe-url/);
});

test("version banners in Server / X-Powered-By warn", () => {
  const result = auditHeaders("Server: Apache/2.4.41 (Ubuntu)\nX-Powered-By: PHP/7.4.3");
  const disclosure = finding(result, "disclosure");
  assert.equal(disclosure.status, "warn");
  assert.match(disclosure.explanation, /Apache\/2\.4\.41|X-Powered-By/);
});

test("X-XSS-Protection 1; mode=block warns as outdated, 0 passes", () => {
  const outdated = auditHeaders("X-XSS-Protection: 1; mode=block");
  assert.equal(finding(outdated, "xss-protection").status, "warn");

  const disabled = auditHeaders("X-XSS-Protection: 0");
  assert.equal(finding(disabled, "xss-protection").status, "pass");
});

test("every finding carries a status, explanation and fix", () => {
  const result = auditHeaders(SAMPLE_WEAK);
  assert.equal(result.findings.length, 10);
  for (const f of result.findings) {
    assert.ok(["pass", "warn", "fail"].includes(f.status), `${f.id} status`);
    assert.ok(f.explanation.length > 0, `${f.id} explanation`);
    assert.ok(f.fix.length > 0, `${f.id} fix`);
    assert.ok(f.severity.length > 0, `${f.id} severity`);
  }
});

test("audit accepts a pre-parsed header object identically", () => {
  const fromString = auditHeaders(SAMPLE_STRONG);
  const fromObject = auditHeaders(parseHeaders(SAMPLE_STRONG));
  assert.equal(fromObject.score, fromString.score);
  assert.deepEqual(
    fromObject.findings.map((f) => f.status),
    fromString.findings.map((f) => f.status),
  );
});
