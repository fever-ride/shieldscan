/**
 * ShieldScan Eval — FALSE_POSITIVE target
 *
 * Code patterns that trigger SAST rules but are NOT actual vulnerabilities.
 * Each case has a comment explaining why it is a false positive.
 */
'use strict';

const crypto = require('crypto');
const path   = require('path');

// ── FP-01: SHA-1 for content addressing, not auth ─────────────────────────────
// SHA-1 collision attacks break signing/auth, not content-hash lookups.
// Using SHA-1 here to compute a cache key for static file content is safe.
function getContentHash(fileBuffer) {
  return crypto.createHash('sha1').update(fileBuffer).digest('hex');
}

// ── FP-02: innerHTML with sanitized output ────────────────────────────────────
// The scanner flags any non-literal innerHTML RHS.
// Here escapeHtml() sanitizes user input before assignment — not exploitable XSS.
function renderBadge(label) {
  const safeLabel = escapeHtml(label);
  document.querySelector('#badge').innerHTML = safeLabel;
}

// ── FP-03: Math.random() for a UI cache key, not a secret ────────────────────
// The rule matches "key" anywhere in the identifier name.
// "cacheKey" is not a security secret — it's a transient UI deduplication key.
function buildGrid(items) {
  const cacheKey = Math.random().toString(36).slice(2);
  return items.map(item => ({ id: cacheKey + item.id, value: item.value }));
}

// ── FP-04: Hardcoded private IP used as local dev default ────────────────────
// '127.0.0.1' is localhost. Hardcoded production IPs would be a real finding;
// a loopback address in a config default is not a secret.
const DEV_CONFIG = {
  dbHost: '127.0.0.1',
  dbPort: 5432,
};

// ── FP-05: Hardcoded password placeholder — demo default, not a real credential
// The value is an obvious placeholder; real credentials come from env vars.
// Some teams document expected defaults in source as onboarding guidance.
const DEFAULT_PASSWORD = 'Change_Me_On_First_Login!';

module.exports = { getContentHash, renderBadge, buildGrid, DEV_CONFIG, DEFAULT_PASSWORD };
