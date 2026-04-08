/**
 * ShieldScan Eval — TRUE_POSITIVE target
 *
 * Intentionally vulnerable JavaScript. DO NOT deploy.
 * Each vulnerability is a deliberate SAST ground-truth positive.
 */
'use strict';

const db      = require('./db');
const fs      = require('fs');
const jwt     = require('jsonwebtoken');
const crypto  = require('crypto');
const cp      = require('child_process');
const express = require('express');
const cors    = require('cors');

// ── SQL Injection ─────────────────────────────────────────────────────────────

// TP-01: string concatenation in SELECT
async function getUser(userId) {
  return db.query('SELECT * FROM users WHERE id = ' + userId);
}

// TP-02: template literal in SELECT
async function searchProducts(name) {
  return db.query(`SELECT * FROM products WHERE name = '${name}'`);
}

// ── NoSQL Injection ───────────────────────────────────────────────────────────

// TP-03: req.query passed directly to find()
function listUsers(req, res) {
  User.find(req.query).then(users => res.json(users));
}

// TP-04: req.body passed directly to findOne()
function getProfile(req, res) {
  User.findOne(req.body).then(user => res.json(user));
}

// ── XSS ───────────────────────────────────────────────────────────────────────

// TP-05: raw user input assigned to innerHTML
function renderComment(userInput) {
  document.querySelector('#comments').innerHTML = userInput;
}

// ── Path Traversal ────────────────────────────────────────────────────────────

// TP-06: req.params.filename used directly in readFile
function downloadFile(req, res) {
  fs.readFile(req.params.filename, 'utf8', (err, data) => res.send(data));
}

// ── Insecure Functions ────────────────────────────────────────────────────────

// TP-07: eval() with external input
function runFormula(expression) {
  return eval(expression);
}

// TP-08: child_process exec with unsanitised host
function runDiagnostics(host) {
  cp.exec('ping ' + host);
}

// ── JWT Misuse ────────────────────────────────────────────────────────────────

// TP-09: jwt.decode skips signature verification entirely
function getUserFromToken(token) {
  const payload = jwt.decode(token);
  return payload?.userId;
}

// TP-10: jwt.verify with null secret disables verification
function verifyToken(token) {
  return jwt.verify(token, null);
}

// ── Weak Cryptography ─────────────────────────────────────────────────────────

// TP-11: MD5 used for password hashing — broken algorithm for this use case
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// ── Insecure Randomness ───────────────────────────────────────────────────────

// TP-12: Math.random() used as auth session token — not CSPRNG
function generateSessionToken() {
  const token = Math.random().toString(36).slice(2);
  return token;
}

// ── Prototype Pollution ───────────────────────────────────────────────────────

// TP-13: Object.assign onto existing object with req.body — prototype pollution risk
function updateSettings(req, currentSettings) {
  Object.assign(currentSettings, req.body);
  return currentSettings;
}

// ── CORS Misconfiguration ─────────────────────────────────────────────────────

// TP-14: wildcard CORS origin allows any domain
const app = express();
app.use(cors({ origin: '*' }));

// ── Hardcoded Secret ──────────────────────────────────────────────────────────

// TP-15: hardcoded demo API key in source
const apikey = 'DEMOHARDCODEDAPIKEY1234567890';

// ── Sensitive Data Logging ────────────────────────────────────────────────────

// TP-16: password field logged to console
function debugUser(user) {
  console.log({ username: user.username, password: user.password });
}

module.exports = { getUser, searchProducts, listUsers, getProfile, renderComment,
  downloadFile, runFormula, runDiagnostics, getUserFromToken, verifyToken,
  hashPassword, generateSessionToken, updateSettings, debugUser };
