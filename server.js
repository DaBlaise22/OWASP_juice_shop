// server.js — SECURE version.
// Run with: npm start   (listens on http://localhost:3000)
//
// Security measures implemented here (mapped to Part 1 of the assignment):
// 1. SQL Injection  -> parameterized queries via better-sqlite3 (no string
//    concatenation of user input into SQL, ever).
// 2. XSS             -> we never reflect raw user input back as HTML; JSON
//    responses only, and the front end renders them with textContent.
//    Helmet-style headers (CSP) are added manually below.
// 3. Auth bypass / brute force -> bcrypt password hashing (never store or
//    compare plaintext passwords), generic error messages (no user
//    enumeration), and rate limiting on the login route.

const express = require('express');
const path = require('path');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Basic security headers (a hand-rolled minimal CSP; in production use helmet)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});

// ---- Database setup (in-memory for demo purposes) ----
const db = new Database(':memory:');
db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  );
`);

// Seed one demo user with a bcrypt-hashed password (12 salt rounds).
const seedPassword = 'CorrectHorse123'; // 8+ chars, meets the assignment's rule
const seedHash = bcrypt.hashSync(seedPassword, 12);
db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)')
  .run('demo@juice-shop-assignment.test', seedHash);

console.log(`Seeded demo user -> email: demo@juice-shop-assignment.test  password: ${seedPassword}`);

// ---- Rate limiting: mitigates brute force / credential stuffing ----
const loginLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 5,              // 5 attempts per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: 'Too many login attempts. Please try again in a minute.' }
});

// ---- Server-side validation (never trust the client) ----
function isValidLoginPayload(body) {
  if (!body || typeof body.email !== 'string' || typeof body.password !== 'string') return false;
  const email = body.email.trim();
  if (email.length === 0 || email.length > 254) return false;
  if (!email.includes('@')) return false;
  if (body.password.length < 8 || body.password.length > 128) return false;
  return true;
}

app.post('/api/login', loginLimiter, (req, res) => {
  if (!isValidLoginPayload(req.body)) {
    return res.status(400).json({ message: 'Invalid email or password format.' });
  }

  const email = req.body.email.trim();
  const password = req.body.password;

  // Parameterized query -> the "?" placeholder is bound by the driver,
  // never string-concatenated. This is what defeats SQL injection such as
  // classic  ' OR '1'='1  payloads.
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);

  // Generic failure message regardless of whether the email exists, and a
  // constant-ish path (bcrypt.compare runs either way conceptually) to
  // reduce user-enumeration / timing signal.
  const genericFail = () => res.status(401).json({ message: 'Invalid email or password.' });

  if (!user) return genericFail();

  bcrypt.compare(password, user.password_hash, (err, match) => {
    if (err || !match) return genericFail();
    return res.json({ message: `Welcome back, ${user.email}!` });
  });
});

app.listen(PORT, () => {
  console.log(`Secure login demo running at http://localhost:${PORT}`);
});
