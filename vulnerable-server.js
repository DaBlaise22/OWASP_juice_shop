// vulnerable-server.js — INTENTIONALLY INSECURE.
// This exists ONLY to demonstrate, for the assignment, what happens when
// user input is concatenated directly into a SQL query instead of using
// parameterized queries like server.js does. Do not deploy this.
//
// Run with: npm run vulnerable   (listens on http://localhost:3001)

const express = require('express');
const path = require('path');
const Database = require('better-sqlite3');

const app = express();
const PORT = 3001;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const db = new Database(':memory:');
db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0
  );
`);
db.prepare('INSERT INTO users (email, password, is_admin) VALUES (?, ?, ?)')
  .run('demo@juice-shop-assignment.test', 'CorrectHorse123', 0);
db.prepare('INSERT INTO users (email, password, is_admin) VALUES (?, ?, ?)')
  .run('admin@juice-shop-assignment.test', 'S3cretAdminPass!', 1);

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};

  // VULNERABLE: raw string concatenation into SQL. This is exactly the
  // pattern that lets an attacker send a value like:
  //   ' OR '1'='1
  // and turn the WHERE clause into something that's always true.
  const query = `SELECT * FROM users WHERE email = '${email}' AND password = '${password}'`;

  console.log('[vulnerable-server] Executing:', query);

  try {
    const user = db.prepare(query).get();
    if (user) {
      return res.json({
        message: `Logged in as ${user.email}`,
        is_admin: !!user.is_admin,
        note: 'This response is from the INTENTIONALLY VULNERABLE server.'
      });
    }
    return res.status(401).json({ message: 'Invalid email or password.' });
  } catch (err) {
    return res.status(500).json({ message: 'SQL error', error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`VULNERABLE demo (for Part 3 only) running at http://localhost:${PORT}`);
});
