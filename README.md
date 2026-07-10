# Secure Login Form — OWASP Juice Shop Security Assignment

A minimal login form (HTML/JS front end + Express/SQLite back end) built to
demonstrate secure design after studying vulnerabilities in
[OWASP Juice Shop](https://preview.owasp-juice.shop/). The repo contains
**two** back ends on purpose:

| File                  | Port | Purpose                                              |
|------------------------|------|-------------------------------------------------------|
| `server.js`            | 3000 | **Secure** version — parameterized SQL, bcrypt, server-side validation, rate limiting |
| `vulnerable-server.js` | 3001 | **Intentionally vulnerable** version — string-concatenated SQL, used only to demonstrate the SQL injection in Part 3 |

Both share the same front end in `public/`.

## Why this design (Part 1 summary)

Studying Juice Shop surfaces three recurring vulnerability classes that a
registration/login system must defend against:

1. **SQL Injection** — Juice Shop's own login form is famously bypassable
   with `' OR 1=1--` because the query is built with string concatenation.
   **Mitigation:** parameterized queries / prepared statements (`?`
   placeholders), so user input is always treated as data, never as SQL
   syntax.
2. **Cross-Site Scripting (XSS)** — Juice Shop has stored and DOM-based XSS
   challenges where unsanitized input gets rendered as HTML. **Mitigation:**
   never use `innerHTML` with user- or server-supplied text (this app uses
   `textContent` everywhere), send a strict `Content-Security-Policy` header,
   and encode/escape any values that ever do need to render as HTML.
3. **Authentication bypass / weak credential handling** — Juice Shop stores
   some passwords with weak/broken hashing in older challenges.
   **Mitigation:** hash passwords with **bcrypt** (adaptive, salted,
   slow-by-design) before storage, compare with `bcrypt.compare`, never log
   or return plaintext passwords, return a generic "Invalid email or
   password" message for both wrong email and wrong password (prevents user
   enumeration), and rate-limit the login endpoint to slow brute forcing.

Example secure password handling used in `server.js`:

```js
const hash = await bcrypt.hash(plainTextPassword, 12); // store this, never the plaintext
const ok   = await bcrypt.compare(candidatePassword, hash); // on login
```

## Run it

```bash
npm install
npm start          # secure version   -> http://localhost:3000
npm run vulnerable # vulnerable demo  -> http://localhost:3001 (for Part 3 only)
```

Demo credentials seeded on the secure server:
`demo@juice-shop-assignment.test` / `CorrectHorse123`

## Part 2 — what was implemented

`public/index.html` + `public/script.js` implement the required front end:
an email field, a password field, and client-side validation that blocks
submission if either field is empty, the email doesn't contain `@`, or the
password is under 8 characters. Errors render inline next to each field.
On a valid submit, the form calls `POST /api/login` on the back end.

**How it was implemented:** the submit handler intercepts the form's
default submission, trims and checks the email/password strings against the
three rules above, toggles an `invalid` CSS class and per-field error text,
and only calls `fetch()` once all checks pass. The back end
(`server.js`) independently re-validates the same rules server-side (never
trusting the client), then looks the user up with a parameterized query and
verifies the password with `bcrypt.compare`.

## Part 3 — exploiting the vulnerable version

See `EXPLOIT_REPORT.md` for the full walkthrough, payloads, raw server
logs, and the fix verification.

## Project structure

```
.
├── server.js              # secure back end (port 3000)
├── vulnerable-server.js    # intentionally vulnerable back end (port 3001), Part 3 only
├── public/
│   ├── index.html          # login form
│   └── script.js           # client-side validation
├── EXPLOIT_REPORT.md       # Part 3 write-up with evidence
├── package.json
└── README.md
```
