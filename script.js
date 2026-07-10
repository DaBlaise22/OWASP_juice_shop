// script.js — client-side validation for the login form.
// NOTE: Client-side checks are a UX convenience only. They are trivial to
// bypass (disable JS, use curl/Postman), so the server re-validates and
// re-sanitizes everything independently (see server.js).

document.getElementById('loginForm').addEventListener('submit', function (e) {
  e.preventDefault();

  const emailInput = document.getElementById('email');
  const passwordInput = document.getElementById('password');
  const emailError = document.getElementById('emailError');
  const passwordError = document.getElementById('passwordError');
  const formMsg = document.getElementById('formMsg');

  // Reset previous error state
  emailError.textContent = '';
  passwordError.textContent = '';
  formMsg.textContent = '';
  emailInput.classList.remove('invalid');
  passwordInput.classList.remove('invalid');

  const email = emailInput.value.trim();
  const password = passwordInput.value;
  let valid = true;

  // Rule 1: fields must not be empty
  if (email === '') {
    emailError.textContent = 'Email is required.';
    emailInput.classList.add('invalid');
    valid = false;
  } else if (!email.includes('@')) {
    // Rule 2: very basic shape check — must contain "@"
    emailError.textContent = 'Please enter a valid email address (must contain "@").';
    emailInput.classList.add('invalid');
    valid = false;
  }

  if (password === '') {
    passwordError.textContent = 'Password is required.';
    passwordInput.classList.add('invalid');
    valid = false;
  } else if (password.length < 8) {
    // Rule 3: minimum password length
    passwordError.textContent = 'Password must be at least 8 characters long.';
    passwordInput.classList.add('invalid');
    valid = false;
  }

  if (!valid) return;

  submitLogin(email, password, formMsg);
});

async function submitLogin(email, password, formMsg) {
  formMsg.textContent = 'Logging in...';
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password })
    });
    const data = await res.json();

    // IMPORTANT: use textContent, never innerHTML, when rendering
    // anything that came from user input or the server. This is what
    // prevents DOM-based XSS on this page.
    formMsg.textContent = data.message || (res.ok ? 'Success' : 'Login failed');
  } catch (err) {
    formMsg.textContent = 'Network error — please try again.';
  }
}
