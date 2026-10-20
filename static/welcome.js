// Willkommensseite: Benutzerdaten laden und Abmelden
// Eigenes File statt Inline-Script, damit die Content-Security-Policy
// ("script-src 'self'") erlauben kann - ohne 'unsafe-inline'.

async function loadUserData() {
  try {
    const response = await fetch('/api/me');
    if (!response.ok) {
      window.location.href = '/';
      return;
    }
    const data = await response.json();
    document.getElementById('user-email').textContent = data.email;

    let methodText = '1. Nur Passwort';
    if (data.auth_method === 'email_otp') methodText = '2. Passwort + E-Mail-Code (2FA)';
    if (data.auth_method === 'totp') methodText = '3. Passwort + Authenticator-App (TOTP)';
    document.getElementById('user-method').textContent = methodText;

    document.getElementById('user-last-login').textContent = data.last_login_at;
    document.getElementById('user-created').textContent = data.created_at;
  } catch (e) {
    window.location.href = '/';
  }
}

document.getElementById('logout-btn').addEventListener('click', async () => {
  try {
    await fetch('/api/logout', { method: 'POST' });
  } finally {
    window.location.href = '/';
  }
});

loadUserData();
