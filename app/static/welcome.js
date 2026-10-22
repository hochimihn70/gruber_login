// ==========================================================================
// Gruber Login – geschützter Bereich
// Holt die Sitzungsdaten von /api/me und meldet auf Wunsch ab.
// ==========================================================================

(() => {
  'use strict';

  const METHOD_LABELS = {
    password: 'Passwort',
    email_otp: 'E-Mail-Code',
    totp: 'Authenticator-App',
  };

  const fields = {
    email: document.getElementById('user-email'),
    method: document.getElementById('user-method'),
    lastLogin: document.getElementById('user-last-login'),
    created: document.getElementById('user-created'),
  };

  const logoutButton = document.getElementById('logout-btn');

  function toLogin() {
    window.location.href = '/';
  }

  async function loadUser() {
    let response;
    try {
      response = await fetch('/api/me');
    } catch {
      toLogin();
      return;
    }

    if (!response.ok) {
      toLogin();
      return;
    }

    const user = await response.json();
    fields.email.textContent = user.email;
    fields.method.textContent = METHOD_LABELS[user.auth_method] || user.auth_method;
    fields.lastLogin.textContent = user.last_login_at;
    fields.created.textContent = user.created_at;
  }

  logoutButton.addEventListener('click', async () => {
    logoutButton.disabled = true;
    try {
      await fetch('/api/logout', { method: 'POST' });
    } finally {
      toLogin();
    }
  });

  loadUser();
})();
