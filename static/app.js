// DOM-Elemente
const mainView = document.getElementById('main-view');
const totpSetupView = document.getElementById('totp-setup-view');
const twoFactorView = document.getElementById('two-factor-view');
const forgotView = document.getElementById('forgot-view');

const loginForm = document.getElementById('login-form') || document.getElementById('login');
const registerForm = document.getElementById('register-form') || document.getElementById('register');
const twoFactorForm = document.getElementById('two-factor-form') || document.getElementById('two-factor');
const twoFactorInfo = document.getElementById('two-factor-info');
const cancel2faBtn = document.getElementById('cancel-2fa-btn') || document.getElementById('cancel-2fa');

const linkForgotPw = document.getElementById('link-forgot-pw');
const cancelForgotBtn = document.getElementById('cancel-forgot-btn');
const forgotStep1 = document.getElementById('forgot-step-1');
const forgotStep2 = document.getElementById('forgot-step-2');
const forgotRequestForm = document.getElementById('forgot-request-form');
const forgotResetForm = document.getElementById('forgot-reset-form');

const totpQrContainer = document.getElementById('totp-qr-container');
const totpSecretKey = document.getElementById('totp-secret-key');
const totpDoneBtn = document.getElementById('totp-done-btn');

const statusText = document.getElementById('status');

// Temporaere Session-Daten fuer 2FA und Reset
let pendingEmail = '';
let resetEmail = '';


// Zeigt Statusmeldungen (Gruen fuer OK, Rot fuer Fehler)
function showMessage(text, isError) {
  statusText.textContent = text;
  statusText.className = isError ? 'error' : 'ok';
}


// Schaltet zwischen den 4 Bildschirmen um
function showView(viewName) {
  mainView.style.display = viewName === 'main' ? 'block' : 'none';
  totpSetupView.style.display = viewName === 'totp-setup' ? 'block' : 'none';
  twoFactorView.style.display = viewName === 'two-factor' ? 'block' : 'none';
  forgotView.style.display = viewName === 'forgot' ? 'block' : 'none';
  showMessage('', false);
}


// Clientseitige Verschluesselung (SHA-256 via Web Crypto API)
// Das Klartextpasswort verlaesst NIEMALS den Browser!
async function hashPassword(plainPassword) {
  const encoder = new TextEncoder();
  const data = encoder.encode(plainPassword);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}


// Hilfsfunktion fuer API-Anfragen
async function postJSON(url, payload) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await response.json();
  data.ok = response.ok;
  return data;
}


// -------------------------------------------------------------
// 1. ANMELDEN (Login)
// -------------------------------------------------------------
async function onLogin(event) {
  event.preventDefault();

  const email = loginForm.email.value.trim().toLowerCase();
  const password = loginForm.password.value;

  if (!email || !password) {
    showMessage('Bitte E-Mail und Passwort eingeben.', true);
    return;
  }

  try {
    // Passwort im Browser hashen vor dem Senden:
    const password_hash = await hashPassword(password);
    const result = await postJSON('/api/login', { email, password_hash });

    if (!result.ok) {
      showMessage(result.error || 'Login fehlgeschlagen.', true);
      return;
    }

    // Fall 1: Nur Passwort (Erfolg)
    if (result.status === 'success') {
      window.location.href = result.redirect || '/welcome';
    }
    // Fall 2 & 3: 2FA-Code erforderlich (E-Mail oder Authenticator-App)
    else if (result.status === '2fa_required') {
      pendingEmail = email;
      showView('two-factor');

      if (result.method === 'email_otp') {
        twoFactorInfo.textContent = `Ein 6-stelliger Bestätigungscode wurde an ${email} gesendet.`;
      } else if (result.method === 'totp') {
        twoFactorInfo.textContent = 'Gib den 6-stelligen Code aus deiner Authenticator-App (z. B. Google Authenticator) ein:';
      }

      twoFactorForm.code.value = '';
      twoFactorForm.code.focus();
      showMessage(result.message || '2FA-Bestätigung erforderlich.', false);
    }
  } catch (e) {
    showMessage('Der Server ist nicht erreichbar.', true);
  }
}


// -------------------------------------------------------------
// 2. 2FA-CODE BESTAETIGEN
// -------------------------------------------------------------
async function onVerify2FA(event) {
  event.preventDefault();

  const code = twoFactorForm.code.value.trim();
  if (code.length !== 6) {
    showMessage('Bitte den 6-stelligen Code eingeben.', true);
    return;
  }

  try {
    const result = await postJSON('/api/verify-2fa', { email: pendingEmail, code });
    if (result.ok) {
      window.location.href = result.redirect || '/welcome';
    } else {
      showMessage(result.error || 'Ungültiger Bestätigungscode.', true);
    }
  } catch (e) {
    showMessage('Der Server ist nicht erreichbar.', true);
  }
}


// -------------------------------------------------------------
// 3. REGISTRIEREN
// -------------------------------------------------------------
async function onRegister(event) {
  event.preventDefault();

  const email = registerForm.email.value.trim().toLowerCase();
  const password = registerForm.password.value;
  const authMethodInput = registerForm.querySelector('input[name="auth_method"]:checked');
  const auth_method = authMethodInput ? authMethodInput.value : 'password';

  if (!email || !password) {
    showMessage('Bitte E-Mail und Passwort eingeben.', true);
    return;
  }
  if (!email.includes('@')) {
    showMessage('Bitte eine gültige E-Mail-Adresse eingeben.', true);
    return;
  }
  if (password.length < 8) {
    showMessage('Das Passwort muss mindestens 8 Zeichen haben.', true);
    return;
  }

  try {
    // Passwort im Browser hashen vor dem Senden:
    const password_hash = await hashPassword(password);
    const result = await postJSON('/api/register', { email, password_hash, auth_method });

    if (!result.ok) {
      showMessage(result.error || 'Registrierung fehlgeschlagen.', true);
      return;
    }

    registerForm.reset();

    // Bei TOTP: QR-Code anzeigen zum Scannen
    if (auth_method === 'totp' && result.qr_svg) {
      totpQrContainer.innerHTML = result.qr_svg;
      totpSecretKey.textContent = result.totp_secret;
      showView('totp-setup');
      showMessage('Registrierung erfolgreich! Bitte richte deine Authenticator-App ein.', false);
    } else {
      showMessage(result.message || 'Registrierung erfolgreich! Du kannst dich jetzt anmelden.', false);
      showView('main');
    }
  } catch (e) {
    showMessage('Der Server ist nicht erreichbar.', true);
  }
}


// -------------------------------------------------------------
// 4. PASSWORT VERGESSEN & ZURUECKSETZEN
// -------------------------------------------------------------
async function onRequestReset(event) {
  event.preventDefault();
  const email = forgotRequestForm.email.value.trim().toLowerCase();
  if (!email) {
    showMessage('Bitte E-Mail eingeben.', true);
    return;
  }

  try {
    const result = await postJSON('/api/forgot-password', { email });
    resetEmail = email;
    forgotStep1.style.display = 'none';
    forgotStep2.style.display = 'block';
    showMessage(result.message || 'Code gesendet.', false);
  } catch (e) {
    showMessage('Der Server ist nicht erreichbar.', true);
  }
}

async function onPerformReset(event) {
  event.preventDefault();
  const code = forgotResetForm.code.value.trim();
  const newPassword = forgotResetForm.new_password.value;

  if (!code || !newPassword) {
    showMessage('Bitte Code und neues Passwort eingeben.', true);
    return;
  }
  if (newPassword.length < 8) {
    showMessage('Das neue Passwort muss mindestens 8 Zeichen haben.', true);
    return;
  }

  try {
    const new_password_hash = await hashPassword(newPassword);
    const result = await postJSON('/api/reset-password', {
      email: resetEmail,
      code,
      new_password_hash
    });

    if (result.ok) {
      forgotResetForm.reset();
      forgotRequestForm.reset();
      forgotStep2.style.display = 'none';
      forgotStep1.style.display = 'block';
      showView('main');
      showMessage(result.message || 'Passwort geändert! Jetzt anmelden.', false);
    } else {
      showMessage(result.error || 'Fehler beim Zurücksetzen.', true);
    }
  } catch (e) {
    showMessage('Der Server ist nicht erreichbar.', true);
  }
}


// Event Listener
if (loginForm) loginForm.addEventListener('submit', onLogin);
if (registerForm) registerForm.addEventListener('submit', onRegister);
if (twoFactorForm) twoFactorForm.addEventListener('submit', onVerify2FA);
if (cancel2faBtn) cancel2faBtn.addEventListener('click', () => showView('main'));

if (totpDoneBtn) totpDoneBtn.addEventListener('click', () => showView('main'));

if (linkForgotPw) {
  linkForgotPw.addEventListener('click', (e) => {
    e.preventDefault();
    if (forgotStep1) forgotStep1.style.display = 'block';
    if (forgotStep2) forgotStep2.style.display = 'none';
    showView('forgot');
  });
}
if (cancelForgotBtn) cancelForgotBtn.addEventListener('click', () => showView('main'));

if (forgotRequestForm) forgotRequestForm.addEventListener('submit', onRequestReset);
if (forgotResetForm) forgotResetForm.addEventListener('submit', onPerformReset);
