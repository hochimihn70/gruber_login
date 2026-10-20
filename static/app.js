// ==========================================================================================
// Login & Auth Demo - Frontend
// Aufbau: 4 Views, die per display umgeschaltet werden (Mini-SPA ohne Framework)
// ==========================================================================================

// ------------------------------------------------------------------------------------------
// DOM-Elemente
// ------------------------------------------------------------------------------------------
const mainView = document.getElementById('main-view');
const registerView = document.getElementById('register-view');
const totpSetupView = document.getElementById('totp-setup-view');
const twoFactorView = document.getElementById('two-factor-view');
const forgotView = document.getElementById('forgot-view');

const loginForm = document.getElementById('login-form');
const registerForm = document.getElementById('register-form');
const twoFactorForm = document.getElementById('two-factor-form');
const twoFactorInfo = document.getElementById('two-factor-info');
const cancel2faBtn = document.getElementById('cancel-2fa-btn');

const btnShowRegister = document.getElementById('btn-show-register');
const cancelRegisterBtn = document.getElementById('cancel-register-btn');
const registerNextBtn = document.getElementById('register-next-btn');
const registerBackBtn = document.getElementById('register-back-btn');
const registerStep2 = document.getElementById('register-step-2');

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
const pageTitle = document.getElementById('page-title');

// Dev-Modus-Boxen (wird nur eingeblendet, wenn kein E-Mail-Server konfiguriert ist)
const devCodeBox = document.getElementById('dev-code-box');
const devCodeValue = document.getElementById('dev-code-value');
const devCodeBoxReset = document.getElementById('dev-code-box-reset');
const devCodeValueReset = document.getElementById('dev-code-value-reset');

// Temporäre Session-Daten für 2FA und Reset
let pendingEmail = '';
let resetEmail = '';


// ------------------------------------------------------------------------------------------
// Hilfsfunktionen
// ------------------------------------------------------------------------------------------

// Zeigt Statusmeldungen (Grün für OK, Rot für Fehler)
function showMessage(text, isError) {
  statusText.textContent = text;
  statusText.className = isError ? 'error' : 'ok';
}


// Titel der Seite, je nach View
const VIEW_TITLES = {
  'main': 'Login',
  'register': 'Konto erstellen',
  'totp-setup': 'Authenticator-App',
  'two-factor': 'Zwei-Faktor-Bestätigung',
  'forgot': 'Passwort zurücksetzen'
};


// Schaltet zwischen den Views um
function showView(viewName) {
  mainView.style.display = viewName === 'main' ? 'block' : 'none';
  registerView.style.display = viewName === 'register' ? 'block' : 'none';
  totpSetupView.style.display = viewName === 'totp-setup' ? 'block' : 'none';
  twoFactorView.style.display = viewName === 'two-factor' ? 'block' : 'none';
  forgotView.style.display = viewName === 'forgot' ? 'block' : 'none';
  if (pageTitle) pageTitle.textContent = VIEW_TITLES[viewName] || 'Login';
  showMessage('', false);
}


// Blendet den Code direkt im Browser ein (nur wenn kein E-Mail-Server konfiguriert ist).
// So bleibt der Login auch ohne SMTP im Dev-Modus bedienbar.
function showDevCode(code, isReset) {
  const box = isReset ? devCodeBoxReset : devCodeBox;
  const value = isReset ? devCodeValueReset : devCodeValue;
  if (!box || !value || !code) return;
  value.textContent = code;
  box.style.display = 'block';
}


// Blendet die Dev-Modus-Boxen wieder aus (z. B. wenn der Nutzer zurückgeht)
function hideDevCode() {
  if (devCodeBox) devCodeBox.style.display = 'none';
  if (devCodeBoxReset) devCodeBoxReset.style.display = 'none';
}


// ------------------------------------------------------------------------------------------
// Passwort-Hashing: passiert auf dem SERVER, nicht im Browser.
//
// Das ist der Industriestandard (Django, Rails, Laravel, Spring, Next.js):
//   1. Das Passwort geht verschlüsselt (HTTPS) zum Server.
//   2. Der Server hasht es mit Argon2id - inklusive zufälligem Salt pro User.
//
// Warum NICHT im Browser hashen? Ein Hash im Browser ist selbst wieder ein
// vollwertiges Passwort ("Pass-the-Hash"): Wer ihn abfängt, kann sich direkt
// anmelden. Und ein einzelnes SHA-256 ist zum Hashen von Passwörtern viel zu
// schnell. "SHA-256 im Browser + bcrypt auf dem Server" war deshalb sicherer,
// aber komplizierter als nötig - ohne echten Zusatznutzen.
// ------------------------------------------------------------------------------------------


// Hilfsfunktion für API-Anfragen
async function postJSON(url, payload) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const data = await response.json();
  data.ok = response.ok;
  data.httpStatus = response.status;      // HTTP-Code (401, 403, 500 ...) getrennt vom App-Status
  return data;
}


// ------------------------------------------------------------------------------------------
// 1. ANMELDEN (Login)
// ------------------------------------------------------------------------------------------
async function onLogin(event) {
  event.preventDefault();

  const email = loginForm.email.value.trim().toLowerCase();
  const password = loginForm.password.value;

  if (!email || !password) {
    showMessage('Bitte E-Mail und Passwort eingeben.', true);
    return;
  }

  try {
    // Das Passwort geht verschlüsselt (HTTPS) zum Server, der hasht es mit Argon2id.
    const result = await postJSON('/api/login', { email, password });

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
      hideDevCode();

      if (result.method === 'email_otp') {
        twoFactorInfo.textContent = `Ein 6-stelliger Bestätigungscode wurde an ${email} gesendet.`;
      } else if (result.method === 'totp') {
        twoFactorInfo.textContent = 'Gib den 6-stelligen Code aus deiner Authenticator-App (z. B. Google Authenticator) ein:';
      }

      // Dev-Modus: kein SMTP konfiguriert -> Code direkt anzeigen und ins Feld eintragen
      if (result.dev_code) {
        showDevCode(result.dev_code, false);
        twoFactorInfo.textContent = 'Dev-Modus: Es konnte keine E-Mail verschickt werden. Nutze den unten angezeigten Code.';
        twoFactorForm.code.value = result.dev_code;
      }

      twoFactorForm.code.focus();
      showMessage(result.message || '2FA-Bestätigung erforderlich.', false);
    }
  } catch (e) {
    showMessage('Der Server ist nicht erreichbar.', true);
  }
}


// ------------------------------------------------------------------------------------------
// 2. REGISTRIEREN (zwei Schritte)
//    Schritt 1: E-Mail + Passwort
//    Schritt 2: Sicherheitsstufe wählen (nur Passwort / E-Mail-2FA / TOTP)
// ------------------------------------------------------------------------------------------

// Setzt die Registrierung auf Schritt 1 zurück (leere Felder, 2FA-Auswahl unsichtbar)
function resetRegisterForm() {
  registerForm.reset();
  registerStep2.style.display = 'none';
  registerNextBtn.style.display = 'block';
}


// Prüft Schritt 1 und blendet die Auswahl der Sicherheitsstufe ein
function showRegisterStep2() {
  const email = registerForm.email.value.trim().toLowerCase();
  const password = registerForm.password.value;
  const password2 = registerForm.password_confirm.value;

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
  if (password !== password2) {
    showMessage('Die beiden Passwörter stimmen nicht überein.', true);
    return;
  }

  showMessage('', false);
  registerStep2.style.display = 'block';
  registerNextBtn.style.display = 'none';
  registerStep2.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}


async function onRegister(event) {
  event.preventDefault();

  // Schritt 1 -> Schritt 2 (Auswahl der Sicherheitsstufe)
  if (registerStep2.style.display === 'none') {
    showRegisterStep2();
    return;
  }

  // Schritt 2 -> Registrierung abschicken
  const email = registerForm.email.value.trim().toLowerCase();
  const password = registerForm.password.value;
  const authMethodInput = registerForm.querySelector('input[name="auth_method"]:checked');
  const auth_method = authMethodInput ? authMethodInput.value : 'password';

  try {
    const result = await postJSON('/api/register', { email, password, auth_method });

    if (!result.ok) {
      showMessage(result.error || 'Registrierung fehlgeschlagen.', true);
      // Konto existiert schon und das Passwort passt nicht -> Hinweis auf den Login geben
      if (result.httpStatus === 401) {
        showMessage(
          (result.error || '') + ' → Du findest die Anmeldung unten auf der Login-Seite.',
          true
        );
      }
      return;
    }

    // Direkt in den Ablauf weiterleiten (kein toter Klick!):
    if (result.status === 'success') {
      window.location.href = result.redirect || '/welcome';
    } else if (result.status === '2fa_required') {
      pendingEmail = email;
      resetRegisterForm();
      showView('two-factor');
      hideDevCode();
      twoFactorInfo.textContent = `Ein 6-stelliger Bestätigungscode wurde an ${email} gesendet.`;

      // Dev-Modus: kein SMTP konfiguriert -> Code direkt anzeigen und ins Feld eintragen
      if (result.dev_code) {
        showDevCode(result.dev_code, false);
        twoFactorInfo.textContent = 'Dev-Modus: Es konnte keine E-Mail verschickt werden. Nutze den unten angezeigten Code.';
        twoFactorForm.code.value = result.dev_code;
      }

      twoFactorForm.code.focus();
      showMessage(result.message || 'Code an deine E-Mail gesendet!', false);
    } else if (result.status === 'totp_setup') {
      resetRegisterForm();
      totpQrContainer.innerHTML = result.qr_svg;
      totpSecretKey.textContent = result.totp_secret;
      showView('totp-setup');
      showMessage('Registrierung erfolgreich! Bitte richte deine Authenticator-App ein.', false);
    } else {
      showMessage(result.message || 'Erfolgreich!', false);
      showView('main');
    }
  } catch (e) {
    showMessage('Der Server ist nicht erreichbar.', true);
  }
}


// ------------------------------------------------------------------------------------------
// 3. 2FA-CODE BESTÄTIGEN
// ------------------------------------------------------------------------------------------
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


// ------------------------------------------------------------------------------------------
// 4. PASSWORT VERGESSEN & ZURÜCKSETZEN
// ------------------------------------------------------------------------------------------
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
    hideDevCode();

    // Dev-Modus: kein SMTP konfiguriert -> Code direkt anzeigen und ins Feld eintragen
    if (result.dev_code) {
      showDevCode(result.dev_code, true);
      forgotResetForm.code.value = result.dev_code;
    }

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
    const result = await postJSON('/api/reset-password', {
      email: resetEmail,
      code,
      new_password: newPassword
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


// ------------------------------------------------------------------------------------------
// Event Listener
// ------------------------------------------------------------------------------------------
if (loginForm) loginForm.addEventListener('submit', onLogin);
if (registerForm) registerForm.addEventListener('submit', onRegister);
if (twoFactorForm) twoFactorForm.addEventListener('submit', onVerify2FA);
if (cancel2faBtn) cancel2faBtn.addEventListener('click', () => showView('main'));

// Registrierung: View wechseln und Schritte steuern
if (btnShowRegister) {
  btnShowRegister.addEventListener('click', () => {
    resetRegisterForm();
    showView('register');
    registerForm.email.focus();
  });
}
if (cancelRegisterBtn) cancelRegisterBtn.addEventListener('click', () => showView('main'));
if (registerNextBtn) registerNextBtn.addEventListener('click', showRegisterStep2);
if (registerBackBtn) {
  registerBackBtn.addEventListener('click', () => {
    registerStep2.style.display = 'none';
    registerNextBtn.style.display = 'block';
    showMessage('', false);
  });
}

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
