const authForms = document.getElementById('auth-forms');                                      // Bereich mit Anmelde- und Registrierungsformularen
const loginForm = document.getElementById('login');                                            // Das Login-Formular
const registerForm = document.getElementById('register');                                      // Das Registrieren-Formular
const twoFactorSection = document.getElementById('two-factor-section');                        // Bereich fuer 2FA-Code-Eingabe
const twoFactorForm = document.getElementById('two-factor-form');                              // Das 2FA-Formular
const twoFactorInfo = document.getElementById('two-factor-info');                              // Infotext fuer 2FA
const cancel2faBtn = document.getElementById('cancel-2fa');                                    // Zurueck-Button bei 2FA
const statusText = document.getElementById('status');                                          // Der Absatz fuer Rueckmeldungen

let pendingEmail = '';                                                                         // Merkt sich die E-Mail waehrend der 2FA-Eingabe


function showMessage(text, isError) {                                                          // Funktion: eine Meldung auf der Seite anzeigen
  statusText.textContent = text;
  if (isError) {
    statusText.className = 'error';
  } else {
    statusText.className = 'ok';
  }
}


function checkInput(email, password, isRegister) {                                             // Funktion: Eingaben pruefen
  if (email === '' || password === '') {
    return 'Bitte E-Mail und Passwort eingeben.';
  }
  if (email.includes('@') === false) {
    return 'Bitte eine gueltige E-Mail-Adresse eingeben.';
  }
  if (isRegister && password.length < 8) {
    return 'Das Passwort muss mindestens 8 Zeichen haben.';
  }
  return '';
}


async function sendToServer(url, payload) {                                                    // Sendet JSON-Daten an den Server
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const result = await response.json();
  result.ok = response.ok;
  return result;
}


async function onLogin(event) {                                                                // Schritt 1: Login mit E-Mail und Passwort
  event.preventDefault();

  const email = loginForm.email.value.trim().toLowerCase();
  const password = loginForm.password.value;

  const error = checkInput(email, password, false);
  if (error !== '') {
    showMessage(error, true);
    return;
  }

  try {
    const result = await sendToServer('/api/login', { email, password });
    if (result.ok && result.status === '2fa_required') {
      // 2FA ist erforderlich: Formulare umschalten
      pendingEmail = email;
      authForms.style.display = 'none';
      twoFactorSection.style.display = 'block';
      twoFactorInfo.textContent = `Wir haben einen 6-stelligen Bestätigungscode an ${email} gesendet.`;
      twoFactorForm.code.value = '';
      twoFactorForm.code.focus();
      showMessage(result.message || 'Code gesendet.', false);
    } else {
      showMessage(result.error || 'Login fehlgeschlagen.', true);
    }
  } catch (e) {
    showMessage('Der Server ist nicht erreichbar.', true);
  }
}


async function onVerify2FA(event) {                                                            // Schritt 2: 6-stelligen 2FA-Code pruefen
  event.preventDefault();

  const code = twoFactorForm.code.value.trim();
  if (code.length !== 6) {
    showMessage('Bitte gib den vollständigen 6-stelligen Code ein.', true);
    return;
  }

  try {
    const result = await sendToServer('/api/verify-2fa', { email: pendingEmail, code });
    if (result.ok) {
      window.location.href = result.redirect || '/welcome';
    } else {
      showMessage(result.error || 'Ungültiger Code.', true);
    }
  } catch (e) {
    showMessage('Der Server ist nicht erreichbar.', true);
  }
}


function onCancel2FA() {                                                                       // Bricht 2FA ab und kehrt zum normalen Login zurueck
  pendingEmail = '';
  twoFactorSection.style.display = 'none';
  authForms.style.display = 'block';
  showMessage('', false);
}


async function onRegister(event) {                                                             // Registrieren
  event.preventDefault();

  const email = registerForm.email.value.trim().toLowerCase();
  const password = registerForm.password.value;

  const error = checkInput(email, password, true);
  if (error !== '') {
    showMessage(error, true);
    return;
  }

  try {
    const result = await sendToServer('/api/register', { email, password });
    if (result.ok) {
      showMessage(result.message, false);
      registerForm.reset();
    } else {
      showMessage(result.error, true);
    }
  } catch (e) {
    showMessage('Der Server ist nicht erreichbar.', true);
  }
}


loginForm.addEventListener('submit', onLogin);
twoFactorForm.addEventListener('submit', onVerify2FA);
cancel2faBtn.addEventListener('click', onCancel2FA);
registerForm.addEventListener('submit', onRegister);
