// ==========================================================================
// Gruber Login – Landingpage
// Ein Formular-Bereich, mehrere Ansichten. Kein Framework, kein Inline-JS
// (die CSP erlaubt nur Scripts von der eigenen Domain).
// ==========================================================================

(() => {
  'use strict';

  const EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;

  const TITLES = {
    login: 'Anmelden',
    register: 'Konto erstellen',
    twofactor: 'Code bestätigen',
    totp: 'Authenticator einrichten',
    forgot: 'Passwort zurücksetzen',
  };

  // ------------------------------------------------------------------
  // Elemente
  // ------------------------------------------------------------------
  const views = new Map(
    [...document.querySelectorAll('[data-view]')].map((view) => [view.dataset.view, view])
  );

  const alertBox = document.getElementById('alert');

  const loginForm = document.getElementById('login-form');
  const loginEmail = document.getElementById('login-email');
  const loginPassword = document.getElementById('login-password');

  const registerForm = document.getElementById('register-form');
  const registerEmail = document.getElementById('register-email');
  const registerPassword = document.getElementById('register-password');
  const registerPassword2 = document.getElementById('register-password2');

  const twoFactorForm = document.getElementById('twofactor-form');
  const twoFactorInfo = document.getElementById('twofactor-info');
  const twoFactorCode = document.getElementById('twofactor-code');
  const twoFactorDev = document.getElementById('twofactor-dev');
  const twoFactorDevCode = document.getElementById('twofactor-dev-code');

  const totpForm = document.getElementById('totp-form');
  const totpCode = document.getElementById('totp-code');
  const totpQr = document.getElementById('totp-qr');
  const totpSecret = document.getElementById('totp-secret');

  const forgotForm = document.getElementById('forgot-form');
  const forgotEmail = document.getElementById('forgot-email');
  const forgotStepRequest = document.getElementById('forgot-step-request');
  const forgotStepReset = document.getElementById('forgot-step-reset');
  const resetForm = document.getElementById('reset-form');
  const resetCode = document.getElementById('reset-code');
  const resetPassword = document.getElementById('reset-password');
  const resetDev = document.getElementById('reset-dev');
  const resetDevCode = document.getElementById('reset-dev-code');

  // Zustand, der zwischen zwei Ansichten gebraucht wird
  let pendingEmail = '';
  let resetEmail = '';

  // ------------------------------------------------------------------
  // Hilfsfunktionen
  // ------------------------------------------------------------------

  /** Fehler mit einer Meldung, die direkt angezeigt werden darf. */
  class FormError extends Error {}

  function say(message, tone = 'info') {
    alertBox.textContent = message;
    alertBox.className = `alert is-${tone}`;
    alertBox.hidden = !message;
    if (message) alertBox.scrollIntoView({ block: 'nearest' });
  }

  function clearAlert() {
    alertBox.textContent = '';
    alertBox.hidden = true;
  }

  function showView(name, focus = true) {
    views.forEach((view, key) => {
      view.hidden = key !== name;
    });
    document.title = `${TITLES[name] || 'Login'} · Gruber Login`;
    clearAlert();

    if (focus) {
      const input = views.get(name)?.querySelector('input');
      input?.focus();
    }
  }

  /**
   * POST als JSON. Liefert die Antwortdaten oder wirft `FormError`
   * mit der Meldung des Servers.
   */
  async function request(path, body) {
    let response;
    try {
      response = await fetch(path, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
    } catch {
      throw new FormError('Der Server ist nicht erreichbar. Bitte später erneut versuchen.');
    }

    let data = {};
    try {
      data = await response.json();
    } catch {
      // z. B. 500 mit HTML-Fehlerseite -> keine JSON-Antwort
    }

    if (!response.ok) {
      throw new FormError(data.error || `Anfrage fehlgeschlagen (HTTP ${response.status}).`);
    }
    return data;
  }

  /** Einheitlicher Submit: sperrt den Button und zeigt Fehler an. */
  function onSubmit(form, handler) {
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      clearAlert();

      const button = form.querySelector('button[type="submit"]');
      button.disabled = true;
      try {
        await handler();
      } catch (error) {
        const message = error instanceof FormError
          ? error.message
          : 'Unerwarteter Fehler. Bitte erneut versuchen.';
        say(message, 'error');
      } finally {
        button.disabled = false;
      }
    });
  }

  function requireEmail(value) {
    if (!value) throw new FormError('Bitte eine E-Mail-Adresse eingeben.');
    if (!EMAIL_PATTERN.test(value)) throw new FormError('Bitte eine gültige E-Mail-Adresse eingeben.');
    return value;
  }

  function requireCode(input) {
    const code = input.value.trim();
    if (!/^\d{6}$/.test(code)) throw new FormError('Bitte den 6-stelligen Code eingeben.');
    return code;
  }

  function goTo(path) {
    window.location.href = path || '/welcome';
  }

  // ------------------------------------------------------------------
  // Ansichten mit dynamischem Inhalt
  // ------------------------------------------------------------------

  function openTwoFactor(data, email) {
    pendingEmail = email;
    twoFactorCode.value = '';
    twoFactorDev.hidden = !data.dev_code;

    if (data.method === 'totp') {
      twoFactorInfo.textContent =
        'Gib den 6-stelligen Code aus deiner Authenticator-App ein.';
    } else {
      twoFactorInfo.textContent = `Ein 6-stelliger Code wurde an ${email} gesendet.`;
    }

    if (data.dev_code) {
      twoFactorDevCode.textContent = data.dev_code;
      twoFactorCode.value = data.dev_code;
      twoFactorInfo.textContent =
        'Dev-Modus: Es wurde keine E-Mail verschickt. Nutze den angezeigten Code.';
    }

    showView('twofactor');
  }

  function openTotpSetup(data, email) {
    pendingEmail = email;
    totpQr.innerHTML = data.qr_svg || '';
    totpSecret.textContent = data.totp_secret || '';
    totpCode.value = '';
    showView('totp');
    say('Konto angelegt. Scanne den QR-Code und bestätige mit dem Code aus der App.', 'success');
  }

  function openForgotStepRequest() {
    forgotStepReset.hidden = true;
    forgotStepRequest.hidden = false;
    showView('forgot');
  }

  // ------------------------------------------------------------------
  // Anmelden
  // ------------------------------------------------------------------

  onSubmit(loginForm, async () => {
    const email = requireEmail(loginEmail.value.trim().toLowerCase());
    if (!loginPassword.value) throw new FormError('Bitte das Passwort eingeben.');

    const data = await request('/api/login', { email, password: loginPassword.value });

    if (data.status === 'success') {
      goTo(data.redirect);
      return;
    }
    openTwoFactor(data, email);
  });

  // ------------------------------------------------------------------
  // Registrieren
  // ------------------------------------------------------------------

  onSubmit(registerForm, async () => {
    const email = requireEmail(registerEmail.value.trim().toLowerCase());
    const password = registerPassword.value;

    if (password.length < 8) {
      throw new FormError('Das Passwort muss mindestens 8 Zeichen haben.');
    }
    if (password !== registerPassword2.value) {
      throw new FormError('Die beiden Passwörter stimmen nicht überein.');
    }

    const selected = registerForm.querySelector('input[name="auth_method"]:checked');
    const authMethod = selected ? selected.value : 'password';

    const data = await request('/api/register', { email, password, auth_method: authMethod });

    if (data.status === 'totp_setup') {
      openTotpSetup(data, email);
    } else if (data.status === '2fa_required') {
      openTwoFactor(data, email);
    } else {
      goTo(data.redirect);
    }
  });

  // ------------------------------------------------------------------
  // Zwei-Faktor-Code (E-Mail oder Authenticator)
  // ------------------------------------------------------------------

  onSubmit(twoFactorForm, async () => {
    const code = requireCode(twoFactorCode);
    const data = await request('/api/verify-2fa', { email: pendingEmail, code });
    goTo(data.redirect);
  });

  // ------------------------------------------------------------------
  // Authenticator einrichten: erster Code bestätigt und meldet direkt an
  // ------------------------------------------------------------------

  onSubmit(totpForm, async () => {
    const code = requireCode(totpCode);
    const data = await request('/api/verify-2fa', { email: pendingEmail, code });
    goTo(data.redirect);
  });

  // ------------------------------------------------------------------
  // Passwort vergessen
  // ------------------------------------------------------------------

  onSubmit(forgotForm, async () => {
    const email = requireEmail(forgotEmail.value.trim().toLowerCase());
    const data = await request('/api/forgot-password', { email });

    resetEmail = email;
    resetDev.hidden = !data.dev_code;

    if (data.dev_code) {
      resetDevCode.textContent = data.dev_code;
      resetCode.value = data.dev_code;
    }

    forgotStepRequest.hidden = true;
    forgotStepReset.hidden = false;
    resetPassword.value = '';
    say(data.message || 'Code gesendet.', data.dev_code ? 'info' : 'success');
    (data.dev_code ? resetPassword : resetCode).focus();
  });

  onSubmit(resetForm, async () => {
    const code = requireCode(resetCode);
    const password = resetPassword.value;

    if (password.length < 8) {
      throw new FormError('Das neue Passwort muss mindestens 8 Zeichen haben.');
    }

    const data = await request('/api/reset-password', {
      email: resetEmail,
      code,
      new_password: password,
    });

    resetForm.reset();
    forgotForm.reset();
    forgotStepReset.hidden = true;
    forgotStepRequest.hidden = false;
    showView('login');
    say(data.message || 'Passwort geändert. Du kannst dich jetzt anmelden.', 'success');
  });

  // ------------------------------------------------------------------
  // Navigation zwischen den Ansichten
  // ------------------------------------------------------------------

  const actions = {
    'show-login': () => showView('login'),
    'show-register': () => {
      registerForm.reset();
      showView('register');
    },
    'show-forgot': openForgotStepRequest,
    'forgot-restart': openForgotStepRequest,
  };

  document.addEventListener('click', (event) => {
    const trigger = event.target.closest('[data-action]');
    if (!trigger) return;
    event.preventDefault();
    actions[trigger.dataset.action]?.();
  });

  // Startzustand: Login-Ansicht ohne Autofokus (verhindert Scrollen auf Mobil)
  showView('login', false);
})();
