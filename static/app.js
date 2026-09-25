const loginForm = document.getElementById('login');                                            // Das Login-Formular aus der HTML-Seite holen
const registerForm = document.getElementById('register');                                      // Das Registrieren-Formular holen
const statusText = document.getElementById('status');                                          // Der Absatz, in dem Meldungen angezeigt werden


function showMessage(text, isError) {                                                          // Funktion: eine Meldung auf der Seite anzeigen
  statusText.textContent = text;                                                               // Den Text in den Absatz schreiben
  if (isError) {                                                                               // Wenn es ein Fehler ist
    statusText.className = 'error';                                                            // CSS-Klasse "error" setzen (rote Schrift)
  } else {                                                                                     // Sonst ist es eine Erfolgsmeldung
    statusText.className = 'ok';                                                               // CSS-Klasse "ok" setzen (gruene Schrift)
  }                                                                                            // Ende von if/else
}                                                                                              // Ende der Funktion


function checkInput(email, password, isRegister) {                                             // Funktion: Eingaben pruefen, gibt Fehlertext oder '' zurueck
  if (email === '' || password === '') {                                                       // Wenn E-Mail oder Passwort leer ist
    return 'Bitte E-Mail und Passwort eingeben.';                                              // Fehlertext zurueckgeben
  }                                                                                            // Ende von if
  if (email.includes('@') === false) {                                                         // Wenn die E-Mail kein @ enthaelt
    return 'Bitte eine gueltige E-Mail-Adresse eingeben.';                                     // Fehlertext zurueckgeben
  }                                                                                            // Ende von if
  if (isRegister && password.length < 8) {                                                     // Nur beim Registrieren: Passwort kuerzer als 8 Zeichen?
    return 'Das Passwort muss mindestens 8 Zeichen haben.';                                    // Fehlertext zurueckgeben
  }                                                                                            // Ende von if
  return '';                                                                                   // Alles in Ordnung, leerer Text heisst kein Fehler
}                                                                                              // Ende der Funktion


async function sendToServer(url, email, password) {                                            // Funktion: Daten an den Server schicken, async weil sie auf das Netzwerk wartet
  const response = await fetch(url, {                                                          // Anfrage an FastAPI schicken und auf die Antwort warten
    method: 'POST',                                                                            // POST-Anfrage, passt zu @app.post in app.py
    headers: { 'Content-Type': 'application/json' },                                           // Dem Server sagen, dass JSON kommt
    body: JSON.stringify({ email: email, password: password })                                 // E-Mail und Passwort in JSON-Text umwandeln
  });                                                                                          // Ende der fetch-Einstellungen
  const result = await response.json();                                                        // Die JSON-Antwort vom Server lesen
  result.ok = response.ok;                                                                     // Merken, ob der Statuscode Erfolg war (200-299)
  return result;                                                                               // Antwort an den Aufrufer zurueckgeben
}                                                                                              // Ende der Funktion


async function onLogin(event) {                                                                // Wird ausgefuehrt, wenn das Login-Formular abgeschickt wird
  event.preventDefault();                                                                      // Seite nicht neu laden

  const email = loginForm.email.value;                                                         // Eingegebene E-Mail lesen
  const password = loginForm.password.value;                                                   // Eingegebenes Passwort lesen

  const error = checkInput(email, password, false);                                            // Eingaben pruefen, false = kein Registrieren
  if (error !== '') {                                                                          // Wenn es einen Fehler gibt
    showMessage(error, true);                                                                  // Fehler anzeigen
    return;                                                                                    // Funktion hier beenden, nichts an den Server schicken
  }                                                                                            // Ende von if

  try {                                                                                        // Versuchen, Fehler wie "Server aus" werden unten abgefangen
    const result = await sendToServer('/api/login', email, password);                          // Daten an /api/login schicken
    if (result.ok) {                                                                           // Wenn der Login geklappt hat
      window.location.href = '/welcome';                                                       // Zur Willkommensseite wechseln
    } else {                                                                                   // Sonst hat der Server abgelehnt
      showMessage(result.error, true);                                                         // Fehlermeldung vom Server anzeigen
    }                                                                                          // Ende von if/else
  } catch (e) {                                                                                // Wenn die Anfrage gar nicht geklappt hat
    showMessage('Der Server ist nicht erreichbar.', true);                                     // Fehler anzeigen
  }                                                                                            // Ende von try/catch
}                                                                                              // Ende der Funktion


async function onRegister(event) {                                                             // Wird ausgefuehrt, wenn das Registrieren-Formular abgeschickt wird
  event.preventDefault();                                                                      // Seite nicht neu laden

  const email = registerForm.email.value;                                                      // Eingegebene E-Mail lesen
  const password = registerForm.password.value;                                                // Eingegebenes Passwort lesen

  const error = checkInput(email, password, true);                                             // Eingaben pruefen, true = Registrieren (mind. 8 Zeichen)
  if (error !== '') {                                                                          // Wenn es einen Fehler gibt
    showMessage(error, true);                                                                  // Fehler anzeigen
    return;                                                                                    // Funktion hier beenden, nichts an den Server schicken
  }                                                                                            // Ende von if

  try {                                                                                        // Versuchen, Fehler wie "Server aus" werden unten abgefangen
    const result = await sendToServer('/api/register', email, password);                       // Daten an /api/register schicken
    if (result.ok) {                                                                           // Wenn die Registrierung geklappt hat
      showMessage(result.message, false);                                                      // Erfolgsmeldung vom Server anzeigen
    } else {                                                                                   // Sonst hat der Server abgelehnt
      showMessage(result.error, true);                                                         // Fehlermeldung vom Server anzeigen
    }                                                                                          // Ende von if/else
  } catch (e) {                                                                                // Wenn die Anfrage gar nicht geklappt hat
    showMessage('Der Server ist nicht erreichbar.', true);                                     // Fehler anzeigen
  }                                                                                            // Ende von try/catch
}                                                                                              // Ende der Funktion


loginForm.addEventListener('submit', onLogin);                                                 // Beim Absenden des Login-Formulars onLogin ausfuehren
registerForm.addEventListener('submit', onRegister);                                           // Beim Absenden des Registrieren-Formulars onRegister ausfuehren
