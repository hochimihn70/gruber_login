const statusElement = document.querySelector('#status'); // Element fuer Meldungen holen.

function showStatus(message, type) { // Meldung anzeigen.
  statusElement.textContent = message; // Text setzen.
  statusElement.className = type; // CSS-Klasse fuer Erfolg oder Fehler setzen.
}

async function handleFormSubmit(event) { // Login oder Registrierung bearbeiten.
  event.preventDefault(); // Seitenneuladen verhindern.

  const form = event.target; // Abgesendetes Formular holen.
  const formData = new FormData(form); // Formularwerte sammeln.
  const emailAddress = formData.get('email'); // E-Mail lesen.
  const password = formData.get('password'); // Passwort lesen.

  if (!emailAddress || !password) { // Leere Eingaben pruefen.
    showStatus('Bitte E-Mail und Passwort eingeben.', 'error'); // Fehler anzeigen.
    return; // Funktion beenden.
  }
  if (!emailAddress.includes('@')) { // Einfache E-Mail-Pruefung.
    showStatus('Bitte eine gueltige E-Mail-Adresse eingeben.', 'error'); // Fehler anzeigen.
    return; // Funktion beenden.
  }
  if (form.id === 'register' && password.length < 8) { // Passwortlaenge bei Registrierung pruefen.
    showStatus('Das Passwort muss mindestens 8 Zeichen haben.', 'error'); // Fehler anzeigen.
    return; // Funktion beenden.
  }

  let apiUrl = '/api/login'; // Standardmaessig Login verwenden.
  if (form.id === 'register') { // Registrierungsformular erkennen.
    apiUrl = '/api/register'; // Registrierungsadresse verwenden.
  }

  const requestData = { // Daten fuer FastAPI vorbereiten.
    email: emailAddress, // E-Mail eintragen.
    password: password // Passwort eintragen.
  };

  try { // Netzwerkfehler abfangen.
    const response = await fetch(apiUrl, { // Anfrage an FastAPI senden.
      method: 'POST', // POST-Anfrage verwenden.
      headers: { 'Content-Type': 'application/json' }, // JSON ankündigen.
      body: JSON.stringify(requestData) // Daten in JSON umwandeln.
    });

    const result = await response.json(); // Serverantwort lesen.
    let message = result.error; // Fehlermeldung vorbereiten.
    if (response.ok) { // Erfolgreiche Antwort pruefen.
      message = result.message; // Erfolgsmeldung verwenden.
    }
    if (!message) { // Fehlende Meldung pruefen.
      message = 'Unbekannter Fehler.'; // Ersatzmeldung setzen.
    }

    if (response.ok) { // Erfolg erkennen.
      showStatus(message, 'ok'); // Erfolg anzeigen.
    } else {
      showStatus(message, 'error'); // Fehler anzeigen.
    }

    if (response.ok && form.id === 'login') { // Erfolgreichen Login erkennen.
      window.location.href = '/welcome'; // Zur Willkommensseite wechseln.
    }
  } catch (error) { // Serverfehler auffangen.
    showStatus('Der Server ist nicht erreichbar.', 'error'); // Serverfehler anzeigen.
  }
}

const forms = document.querySelectorAll('form'); // Alle Formulare holen.
for (const form of forms) { // Jedes Formular durchlaufen.
  form.addEventListener('submit', handleFormSubmit); // Submit-Funktion verbinden.
}
