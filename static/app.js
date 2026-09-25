const loginForm = document.getElementById('login');
const registerForm = document.getElementById('register');
const statusText = document.getElementById('status');


function showMessage(text, isError) {
  statusText.textContent = text;
  if (isError) {
    statusText.className = 'error';
  } else {
    statusText.className = 'ok';
  }
}


// Prueft die Eingaben. Gibt eine Fehlermeldung zurueck oder '' wenn alles passt.
function checkInput(email, password, isRegister) {
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


// Schickt E-Mail und Passwort als JSON an den Server und gibt die Antwort zurueck.
async function sendToServer(url, email, password) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: email, password: password })
  });
  const result = await response.json();
  result.ok = response.ok;
  return result;
}


async function onLogin(event) {
  event.preventDefault();  // Seite nicht neu laden

  const email = loginForm.email.value;
  const password = loginForm.password.value;

  const error = checkInput(email, password, false);
  if (error !== '') {
    showMessage(error, true);
    return;
  }

  try {
    const result = await sendToServer('/api/login', email, password);
    if (result.ok) {
      window.location.href = '/welcome';
    } else {
      showMessage(result.error, true);
    }
  } catch (e) {
    showMessage('Der Server ist nicht erreichbar.', true);
  }
}


async function onRegister(event) {
  event.preventDefault();  // Seite nicht neu laden

  const email = registerForm.email.value;
  const password = registerForm.password.value;

  const error = checkInput(email, password, true);
  if (error !== '') {
    showMessage(error, true);
    return;
  }

  try {
    const result = await sendToServer('/api/register', email, password);
    if (result.ok) {
      showMessage(result.message, false);
    } else {
      showMessage(result.error, true);
    }
  } catch (e) {
    showMessage('Der Server ist nicht erreichbar.', true);
  }
}


loginForm.addEventListener('submit', onLogin);
registerForm.addEventListener('submit', onRegister);
