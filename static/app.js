import crypto from './crypto.js';

const guestView = document.querySelector('#guest-view');
const sessionView = document.querySelector('#session-view');
const createPanel = document.querySelector('#create-panel');
const signinPanel = document.querySelector('#signin-panel');
const createForm = document.querySelector('#create-form');
const usernameInput = document.querySelector('#username');
const loginBtn = document.querySelector('#login-btn');
const logoutBtn = document.querySelector('#logout-btn');
const modeButtons = [...document.querySelectorAll('.mode-btn')];
const sessionName = document.querySelector('#session-name');
const sessionAvatar = document.querySelector('#session-avatar');
const statusEl = document.querySelector('#status');

let currentMode = 'create';
let busy = false;

const api = async (path, body) => {
  const hasBody = body !== undefined;
  const method = hasBody ? 'POST' : 'GET';
  const headers = hasBody ? { 'Content-Type': 'application/json' } : {};
  const payload = hasBody ? JSON.stringify(body) : undefined;
  const options = {
    method,
    credentials: 'same-origin',
    headers,
    body: payload,
  };
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'Request failed');
  return data;
};

const setStatus = (message, tone = 'idle') => {
  statusEl.value = message;
  statusEl.dataset.tone = tone;
  statusEl.style.animation = 'none';
  statusEl.offsetHeight;
  statusEl.style.animation = '';
};

const interactiveControls = () => [
  ...modeButtons,
  createForm.querySelector('button'),
  usernameInput,
  loginBtn,
  logoutBtn,
];

const setBusy = (nextBusy) => {
  busy = nextBusy;
  guestView.dataset.busy = String(nextBusy);
  sessionView.dataset.busy = String(nextBusy);
  for (const control of interactiveControls()) {
    if (!control || control.hidden) continue;
    control.disabled = nextBusy;
  }
};

const setMode = (mode, { focus = true } = {}) => {
  currentMode = mode;
  const createSelected = mode === 'create';

  for (const button of modeButtons) {
    const selected = button.dataset.mode === mode;
    button.setAttribute('aria-selected', String(selected));
    button.tabIndex = selected ? 0 : -1;
  }

  createPanel.hidden = !createSelected;
  signinPanel.hidden = createSelected;

  if (focus && createSelected && !busy) {
    usernameInput.focus();
  }
};

const showSession = (user) => {
  const signedIn = Boolean(user);
  guestView.hidden = signedIn;
  sessionView.hidden = !signedIn;

  if (user) {
    sessionName.textContent = user.username;
    sessionAvatar.textContent = user.username.slice(0, 1).toUpperCase();
    setStatus(`Welcome back, ${user.username}`, 'ok');
  } else {
    sessionName.textContent = '';
    sessionAvatar.textContent = '?';
    setMode(currentMode, { focus: false });
  }
};

const createAccount = async (event) => {
  event.preventDefault();
  const username = new FormData(createForm).get('username')?.trim();
  if (!username) {
    setStatus('Enter a username to register.', 'error');
    usernameInput.focus();
    return;
  }

  setBusy(true);
  try {
    setStatus('Creating key pair…', 'pending');
    const options = await api('/api/register/options', { username });
    const id = crypto.randomId();
    const keys = await crypto.generateKeys();
    const payload = {
      type: 'registration',
      origin: location.origin,
      challenge: options.challenge,
      credentialId: id,
    };
    const { clientData, signature } = await crypto.signPayload(
      keys.privateKey,
      payload,
    );
    await crypto.saveLocalCredential(id, keys.privateKey);
    const result = await api('/api/register/verify', {
      id,
      publicKey: keys.publicKey,
      clientData,
      signature,
    });
    createForm.reset();
    showSession(result.user);
    setStatus(`Registered — signed in as ${result.user.username}`, 'ok');
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    setBusy(false);
  }
};

const login = async () => {
  setBusy(true);
  try {
    setStatus('Signing challenge…', 'pending');
    const local = await crypto.loadLocalCredential();
    if (!local) {
      throw new Error('No local key found. Create an account first.');
    }
    const { id, privateKey } = local;
    const options = await api('/api/login/options', {});
    const payload = {
      type: 'authentication',
      origin: location.origin,
      challenge: options.challenge,
      credentialId: id,
    };
    const { clientData, signature } = await crypto.signPayload(
      privateKey,
      payload,
    );
    const result = await api('/api/login/verify', {
      id,
      clientData,
      signature,
    });
    showSession(result.user);
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    setBusy(false);
  }
};

const logout = async () => {
  setBusy(true);
  try {
    await api('/api/logout', {});
    showSession(null);
    setStatus('Signed out', 'idle');
  } catch (error) {
    setStatus(error.message, 'error');
  } finally {
    setBusy(false);
  }
};

const restoreSession = async () => {
  if (!globalThis.crypto?.subtle || !navigator.storage?.getDirectory) {
    setStatus('This browser does not support Web Crypto or OPFS.', 'error');
    guestView.hidden = true;
    sessionView.hidden = true;
    return;
  }
  try {
    const result = await api('/api/session');
    showSession(result.user);
  } catch {
    showSession(null);
    setStatus('Ready', 'idle');
  }
};

const onModeKeydown = (event) => {
  const keys = ['ArrowLeft', 'ArrowRight', 'Home', 'End'];
  if (!keys.includes(event.key)) return;

  event.preventDefault();
  const index = modeButtons.indexOf(event.currentTarget);
  let next = index;
  if (event.key === 'ArrowRight') next = (index + 1) % modeButtons.length;
  if (event.key === 'ArrowLeft') {
    next = (index - 1 + modeButtons.length) % modeButtons.length;
  }
  if (event.key === 'Home') next = 0;
  if (event.key === 'End') next = modeButtons.length - 1;

  const mode = modeButtons[next].dataset.mode;
  setMode(mode);
  modeButtons[next].focus();
};

const onModeClick = (event) => {
  if (busy) return;
  setMode(event.currentTarget.dataset.mode);
};

for (const button of modeButtons) {
  button.addEventListener('click', onModeClick);
  button.addEventListener('keydown', onModeKeydown);
}

createForm.addEventListener('submit', createAccount);
loginBtn.addEventListener('click', login);
logoutBtn.addEventListener('click', logout);
setMode('create', { focus: false });
restoreSession();
