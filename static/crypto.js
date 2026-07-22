const ECDSA = { name: 'ECDSA', namedCurve: 'P-256' };
const ECDSA_SIGN = { name: 'ECDSA', hash: 'SHA-256' };
const KEY_FILE = 'private.pkcs8';
const ID_FILE = 'credential-id';

const toBase64url = (value) => {
  const bytes = new Uint8Array(value);
  return bytes.toBase64({ alphabet: 'base64url', omitPadding: true });
};

const fromBase64url = (value) => {
  const options = { alphabet: 'base64url' };
  return Uint8Array.fromBase64(value, options);
};

const keysDir = async () => {
  const root = await navigator.storage.getDirectory();
  return root.getDirectoryHandle('keys', { create: true });
};

const writeText = async (dir, name, text) => {
  const handle = await dir.getFileHandle(name, { create: true });
  const writable = await handle.createWritable();
  await writable.write(text);
  await writable.close();
};

const readText = async (dir, name) => {
  const handle = await dir.getFileHandle(name);
  const file = await handle.getFile();
  return file.text();
};

const randomId = () => {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toBase64url(bytes);
};

const generateKeys = async () => {
  const keyPair = await crypto.subtle.generateKey(ECDSA, true, [
    'sign',
    'verify',
  ]);
  const publicKeyBuffer = await crypto.subtle.exportKey(
    'spki',
    keyPair.publicKey,
  );
  const privateKeyBuffer = await crypto.subtle.exportKey(
    'pkcs8',
    keyPair.privateKey,
  );
  return {
    publicKey: toBase64url(publicKeyBuffer),
    privateKey: toBase64url(privateKeyBuffer),
  };
};

const importPrivateKey = async (encoded) => {
  const bytes = fromBase64url(encoded);
  return crypto.subtle.importKey('pkcs8', bytes, ECDSA, false, ['sign']);
};

const signPayload = async (privateKey, payload) => {
  const key =
    typeof privateKey === 'string'
      ? await importPrivateKey(privateKey)
      : privateKey;
  const bytes = new TextEncoder().encode(JSON.stringify(payload));
  const signature = await crypto.subtle.sign(ECDSA_SIGN, key, bytes);
  return {
    clientData: toBase64url(bytes),
    signature: toBase64url(signature),
  };
};

const saveLocalCredential = async (id, privateKey) => {
  const dir = await keysDir();
  await writeText(dir, ID_FILE, id);
  await writeText(dir, KEY_FILE, privateKey);
};

const loadLocalCredential = async () => {
  try {
    const dir = await keysDir();
    const id = await readText(dir, ID_FILE);
    const privateKey = await readText(dir, KEY_FILE);
    return { id, privateKey };
  } catch {
    return null;
  }
};

export default {
  randomId,
  generateKeys,
  signPayload,
  saveLocalCredential,
  loadLocalCredential,
};
