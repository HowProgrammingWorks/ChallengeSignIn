import crypto from 'node:crypto';
import fs from 'node:fs';

import config from '../config.js';

class ServerError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

const credentials = new Map();
const challenges = new Map();
const sessions = new Map();

const loadCredentials = () => {
  try {
    const raw = fs.readFileSync(config.CREDENTIALS_FILE, 'utf8');
    const list = JSON.parse(raw);
    for (const item of list) credentials.set(item.id, item);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
};

const persistCredentials = () => {
  const list = [...credentials.values()];
  const data = JSON.stringify(list, null, 2);
  fs.writeFileSync(config.CREDENTIALS_FILE, data);
};

loadCredentials();

const randomToken = () => crypto.randomBytes(32).toString('base64url');

const fromBase64url = (value) => Buffer.from(value, 'base64url');

const issueChallenge = (payload) => {
  const challenge = randomToken();
  const expiresAt = Date.now() + config.CHALLENGE_TTL;
  challenges.set(challenge, { ...payload, expiresAt });
  return challenge;
};

const consumeChallenge = (challenge, expectedType) => {
  const entry = challenges.get(challenge);
  challenges.delete(challenge);
  if (!entry || entry.type !== expectedType || entry.expiresAt <= Date.now()) {
    throw new ServerError('Invalid or expired challenge');
  }
  return entry;
};

const readClientData = (encoded, expectedType) => {
  const bytes = fromBase64url(encoded);
  const data = JSON.parse(bytes.toString('utf8'));
  if (data.type !== expectedType) {
    throw new ServerError('Unexpected ceremony type');
  }
  if (data.origin !== config.ORIGIN) {
    throw new ServerError('Unexpected origin');
  }
  if (typeof data.challenge !== 'string') {
    throw new ServerError('Missing challenge');
  }
  if (typeof data.credentialId !== 'string') {
    throw new ServerError('Missing credential id');
  }
  return { bytes, data };
};

const normalizeSpki = (encoded) => {
  const publicKey = fromBase64url(encoded);
  crypto.createPublicKey({ key: publicKey, format: 'der', type: 'spki' });
  return publicKey.toString('base64url');
};

const verifySignature = (bytes, publicKeyDer, signature) => {
  const key = crypto.createPublicKey({
    key: publicKeyDer,
    format: 'der',
    type: 'spki',
  });
  const ok = crypto.verify(
    'sha256',
    bytes,
    { key, dsaEncoding: 'ieee-p1363' },
    signature,
  );
  if (!ok) throw new ServerError('Invalid signature', 401);
};

const userIdForUsername = (username) => {
  for (const credential of credentials.values()) {
    if (credential.username === username) return credential.userId;
  }
  return randomToken();
};

const replaceUsernameCredentials = (username, keepId) => {
  for (const [id, credential] of credentials) {
    if (credential.username === username && id !== keepId) {
      credentials.delete(id);
    }
  }
};

const createSession = (username) => {
  const token = randomToken();
  const expiresAt = Date.now() + config.SESSION_TTL;
  sessions.set(token, { username, expiresAt });
  return token;
};

const registrationOptions = ({ username }) => {
  if (typeof username !== 'string' || !username.trim()) {
    throw new ServerError('Invalid username');
  }
  username = username.trim();
  const userId = userIdForUsername(username);
  const challenge = issueChallenge({ type: 'registration', username, userId });
  return { challenge, userId, username };
};

const verifyRegistration = ({ id, publicKey, clientData, signature }) => {
  if (!id || !publicKey || !clientData || !signature) {
    throw new ServerError('Invalid credential');
  }
  const { bytes, data } = readClientData(clientData, 'registration');
  if (data.credentialId !== id) {
    throw new ServerError('Credential id mismatch');
  }
  const { username, userId } = consumeChallenge(data.challenge, 'registration');
  const spki = normalizeSpki(publicKey);
  verifySignature(bytes, fromBase64url(spki), fromBase64url(signature));
  const record = { id, username, userId, publicKey: spki };
  replaceUsernameCredentials(username, id);
  credentials.set(id, record);
  persistCredentials();
  const token = createSession(username);
  return { verified: true, token, user: { username } };
};

const authenticationOptions = () => {
  if (credentials.size === 0) {
    throw new ServerError('No credentials registered yet', 404);
  }
  const challenge = issueChallenge({ type: 'authentication' });
  return { challenge };
};

const verifyAuthentication = ({ id, clientData, signature }) => {
  if (!id || !clientData || !signature) {
    throw new ServerError('Invalid credential');
  }
  const record = credentials.get(id);
  if (!record) throw new ServerError('Unknown credential', 401);

  const { bytes, data } = readClientData(clientData, 'authentication');
  if (data.credentialId !== id) {
    throw new ServerError('Credential id mismatch', 401);
  }
  consumeChallenge(data.challenge, 'authentication');
  verifySignature(
    bytes,
    fromBase64url(record.publicKey),
    fromBase64url(signature),
  );

  const token = createSession(record.username);
  return { verified: true, token, user: { username: record.username } };
};

const getSession = (token) => {
  const session = sessions.get(token);
  if (!session || session.expiresAt <= Date.now()) {
    sessions.delete(token);
    return null;
  }
  return { username: session.username };
};

const revokeSession = (token) => sessions.delete(token);

export default {
  ServerError,
  registrationOptions,
  verifyRegistration,
  authenticationOptions,
  verifyAuthentication,
  getSession,
  revokeSession,
};
