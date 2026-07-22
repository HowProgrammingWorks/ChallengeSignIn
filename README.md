# ChallengeSignIn

Dependency-free challenge–response sign-in for Node.js and modern browsers.
Uses **Web Crypto** (ECDSA P-256) and **OPFS** for the private key — no
Passkeys / WebAuthn.

## Run

```bash
npm start
```

Open `http://localhost:8000`.

Edit `config.js` if you change host, port, or deploy over HTTPS.

## Flow

Create an account (signs you in):

```text
POST /api/register/options
crypto.subtle.generateKey → save PKCS8 private key to OPFS
sign { type, origin, challenge, credentialId }
POST /api/register/verify   → session cookie
```

Sign in again later:

```text
POST /api/login/options
load private key from OPFS → crypto.subtle.sign
POST /api/login/verify      → session cookie
```

Session:

```text
GET  /api/session
POST /api/logout
```

## How it works

- Browser creates an ECDSA P-256 key pair, keeps the private key in OPFS
  (`keys/private.pkcs8`), and sends the public key to the server.
- Both register and login sign a small JSON payload: `type`, `origin`,
  `challenge`, and `credentialId`.
- Server checks challenge, origin, and the signature, then sets an HttpOnly
  session cookie.
- Public keys live in `credentials.json` (survive restarts). Challenges and
  sessions stay in memory.

App code: `static/crypto.js`, `lib/auth.js`.
