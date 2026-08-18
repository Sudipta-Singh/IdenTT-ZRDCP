# IdenTT — V1.0

A local, offline-first implementation of the **Zero-Knowledge Runtime-Generated Dynamic Challenge
Protocol (ZRDCP)**: a way to authenticate or recover access to an account using a threshold of
trusted devices instead of (or alongside) a single password — without any one device ever
exposing your real secret. Built from `Zero_Knowledge_Dynamic_Challenge_Protocol_ZRDCP.docx`, a
doctoral dissertation by Sudipta Singh formalizing the protocol.

**New here?** [`docs/DOCUMENTATION.md`](docs/DOCUMENTATION.md) is a non-technical overview, a
brief technical summary, and a full screenshot-driven walkthrough of every feature, with a
references appendix. This README covers how to run it and how it's built.

See it in action at https://www.sudiptasingh.com/IdenTT/public/index.html


## What it does

- **No single point of failure.** Instead of one password or one device, a threshold of your own
  trusted devices (a phone, a laptop, a security key, a trusted friend's own vault) has to
  genuinely agree — using real Pedersen commitments, a Fiat-Shamir zero-knowledge proof, and
  Shamir's Secret Sharing — before anything unlocks.
- **Two distinct operations, deliberately kept separate:** a lightweight **authentication** quorum
  (any enrolled device counts, no share of anything ever moves) and a full cryptographic
  **recovery** reconstruction (only genuine share-holding devices count, with a minimum required
  to be geographically remote from you, so a mesh can't be defeated by devices sitting on the same
  desk).
- **A duress passcode.** Under coercion, a separate pre-set code produces a response
  indistinguishable from a real success — nothing real happens — while silently logging what
  occurred, visible only to you later.
- **Runtime-challenge response authentication.** Every device a challenge is dispatched to must
  independently type back the exact runtime code used, as a live authentication factor on top of
  the cryptographic proof itself.
- **Real cross-vault Responder Mode**, for local testing: any number of independently named vaults
  can share one browser, so a trusted device can be a genuine second party — real decryption, real
  approvals — not a simulation.
- **Optional real email/SMS dispatch**, via a small local backend you run yourself; credentials
  never touch the browser app.

## Running the app

No install needed to just use it — open `public/index.html` directly in a browser
(`dist/app.bundle.js` is pre-built and checked in). First run shows the Sign On screen: choose
"+ Create a new vault," set a name and passphrase, and go. That passphrase encrypts the vault's
trusted-device registry at rest in your browser's local storage — nothing leaves your machine.
You can create as many named vaults as you like in the same browser (useful for testing Responder
Mode against yourself — see below).

If you change anything under `src/`, rebuild the bundle before reloading the page:

```bash
npm install
npm run build        # regenerates dist/app.bundle.js from src/app/main.js
```

**Real email/SMS is optional.** By default every challenge uses simulated dispatch (an on-screen
activity log, no message actually sent). To send for real, run the small local backend under
`server/`:

```bash
cd server
npm install
cp .env.example .env   # fill in your own SMTP and/or Twilio credentials
npm start
```

That backend is the only place real credentials ever live — the browser app calls its
`/send-email`/`/send-sms` endpoints over `localhost` and never sees them directly. See
`server/README.md` for details; it's meant to run only on your own machine.

## Running the tests

```bash
npm install
npm test                          # 140 unit/integration tests (Vitest)
node scripts/smoke-test-ui.mjs    # end-to-end UI smoke test via a real headless Chromium
```

The unit suite covers the crypto core (Pedersen/NIZK, Shamir split/reconstruct, and a constructive
proof that k-1 shares reveal nothing), the encrypted vault and multi-vault store, the trusted
device registry (including FIDO2 simulation and remote-device diversity checks), the recovery
pipeline (initiation, wrapping, dispatch, outcome evaluation), real cross-vault Responder Mode
(directory lookup, inbox, approval, reconstruction), the per-vault history log, the duress
passcode and decoy session, and the real-dispatch client. The Playwright smoke test drives the
actual built page through every major flow, including a real 2-of-3 authentication step-up round
trip and a real 3-of-3 Shamir reconstruction round trip across four vaults sharing one browser.

## Source layout

```
src/crypto/     — Pedersen commitment, NIZK proof, Shamir secret sharing (the protocol's math core),
                  device identity keypairs, hex/point (de)serialization, per-recipient share
                  wrapping (ECDH+HKDF+AES-GCM)
src/vault/      — passphrase-sealed AES-GCM vault, storage adapters, multi-vault store, per-vault
                  unlock policy, browser-wide vault/identity directories, cross-vault inbox +
                  reconstruction scratch areas, vault-self-unlock Shamir split, per-vault history
                  log, duress passcode
src/registry/   — trusted-device data model + CRUD (zrdcp-native and fido2 device types), threshold
                  validation, mesh-diversity warnings
src/fido/       — simulated FIDO2/WebAuthn ceremonies (real ceremony deferred — see below), PRF-
                  output-to-ECDH-keypair derivation for full-share devices
src/protocol/   — RECOVERY_INIT / SHARE_DELIVERY / AUTH_CHALLENGE wire message builders
src/dispatch/   — simulated dispatch layer (activity log + responder link), plus realDispatch.js
                  (fetch() client for the server/ backend)
src/recovery/   — initiateRecovery() orchestration, evaluateOutcome() (policy-level outcome
                  simulator), respond.js (real Responder Mode approval logic), decoy.js
                  (DECOY_EXEC fake-session builder)
src/app/        — browser UI: main.js (2-line bootstrap), ui.js/state.js (shared helpers/state),
                  and screens/{signOn,shell,requests,vaults,devices,help}.js — see below
server/         — small local Express backend (own package.json) holding real SMTP/Twilio
                  credentials via .env, exposing /send-email and /send-sms — see server/README.md
public/         — index.html + styles.css, the actual page you open
dist/           — built bundle (checked in so no build step is required to just use the app)
scripts/        — smoke-test-ui.mjs (Playwright end-to-end check) and
                  generate-docs-screenshots.mjs (regenerates docs/screenshots/)
docs/           — DOCUMENTATION.md (public walkthrough) and screenshots/; docs/internal/ holds
                  project planning/build-log notes, kept for internal reference only
```

## How it works

### Trusted device types

Two kinds of trusted device can be enrolled:

- **zrdcp-native** — a peer running this same app/protocol, identified by a public key used to
  wrap its Shamir share.
- **fido2** — a WebAuthn authenticator (security key, Touch ID, Windows Hello, etc.). Its
  participation mode is decided automatically at enrollment by whether it supports the WebAuthn
  PRF/hmac-secret extension: `full-share` devices hold a genuine Shamir share (unlocked by a real
  assertion); `approval-only` devices count toward authentication but hold no share math.

Both types carry an `isRemote` flag — true means not physically co-located with you. Recovery
requires a minimum number of responding share-holders to be flagged remote.

**FIDO2 ceremonies are simulated for now** (`src/fido/simulate.js`) behind an interface shaped
exactly like the real WebAuthn API, so swapping in real hardware later won't require touching any
calling code — real ceremonies need a secure context and a relying-party backend, which is a
larger platform change deferred past V1.

### The five-tab app

1. **Sign On** — the only screen shown before a vault unlocks; picks or creates a vault and shows
   the sign-in flow matching its own unlock policy.
2. **Requests** — split into **Create Challenge** (prove yourself to another application) and
   **Responses** (every response-type interaction: requests awaiting your response, and challenges
   you've initiated), plus a persisted history log shown under both.
3. **Vaults** — this vault's unlock policy, mesh/threshold settings, and the duress + default
   authentication code passcodes.
4. **Trusted Devices** — your device identity, the device list, enroll/remove.
5. **Help** — inline documentation covering the other four, from inside the app itself.

### Duress passcode and decoy response

Set from the Vaults tab, stored only as a salted hash (never reversibly). Entering it instead of
your real runtime code on the Requests tab silently swaps in a session shaped identically to a
real one — same dispatch rows, same controls — but touches no real cryptography, split, or
dispatch, and always reports success. The only trace is a `duress-triggered` entry in the vault's
own history, stored inside the encrypted registry itself, so it's only ever visible to someone who
has genuinely signed in as the vault's owner.

### Runtime-challenge response authentication

Per the protocol's real-time authentication requirement, every device a challenge is dispatched to
must independently type back the exact same runtime code the originator used before its response
counts toward the threshold. This is verified by reusing the protocol's own hash function against
the value it already commits to (`H()` in `src/crypto/hash.js`) — a manual, out-of-band factor
(you'd tell a trusted responder the code directly) that sits on top of, not instead of, the
Pedersen/NIZK cryptographic proof. It applies to the Create Challenge flow, where a runtime code is
actually typed; the real cross-vault Responder Mode inbox has no typed code in its design
(recovery self-unlock uses a randomly generated split key; the authentication step-up is a pure
liveness check), so it doesn't apply there.

### Multi-vault architecture and real Responder Mode

App startup is a vault picker, not one fixed vault — any number of independently named vaults can
coexist in the same browser's storage. Each has its own **unlock policy**: passphrase only,
passphrase plus a live authentication step-up, or recovery-only (no passphrase — the vault's key
is protected by a real Shamir split across its own mesh instead). When one vault enrolls another
local vault's identity public key as a trusted device, a small browser-wide directory lets it
recognize that trusted device as a real local vault and deliver a genuine request into a real
inbox — approving a recovery request really decrypts a Shamir share with the responder's own
private key; approving an authentication request contributes a real liveness approval. What's
still simulated is only actual network delivery to a vault *outside* the browser (email/SMS/
webhook) — everything else in this path is real cryptography and real per-vault state.

### Two-tier threshold

`kAuthentication` (minimum 2) is a lightweight quorum check — any enrolled device counts, no share
ever leaves a device. `kRecovery` (minimum 3) plus `minRemoteForRecovery` (minimum 1) is the full
reconstruction flow — only real share-holding devices count, and at least that many responders
must be flagged remote. Total enrolled devices per vault are bounded to 4-9.

### Share wrapping

Every vault generates its own persistent ZRDCP identity keypair at creation. Outgoing shares are
wrapped via ECDH + HKDF + AES-GCM, keyed to each recipient's public key. FIDO2 full-share devices
don't have an addressable persistent keypair the normal way, so their WebAuthn PRF output (for one
fixed salt) is deterministically derived into a secp256k1 keypair instead — only the resulting
public key is registered, so the same ECDH wrapping code path handles both device types. One
deliberate, documented deviation from the dissertation's illustrative `SHARE_DELIVERY` JSON
schema: an `iv` field was added, since AES-GCM needs a nonce.

## Release notes — V1.0

This is IdenTT's first tagged release. Everything described above is implemented and working
against the real built app: the crypto core, the trusted device registry, recovery initiation and
dispatch, the multi-vault architecture with real cross-vault Responder Mode, the five-tab UI, the
duress passcode and decoy mechanism, real email/SMS dispatch, and runtime-challenge response
authentication. 140 automated tests and an end-to-end Playwright smoke test back all of it.

Deliberately not yet built, and open for a future release: a live reconstruction state machine for
a real *external* application's challenge session (today's real cryptographic reconstruction
covers a vault's own recovery-mode unlock; the "Create Challenge" flow's outcome check against
another application is a policy-level evaluator rather than a live external session), real voice
and WebAPI dispatch, real FIDO2/WebAuthn hardware ceremonies, the dissertation's AiTM/TLS-origin
binding (meaningful once there's a real hosted responder site to bind against), and optional
desktop packaging (Electron/Tauri).

## A protocol-design note worth flagging

The dissertation's state diagram doesn't fully specify how NIZK proof verification and Shamir
reconstruction relate to each other, or what happens to a reconstructed secret afterward. This
implementation treats them as two independent mechanisms — the NIZK proof is how each node
verifies a request is legitimate before releasing its share; Shamir reconstruction is how the
session's secret material is actually recovered once enough shares are back — and does not persist
a reconstructed secret itself; it's used in-session for ongoing authentication with whatever
application issued the original challenge. See `test/integration.test.js`'s header comment for the
full reasoning.
