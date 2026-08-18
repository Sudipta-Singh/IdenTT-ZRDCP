# Work Log — IdenTT (internal)

Internal project record, not published. This is a single consolidated narrative covering how V1
was built, replacing the old session-by-session log (squashed here per the V1 release decision —
the detailed per-session entries added noise for anyone outside the build process). Update this
file going forward by extending the narrative below, not by appending new dated session sections.

## How V1 came together

IdenTT started from a single source document — a doctoral dissertation (author: Sudipta Singh)
formalizing the Zero-Knowledge Runtime-Generated Dynamic Challenge Protocol (ZRDCP) — and was built
in phases, each producing something runnable before the next began.

**Crypto core first.** The math came before any UI: Pedersen commitments and Fiat-Shamir NIZK
proofs (`src/crypto/pedersen.js`), Shamir's Secret Sharing with Lagrange reconstruction
(`src/crypto/shamir.js`), and the protocol's SHA3-256 hash-to-scalar function `H()`
(`src/crypto/hash.js`), all built on `@noble/curves` (secp256k1) and `@noble/hashes`, with a
constructive proof-by-test of the dissertation's Theorem 1 (k-1 shares reveal nothing about the
secret). This module never changed shape after V1 — everything built on top of it.

**Trusted device registry and a running app.** A local, passphrase-sealed vault (AES-GCM +
PBKDF2, `src/vault/`) holds a registry of trusted devices of two types — zrdcp-native peers
(identified by a public key) and FIDO2/WebAuthn authenticators (identified by credential ID,
with a hybrid `full-share`/`approval-only` participation model depending on PRF/hmac-secret
support). Real WebAuthn ceremonies need a secure context and a relying-party backend that a bare
`file://` page can't provide, so FIDO2 is simulated (`src/fido/simulate.js`) behind an interface
shaped exactly like the real thing, so swapping it in later doesn't touch calling code.

**Recovery initiation and dispatch.** Every vault generates its own persistent ZRDCP identity
keypair at creation. Recovery initiation (`src/recovery/initiate.js`) computes the Pedersen
commitment + NIZK proof over a runtime-entered code, splits `H(code)` into Shamir shares sized to
the mesh's actual share-holding devices, wraps each share per-recipient (ECDH+HKDF+AES-GCM,
`src/crypto/shareWrap.js` — FIDO2 full-share devices derive their ECDH keypair from a WebAuthn PRF
output), and dispatches to every device. This threshold model split further into two structurally
different operations: **authentication** (`kAuthentication`, a lightweight quorum check, no share
math) and **recovery** (`kRecovery` + `minRemoteForRecovery`, the full reconstruction flow,
requiring at least one responder flagged remote so a mesh can't be defeated by co-located devices).
Mesh size is bounded to 4-9 enrolled devices.

**Multi-vault architecture and real Responder Mode.** The app grew to support any number of
independently named local vaults sharing one browser's storage — which is what let Responder Mode
become real cryptography instead of a simulation harness. Each vault has its own unlock policy
(passphrase / passphrase + live authentication step-up / recovery-only with no passphrase, its
key protected by a real Shamir split across its own mesh). When one vault enrolls another local
vault's identity public key as a trusted device, a browser-wide directory
(`src/vault/directory.js`) lets it recognize that trusted device as a real local vault and deliver
a genuine request into a real inbox (`src/vault/crossVault.js`) — approving a recovery-kind
request really decrypts a Shamir share with the responder's own private key; approving an
authentication-kind request contributes a real liveness approval. Everything in this path is real
cryptography and real per-vault state; only actual network delivery to a vault outside the browser
remains simulated.

**Five-component UI, duress/decoy, and real dispatch.** The single long screen was restructured
into five components — Sign On, Requests, Vaults, Trusted Devices, Help — each its own module
under `src/app/screens/`, sharing DOM helpers (`src/app/ui.js`) and live session state
(`src/app/state.js`). A duress passcode (`src/vault/duress.js`, stored only as a salted hash) lets
someone under coercion enter a decoy code instead of their real runtime code on the Requests tab;
it silently swaps in a fake session (`src/recovery/decoy.js`) that looks and behaves identically to
a real one but touches no real cryptography, dispatch, or the normal device-count validation — the
only trace is a silent entry in the vault's own per-vault history log
(`src/vault/history.js`, stored inside the encrypted registry so it's only ever visible after a
genuine sign-in). Real (non-simulated) email/SMS dispatch was added via a small local Node/Express
backend (`server/`) holding SMTP/Twilio credentials in its own `.env`, called from the browser over
`fetch()` (`src/dispatch/realDispatch.js`) — additive alongside, not replacing, the existing
simulated dispatch used for testing threshold/remote-diversity policy without live credentials.

**Runtime-challenge response authentication and a unified Responses view (V1 closing work).** Two
requirements closed out V1. First: every device a challenge is dispatched to must now
independently type the exact same runtime challenge the originator used before its response counts
toward the threshold — an explicit, real-time authentication factor layered on top of (not
replacing) the existing Pedersen/NIZK proof, verified by reusing the protocol's own `H()` function
against the value it already commits to (`runtimeChallengeDigest()` in
`src/app/screens/requests.js`). This applies only to the Create Challenge flow, which is the only
place a runtime code is actually typed — the real cross-vault Responder Mode inbox has no typed
code in its design (recovery self-unlock uses a randomly generated split key; the
authentication-policy step-up is a pure liveness check), so it was deliberately left alone. Second:
the Requests tab was split into "Create Challenge" and "Responses" sub-tabs, with Responses now
showing both directions of a response together — incoming requests awaiting your response, and
every challenge you've initiated this session, each trackable through to its outcome in one place.

**V1 documentation pass.** With the app's functionality complete, all public-facing documentation
was regenerated against the current five-tab UI: fresh screenshots, a rewritten walkthrough, and a
clean GitHub-ready root README with a short release note rather than a changelog. This file, along
with `PLAN.md` and `TOOLS_AND_SKILLS.md`, moved to `docs/internal/` and was condensed here as the
project's internal build record, kept updated going forward but not published as primary
documentation.

## Current status (V1.0)

All originally planned phases are functionally complete for local, single-browser use:

- Crypto core, trusted device registry, recovery initiation/dispatch — done.
- Multi-vault architecture, per-vault unlock policy, real cross-vault Responder Mode — done.
- Five-component UI, duress passcode/decoy, real email/SMS dispatch — done.
- Runtime-challenge response authentication, unified Responses view — done.
- Test coverage: 140 Vitest tests plus a Playwright end-to-end smoke test
  (`scripts/smoke-test-ui.mjs`) driving the actual built app through every major flow, including a
  real 2-of-3 authentication step-up round trip and a real 3-of-3 Shamir reconstruction round trip
  across four vaults sharing one browser.

Still open, deliberately deferred past V1 (see `PLAN.md`'s "what's left" section for detail): the
full live reconstruction state machine for a real external challenge session (today's real
reconstruction only covers a vault's own recovery-mode unlock), real voice/WebAPI dispatch, real
FIDO2/WebAuthn ceremonies, AiTM/origin (TLS) binding meaningful only once there's a real hosted
responder site, and Electron/installer packaging.

`docs/DOCUMENTATION.docx` was intentionally left unregenerated in the V1 documentation pass (the
`.md` version is current; the `.docx` export is stale) — regenerate it in a future session if a
Word-format deliverable is needed again.
