# IdenTT — Build Plan (internal)

Internal reference, not published. Condensed for V1 — see `WORK_LOG.md` in this same folder for the
narrative of how the app got here, and the root `README.md` for the public-facing description.
Source spec: `Zero_Knowledge_Dynamic_Challenge_Protocol_ZRDCP.docx` (doctoral dissertation
formalizing ZRDCP, author Sudipta Singh).

## What the spec asks for

ZRDCP is an account-recovery protocol that replaces "prove who you are with one hardware key or
biometric" with "prove who you are by getting agreement from k-of-n trusted devices/people, using
math that never exposes your actual secret." Six pieces, per the dissertation:

1. Pedersen commitment + Fiat-Shamir NIZK proof (§2.1) — prove knowledge of a runtime secret
   without revealing it.
2. Shamir's Secret Sharing (§2.2/§2.3) — split the committed value into n shares; k reconstruct it,
   fewer reveal nothing.
3. AiTM/origin binding (§4.1) — bind the challenge to a TLS certificate hash so a phishing proxy
   can't relay a session.
4. Duress/decoy handling (§4.2) — a second code opens a fake decoy session while alerting contacts.
5. Wire protocol (§5.1) — `RECOVERY_INIT` / `SHARE_DELIVERY` JSON messages.
6. State machine (§5.2) — `IDLE → CHALLENGE_INPUT → DISPATCH_SHARES → {INTERPOLATING |
   DEGRADED_MESH | DECOY_EXEC} → AUTHENTICATED`.

## Scope decisions

- **App name:** IdenTT. **Platform:** static HTML/JS, no install, all crypto client-side
  (WebCrypto + BigInt) — could be wrapped as an Electron app later without a redesign.
- **Mesh size:** 4-9 enrolled devices per vault (`targetN`, default 6). Two-tier threshold, not a
  single `k`: `kAuthentication` (min 2, lightweight quorum, any device type) and `kRecovery` (min
  3) + `minRemoteForRecovery` (min 1, real share-holders only, diversity-checked).
- **Dispatch:** simulated/logged by default; real SMTP (Nodemailer) + Twilio SMS now implemented
  via a local `server/` backend (V1) — voice and WebAPI dispatch remain simulated.
- **Responder site:** the same app, opened as another local named vault — no separate hosting.
- **Reconstructed secret:** used in-session for ongoing auth with the challenging application, not
  persisted by IdenTT itself.
- **FIDO2/WebAuthn:** first-class trusted devices, hybrid full-share (PRF-capable) /
  approval-only participation, real ceremonies deferred (see "What's left").
- **Elliptic curve:** secp256k1 via `@noble/curves`, unchanged since Phase 0.

## Architecture (current, V1)

```
[Trusted Device Registry]  → n devices per vault, each zrdcp-native or fido2
        |
        v
[Create Challenge]  → runtime code C_r (or duress code → decoy) + purpose
        |                (authentication | recovery)
        v
[Crypto Core]  → Pedersen commitment, NIZK proof, Shamir split (recovery only),
                  per-recipient ECDH+AES-GCM share wrapping
        |
        v
[Dispatch]  → simulated activity log, or real email/SMS via server/ backend
        |
        v
[Responses]  → "Awaiting your response" (real cross-vault Responder Mode inbox)
               "Challenges you've initiated" (dispatch tracking + runtime-challenge
               response authentication + outcome evaluation)
        |
        v
[Reconstruction]  → real Lagrange interpolation once k genuine responses (incl.
                     required remote diversity) are collected
```

Vault unlock itself is a parallel, simpler use of the same primitives: each vault picks its own
unlock policy (passphrase / passphrase + authentication step-up / recovery-only, its key protected
by a Shamir split across its own mesh) — see `src/vault/meta.js`, `unlockRecovery.js`.

Persistent local storage (encrypted): device registry, thresholds, per-vault history log. Session
state (in-flight challenges, dispatch/outcome tracking) is deliberately ephemeral — no long-term
central server holds secrets, matching the spec's model. No raw secret is ever stored, only
`H(C_r)`'s Shamir shares, each encrypted per-recipient before leaving the initiating device.

## Source layout

See the root `README.md`'s "Source layout" section — kept there since it's the map a new
contributor needs first, and duplicating it here would just drift out of sync.

## What's left (post-V1)

- **Live external reconstruction state machine.** Today's real Shamir reconstruction only covers a
  vault's own recovery-mode self-unlock. The "Create Challenge" flow's outcome evaluation (for
  proving yourself to some *other* application) still uses a policy-only evaluator
  (`src/recovery/evaluateOutcome.js`) rather than a live, real external session — building the
  latter needs an actual external relying party to challenge, which doesn't exist yet.
- **Real voice / WebAPI dispatch.** Email and SMS are real (V1); voice (Twilio) and direct WebAPI
  delivery remain simulated.
- **Real FIDO2/WebAuthn ceremonies.** Still simulated (`src/fido/simulate.js`) behind an interface
  matching the real WebAuthn API shape. The local Express backend added for real email/SMS is also
  the relying-party-server infrastructure real WebAuthn will need — just not wired to it yet.
- **AiTM/origin (TLS) binding (§4.1).** Only meaningful once there's a real hosted responder site
  to bind against; not yet built.
- **Packaging.** Electron/Tauri wrapper for a distributable desktop app, if wanted — currently just
  "open `public/index.html`."

## Open questions — all resolved for V1

App name, mesh sizing, Twilio/SMTP, elliptic curve choice, reconstructed-secret handling, and the
FIDO2 participation model were all settled early and haven't changed — see `WORK_LOG.md` for how
each was decided if the reasoning is needed again.
