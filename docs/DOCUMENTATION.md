# IdenTT — Documentation (V1.0)

A public, non-technical-first walkthrough of what IdenTT does, how it works, and how to use it —
with a screenshot-driven tour of every key function and a references appendix. For build/run
instructions and the source layout, see the root [`README.md`](../README.md).

**Table of contents**

1. [Non-technical overview](#1-non-technical-overview)
2. [Technical summary](#2-technical-summary)
3. [Walkthrough](#3-walkthrough)
4. [Project status](#4-project-status)
5. [Appendix A — References](#appendix-a--references)
6. [Appendix B — Glossary](#appendix-b--glossary)

---

## 1. Non-technical overview

Most account recovery today comes down to one single point of failure: a password, an email
inbox, or a phone number. If that one thing is compromised, lost, or taken from you under duress,
whoever holds it can act as you.

IdenTT implements the **Zero-Knowledge Runtime-Generated Dynamic Challenge Protocol (ZRDCP)**, an
academic protocol (see Appendix A) that replaces that single point of failure with a **group of
trusted devices or people who each hold a small piece of the puzzle**. No individual device —
including the one you're using right now — ever holds enough on its own to impersonate you or
recover your account. A threshold of them (say, 3 of 6) has to genuinely agree, using real
cryptography, before anything happens.

IdenTT does two related but distinct things with that idea:

- **Unlocking your own vault.** Instead of (or in addition to) a passphrase, your own local vault
  of trusted devices can require a live check-in from some of them, or reconstruct your vault's
  key from a threshold of them — see §3.3–§3.5 below.
- **Proving yourself to some other application.** When another system challenges you to
  authenticate or recover access, IdenTT computes a cryptographic commitment to a code you enter
  at that moment, dispatches it to your trusted devices, and (for recovery) splits the commitment
  into shares no single device can use alone — see §3.6–§3.9.

A second layer sits on top of both: if you're ever forced to authenticate under coercion, a
**duress passcode** produces a response that looks completely normal to an observer while quietly
recording what really happened, visible only to you later.

Everything runs entirely in your browser (with an optional small local helper for sending real
email/SMS). Nothing is sent to any third party unless you set that helper up yourself.

## 2. Technical summary

IdenTT is a static, local-first HTML/JS application — no install, no server required to run it
(open `public/index.html`). All cryptography runs client-side using the Web Crypto API and BigInt
arithmetic, built on the audited `@noble/curves`/`@noble/hashes` libraries over the secp256k1
curve. The full source layout, dependency list, and test suite are documented in the root
[`README.md`](../README.md) rather than repeated here.

In brief, the cryptographic core implements:

- **Pedersen commitments + a Fiat-Shamir non-interactive zero-knowledge proof**, so a device can
  prove it knows a runtime-entered secret without revealing it.
- **Shamir's Secret Sharing**, so that secret's committed value can be split across a mesh of
  trusted devices such that any *k* of them reconstruct it, and fewer than *k* reveal nothing about
  it at all.
- A **two-tier threshold model**: a lightweight *authentication* quorum (any enrolled device
  counts, no cryptographic share ever moves) and a full *recovery* reconstruction (only genuine
  share-holding devices count, with a minimum number required to be geographically/physically
  remote from you, so a mesh can't be defeated just by possessing every device sitting on the same
  desk).
- A **duress/decoy mechanism**: entering a separate, pre-configured passcode instead of your real
  one produces a session that is — by design — indistinguishable from a genuine success, while
  silently logging the event where only you can find it later.

140 automated unit/integration tests (Vitest) and an end-to-end Playwright smoke test covering
every flow described below, including real multi-vault cryptographic round trips, back this up —
see the root README's "Running the tests" section.

## 3. Walkthrough

This walkthrough follows one user, Alice, from her first vault through enrolling trusted devices,
configuring her vault's security, and a full real round trip with three of her trusted devices
(Bob, Carol, and Dave) acting as genuine responders — all in the same browser, exactly as this
documentation's screenshots were generated.

### 3.1 Signing in

The Sign On screen is the only screen you see before a vault unlocks. A single dropdown picks
which vault to act on — including "+ Create a new vault" — and a short explanation of the two ways
a vault can be signed into: **Authentication mode** (a passphrase, optionally followed by a live
check-in) and **Recovery mode** (no passphrase at all — the mesh reconstructs the key instead).

![Sign On screen, no vaults yet](screenshots/01-sign-on-empty.png)

Creating a vault just needs a name and a passphrase:

![Creating a new vault](screenshots/02-sign-on-create-vault-form.png)

### 3.2 A fresh vault, and its security settings

A brand-new vault has no trusted devices yet, so its Vault settings tab shows a warning that its
recovery threshold can't currently be met — the same "Vault security" panel where you'll later
choose how this vault unlocks (§3.4):

![A fresh vault's security panel](screenshots/03-fresh-vault-warnings.png)

### 3.3 Enrolling trusted devices

The Trusted Devices tab is where Alice's mesh is built. Two device types are supported:
**zrdcp-native** (another IdenTT vault or client, identified by a public key), and **FIDO2/
WebAuthn** (a security key, Touch ID, Windows Hello, etc.). Either can be flagged **remote** — not
physically co-located with you — which matters for the recovery threshold below.

![Adding a ZRDCP-native device](screenshots/04-add-native-device-form.png)

![Adding a remote ZRDCP-native device](screenshots/05-add-remote-device-form.png)

FIDO2 devices are registered the same way, with real hardware ceremonies still simulated for now
(see §4):

![Adding a FIDO2/WebAuthn device](screenshots/06-add-fido2-device-form.png)

The Trusted Devices tab also shows Alice's own device identity (the public key other vaults would
enroll to trust *her*) and the current device list:

![Trusted device list](screenshots/07-device-list.png)

### 3.4 Mesh size and unlock policy

Back on Vault settings, "Mesh & threshold" configures how large this vault's mesh is allowed to
grow (4–9 devices) and the two separate thresholds: how many devices must approve a live
authentication check, and how many real shares (with how many required to be remote) a recovery
needs.

![Mesh & threshold configuration](screenshots/08-mesh-threshold-config.png)

"Vault security" is where the unlock policy itself is chosen — passphrase only, passphrase plus a
live authentication check-in, or recovery-only with no passphrase at all:

![Vault security policy selector](screenshots/09-vault-security-policy-selector.png)

### 3.5 Duress passcode

A separate, optional passcode can be set for use under coercion. Entering it instead of a real
runtime code produces a session that looks and behaves exactly like a genuine success — nothing
real is computed or sent — while silently recording the event in this vault's own history,
visible only after a genuine sign-in (§3.9).

![Duress and authentication passcode settings](screenshots/10-duress-passcode-section.png)

### 3.6 Multiple vaults, and a real trusted-device mesh

Any number of independently named vaults can coexist in the same browser. Three more — Bob,
Carol, and Dave — are created here specifically so they can act as **real** responders to Alice's
requests below, rather than a simulation:

![Sign On screen with multiple vaults](screenshots/11-sign-on-multiple-vaults.png)

Once Bob, Carol, and Dave's own identity public keys are enrolled as Alice's trusted devices (Dave
flagged remote), Alice's mesh recognizes each of them as a real local vault — not just a name —
which is what makes the next two sections genuine cryptography rather than a simulated response.

### 3.7 Real authentication step-up (2-of-3 approval)

With Alice's unlock policy set to require a live authentication check-in, locking and unlocking her
vault now dispatches a real request to her trusted devices:

![Authentication step-up dispatch](screenshots/12-auth-stepup-dispatch.png)

Each responder sees the pending request in their own vault's Requests → Responses tab, and
genuinely approves or denies it:

![A pending authentication request in Bob's Responder inbox](screenshots/13-responder-mode-pending-authentication-request.png)

Once two of the three real approvals are in, Alice's vault reflects it and lets her continue:

![Authentication step-up granted](screenshots/14-auth-stepup-granted.png)

### 3.8 Real recovery reconstruction (3-of-3, including the required remote device)

Switching Alice's vault to recovery-only unlock protects its key with a genuine Shamir split
across her mesh — from this point there's no passphrase for this vault at all. Locking it and
initiating recovery dispatches a real request to every share-holding device:

![Recovery unlock dispatch](screenshots/15-recovery-unlock-dispatch.png)

![A pending recovery request in a responder's inbox](screenshots/16-responder-mode-pending-recovery-request.png)

Each of Bob, Carol, and Dave genuinely decrypts and contributes their own real Shamir share —
nothing is simulated here. Once all three responses are in (including Dave, the required remote
responder), Alice's vault can really reconstruct its key and open:

![Recovery unlock ready to open](screenshots/17-recovery-unlock-ready.png)

### 3.9 Proving yourself to another application: Create Challenge and Responses

Separately from unlocking her own vault, Alice can prove herself to some *other* application that
has issued her a challenge. The Requests tab's **Create Challenge** sub-tab starts one:

![Create a challenge](screenshots/18-requests-create-challenge.png)

Submitting a challenge switches straight to the **Responses** sub-tab, which is where *every*
response-type interaction lives — requests awaiting Alice's own response, and every challenge
she's initiated herself, together in one place:

![Challenges you've initiated, with dispatch rows](screenshots/19-requests-outgoing-dispatch.png)

**Runtime-challenge response authentication.** Every device a challenge is dispatched to must
independently type back the *exact* runtime code Alice used — an explicit, real-time
authentication step layered on top of (not replacing) the underlying cryptographic proof. A device
that "responds" with the wrong code — or the right code typed by someone who was never told it —
does not count toward the threshold:

![Runtime-challenge response denied — wrong code entered](screenshots/20-runtime-challenge-outcome-denied.png)

Typed correctly by enough responders, the same challenge is granted:

![Runtime-challenge response granted — correct code entered](screenshots/21-runtime-challenge-outcome-granted.png)

### 3.10 Duress passcode in action

Entering the duress passcode configured earlier (§3.5), instead of a real runtime code, produces a
session shaped identically to a real one — same dispatch rows, same controls — but touches no real
cryptography or dispatch, and always reports success:

![A duress-triggered decoy session](screenshots/22-duress-decoy-session.png)

The only trace is a silent entry in this vault's own history, readable only after a genuine
sign-in as its owner:

![Vault history log, including the duress trigger](screenshots/23-history-log.png)

### 3.11 In-app help, and locking up

An in-app Help tab explains every tab in practical terms, including how to set up real email/SMS
sending:

![The in-app Help tab](screenshots/24-help-tab.png)

And, as always, locking a vault returns to the Sign On screen with nothing decrypted in memory:

![A locked vault](screenshots/25-vault-locked.png)

## 4. Project status

**IdenTT V1.0.** All of the flows shown above are fully implemented, real (not simulated) where
described, and covered by 140 automated tests plus an end-to-end browser smoke test. What remains
open for a future release: a live reconstruction state machine for a real *external* application's
challenge session (today's real cryptographic reconstruction covers a vault's own recovery-mode
unlock; the "Create Challenge" flow's outcome check against another application is a policy-level
evaluator rather than a live external session), real voice/WebAPI dispatch, real FIDO2/WebAuthn
hardware ceremonies (currently simulated behind an interface matching the real one), the
dissertation's AiTM/TLS-origin binding (meaningful once there's a real hosted responder site), and
optional desktop packaging. See the root [`README.md`](../README.md) for how to run and test the
app as it stands today.

## Appendix A — References

1. Singh, Sudipta. *Zero-Knowledge Runtime-Generated Dynamic Challenge Protocol (ZRDCP)* —
   doctoral dissertation; the source specification this project implements.
2. Pedersen, T. P. (1991). *Non-Interactive and Information-Theoretic Secure Verifiable Secret
   Sharing.* CRYPTO '91.
3. Shamir, A. (1979). *How to Share a Secret.* Communications of the ACM, 22(11), 612–613.
4. Fiat, A., & Shamir, A. (1986). *How to Prove Yourself: Practical Solutions to Identification and
   Signature Problems.* CRYPTO '86.
5. [`@noble/curves`](https://github.com/paulmillr/noble-curves) — audited, dependency-free
   elliptic-curve library used for all group arithmetic.
6. [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — audited hash function library
   (SHA3-256, as specified by the protocol).
7. [WebAuthn (Web Authentication) specification](https://www.w3.org/TR/webauthn-3/) — W3C
   Recommendation, the standard IdenTT's FIDO2 device type targets.
8. [Web Cryptography API specification](https://www.w3.org/TR/WebCryptoAPI/) — W3C
   Recommendation, used for AES-GCM, PBKDF2/HKDF, and secure random generation.
9. [Vitest](https://vitest.dev/) — the unit/integration test runner used throughout.
10. [Playwright](https://playwright.dev/) — the end-to-end browser automation used for
    `scripts/smoke-test-ui.mjs` and this documentation's own screenshots.
11. [esbuild](https://esbuild.github.io/) — bundles the app's ES modules into the single script a
    `file://` page can load.
12. [`README.md`](../README.md) — this project's own build/run instructions, architecture, and
    source layout.

## Appendix B — Glossary

- **ZRDCP** — Zero-Knowledge Runtime-Generated Dynamic Challenge Protocol; the protocol this app
  implements.
- **Runtime code / runtime challenge (`C_r`)** — the secret you type at the moment of a challenge;
  never stored, only committed to and split.
- **Pedersen commitment** — a cryptographic value that "locks in" a secret without revealing it,
  which can later be proven to have been computed honestly.
- **NIZK proof (Non-Interactive Zero-Knowledge proof)** — the Fiat-Shamir proof that a device knows
  the runtime code behind a commitment, without revealing the code itself.
- **Shamir share** — one piece of a secret split via Shamir's Secret Sharing; a threshold of pieces
  reconstructs the secret, fewer reveal nothing.
- **Threshold (`k`-of-`n`)** — the minimum number of trusted devices/shares required, out of the
  total enrolled.
- **Authentication vs. recovery** — two distinct operations against the same mesh: authentication
  is a lightweight live-approval quorum with no share math; recovery is the full cryptographic
  reconstruction, requiring real shares and a minimum number of remote responders.
- **Remote device** — a trusted device flagged as not physically co-located with you; recovery
  requires a minimum number of responding share-holders to be remote.
- **Vault** — a local, encrypted registry of your trusted devices, thresholds, and history, sealed
  either by a passphrase or by your own mesh (recovery-only unlock policy).
- **Unlock policy** — how a specific vault unlocks: passphrase only, passphrase plus a live
  authentication check-in, or recovery-only (no passphrase).
- **Responder Mode / "Awaiting your response"** — the real inbox of requests from other local
  vaults that trust yours, on the Requests tab's Responses sub-tab.
- **Runtime-challenge response authentication** — the requirement that a device responding to a
  dispatched challenge type back the exact runtime code used, as a live authentication factor on
  top of the cryptographic proof.
- **Duress passcode** — a second, separate code that, entered instead of your real one, produces an
  indistinguishable fake "success" while silently logging the event.
- **Decoy session (`DECOY_EXEC`)** — the fake session a duress passcode triggers: shaped like a
  real one, touching no real cryptography or dispatch, always reporting success.
- **FIDO2 / WebAuthn device** — a hardware authenticator (security key, biometric, etc.) enrolled
  as a trusted device, either as a real share-holder (`full-share`) or an approval-only vote.
