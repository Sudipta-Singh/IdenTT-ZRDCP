# Tools & Skills Reference — IdenTT (internal)

Internal reference, not published. What the project is built with, and why — kept updated as
choices change so a future session doesn't need to re-derive them.

## Runtime & languages

- **JavaScript (ES2022+) / HTML / CSS** — no framework; plain DOM + ES modules keeps the app
  inspectable and dependency-light.
- **Browser WebCrypto API** — AES-GCM, PBKDF2/HKDF, secure random generation.
- **BigInt (native JS)** — modular arithmetic for Pedersen commitments and Shamir polynomials.
- **Node.js** — dev-time only (tests, bundling, the optional real-dispatch backend); not required
  to run the shipped app.

## Cryptography

- **`@noble/curves`** (audited, no dependencies) — secp256k1 group operations for Pedersen
  commitments, and `secp256k1.getSharedSecret()` for ECDH share wrapping.
- **`@noble/hashes`** — SHA3-256, the spec's hash function `H`.
- **Custom Shamir Secret Sharing** — field arithmetic and Lagrange interpolation implemented
  directly (~100 lines, BigInt) so it's traceable line-by-line to the dissertation's §2.2/§2.3
  formulas rather than trusting an opaque library's conventions. Deliberately avoids libraries like
  `secrets.js-grempe` that hardcode their own field/prime.
- **WebCrypto HKDF** — turns a raw ECDH shared secret (or a FIDO2 PRF output) into an AES-256 key
  for share wrapping (`src/crypto/shareWrap.js`).

## Testing

- **Vitest** — 140 unit/integration tests across the crypto core, vault, registry, recovery
  pipeline, multi-vault/Responder Mode, duress/decoy, and real-dispatch client.
- **Playwright** — drives real headless Chromium against the built `public/index.html`
  (`scripts/smoke-test-ui.mjs`), covering what Vitest alone can't (real DOM + localStorage +
  WebCrypto together on an actual page). Chromium binary pre-installed in the dev environment;
  `npx playwright install chromium` on a fresh machine.

## Build/dev tooling

- **esbuild** — bundles `src/app/main.js` into `dist/app.bundle.js` (IIFE). Necessary, not
  optional: `file://` pages can't use `type="module"` script imports (CORS). Source stays modular
  for testing; the checked-in bundle is what the shipped page loads. `npm run build` after any
  `src/` change.

## FIDO2/WebAuthn (simulated; real integration still open)

- **WebCrypto (`crypto.subtle`)** — used now for the simulated ceremony (`src/fido/simulate.js`,
  real ECDSA P-256 keypairs so the shape matches genuine COSE ES256 credentials).
- **`@simplewebauthn/browser` + `@simplewebauthn/server`** (not yet installed) — candidate pair for
  a real WebAuthn relying party once that work starts; the local Express backend added for real
  email/SMS is the server-side piece it would need.

## Backend & real dispatch (V1)

- **Express** (`server/`, own `package.json`) — small local server holding real SMTP/Twilio
  credentials via `.env` (never committed), exposing `/health`, `/send-email`, `/send-sms` over
  `http://localhost:4737`. Single local user, no auth of its own by design — see
  `server/README.md`.
- **Nodemailer** (`^9.0.5`) — real SMTP email dispatch. Bumped from an initial `^6.9.14` after
  `npm audit` flagged SSRF/file-read and SMTP-command-injection issues; `server/` audits clean now.
- **Twilio** (official Node SDK) — real SMS dispatch. Voice is not wired up.
- **dotenv**, **cors** — `.env` loading, permissive local CORS for the browser-to-localhost calls.
- **`src/dispatch/realDispatch.js`** — thin `fetch()` client, additive alongside the existing
  simulated dispatch layer (used to test threshold/remote-diversity policy without live
  credentials).

## Still open

- Real Twilio voice calls, and direct WebAPI dispatch — no extra library needed, just not built.
- **Electron** or **Tauri** — only if/when packaging as an installable desktop app is wanted.

## Claude-side skills/tools used in this project

- **`docx` skill** — used to read the source dissertation via `pandoc`, and previously to export
  `docs/DOCUMENTATION.docx` (not regenerated for V1 — see `WORK_LOG.md`).
- **Device bridge (`mcp__remote-devices__*`)** — reads/writes the project folder on the user's own
  machine so code and docs persist locally across sessions.
- **Project memory** — cross-session status notes for fast context recovery.

## Deliberately not used

- No cloud database or backend service beyond the optional local `server/` — everything else is
  local-first per the original project brief.
- No proprietary/closed cryptography — every primitive traces to a named, cited construction
  (Pedersen 1991, Shamir 1979, Fiat-Shamir 1986).
