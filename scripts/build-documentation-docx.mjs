// Converts docs/DOCUMENTATION.md into docs/DOCUMENTATION.docx, with the walkthrough's
// screenshots embedded INLINE as real image data (not relative file links) so the .docx is fully
// self-contained and portable. Run with:
//   node scripts/build-documentation-docx.mjs
// Hand-authored against this document's actual content (rather than a generic Markdown->docx
// converter) so headings, the references list, and the screenshot placements come out exactly
// right; re-run after editing docs/DOCUMENTATION.md to regenerate docs/DOCUMENTATION.docx.
//
// Rewritten for V1.0 (session 9) to match the V1.0 rewrite of docs/DOCUMENTATION.md: the
// five-tab/sub-tab UI walkthrough (§3.1-3.11, 25 screenshots, filenames like
// "01-sign-on-empty.png"), the runtime-challenge response authentication and duress/decoy
// sections, and references/appendices that no longer point at docs/PLAN.md, docs/WORK_LOG.md, or
// docs/TOOLS_AND_SKILLS.md as public docs (those moved to docs/internal/ for V1.0 — this document
// links to the root README.md instead, matching the .md source).
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  Document,
  Packer,
  Paragraph,
  TextRun,
  ExternalHyperlink,
  ImageRun,
  HeadingLevel,
  AlignmentType,
  BorderStyle,
} from 'docx';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const docsDir = path.join(__dirname, '..', 'docs');
const screenshotsDir = path.join(docsDir, 'screenshots');

function pngSize(file) {
  const buf = fs.readFileSync(file);
  return { width: buf.readUInt32BE(16), height: buf.readUInt32BE(20) };
}

// Scale every (760x1000) screenshot down to a page-friendly width, preserving aspect ratio.
function screenshotImage(filename) {
  const file = path.join(screenshotsDir, filename);
  const { width, height } = pngSize(file);
  const targetWidth = 460;
  const targetHeight = Math.round((height / width) * targetWidth);
  return new ImageRun({
    type: 'png',
    data: fs.readFileSync(file),
    transformation: { width: targetWidth, height: targetHeight },
  });
}

// --- tiny inline-markdown -> docx runs helper (bold, italics, code, links) -----------------

function inline(text) {
  const runs = [];
  const re = /(`[^`]+`)|(\*\*[^*]+\*\*)|(\*[^*]+\*)|(\[[^\]]+\]\([^)]+\))/g;
  let last = 0;
  let m;
  const pushPlain = (s) => {
    if (s) runs.push(new TextRun(s));
  };
  while ((m = re.exec(text))) {
    pushPlain(text.slice(last, m.index));
    const token = m[0];
    if (token.startsWith('`')) {
      runs.push(new TextRun({ text: token.slice(1, -1), font: 'Consolas', shading: { fill: 'F0F0F0' } }));
    } else if (token.startsWith('**')) {
      runs.push(new TextRun({ text: token.slice(2, -2), bold: true }));
    } else if (token.startsWith('*')) {
      runs.push(new TextRun({ text: token.slice(1, -1), italics: true }));
    } else {
      const linkMatch = token.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
      const label = linkMatch[1];
      const url = linkMatch[2];
      if (/^https?:\/\//.test(url)) {
        runs.push(
          new ExternalHyperlink({
            link: url,
            children: [new TextRun({ text: label, style: 'Hyperlink' })],
          })
        );
      } else {
        // Internal anchor or relative repo-file link — not resolvable inside a standalone .docx,
        // so render as plain (non-broken-looking) emphasized text rather than a dead hyperlink.
        runs.push(new TextRun({ text: label, italics: true }));
      }
    }
    last = m.index + token.length;
  }
  pushPlain(text.slice(last));
  return runs.length ? runs : [new TextRun(text)];
}

function p(text, opts = {}) {
  return new Paragraph({ children: inline(text), spacing: { after: 160 }, ...opts });
}

function heading(text, level) {
  return new Paragraph({ text, heading: level, spacing: { before: 280, after: 140 } });
}

function bullet(text) {
  return new Paragraph({ children: inline(text), bullet: { level: 0 }, spacing: { after: 80 } });
}

function figure(filename, caption) {
  return [
    new Paragraph({ children: [screenshotImage(filename)], alignment: AlignmentType.CENTER, spacing: { before: 120, after: 60 } }),
    new Paragraph({
      children: [new TextRun({ text: caption, italics: true, size: 20 })],
      alignment: AlignmentType.CENTER,
      spacing: { after: 240 },
    }),
  ];
}

function rule() {
  return new Paragraph({
    text: '',
    border: { bottom: { color: 'AAAAAA', space: 1, style: BorderStyle.SINGLE, size: 6 } },
    spacing: { after: 240 },
  });
}

function subhead(text) {
  return new Paragraph({ children: [new TextRun({ text, bold: true })], spacing: { before: 160, after: 120 } });
}

// --- document body -----------------------------------------------------------------------

const children = [];

children.push(
  new Paragraph({ text: 'IdenTT — Documentation (V1.0)', heading: HeadingLevel.TITLE, spacing: { after: 200 } }),
  p(
    'A public, non-technical-first walkthrough of what IdenTT does, how it works, and how to use it — with a screenshot-driven tour of every key function and a references appendix. For build/run instructions and the source layout, see the root [`README.md`](../README.md).'
  ),
  rule()
);

// 1. Non-technical overview
children.push(heading('1. Non-technical overview', HeadingLevel.HEADING_1));
children.push(
  p(
    'Most account recovery today comes down to one single point of failure: a password, an email inbox, or a phone number. If that one thing is compromised, lost, or taken from you under duress, whoever holds it can act as you.'
  ),
  p(
    'IdenTT implements the **Zero-Knowledge Runtime-Generated Dynamic Challenge Protocol (ZRDCP)**, an academic protocol (see Appendix A) that replaces that single point of failure with a group of trusted devices or people who each hold a small piece of the puzzle. No individual device — including the one you\'re using right now — ever holds enough on its own to impersonate you or recover your account. A threshold of them (say, 3 of 6) has to genuinely agree, using real cryptography, before anything happens.'
  ),
  p('IdenTT does two related but distinct things with that idea:'),
  bullet(
    '**Unlocking your own vault.** Instead of (or in addition to) a passphrase, your own local vault of trusted devices can require a live check-in from some of them, or reconstruct your vault\'s key from a threshold of them — see §3.3–§3.5 below.'
  ),
  bullet(
    '**Proving yourself to some other application.** When another system challenges you to authenticate or recover access, IdenTT computes a cryptographic commitment to a code you enter at that moment, dispatches it to your trusted devices, and (for recovery) splits the commitment into shares no single device can use alone — see §3.6–§3.9.'
  ),
  p(
    "A second layer sits on top of both: if you're ever forced to authenticate under coercion, a **duress passcode** produces a response that looks completely normal to an observer while quietly recording what really happened, visible only to you later."
  ),
  p(
    'Everything runs entirely in your browser (with an optional small local helper for sending real email/SMS). Nothing is sent to any third party unless you set that helper up yourself.'
  )
);

// 2. Technical summary
children.push(heading('2. Technical summary', HeadingLevel.HEADING_1));
children.push(
  p(
    'IdenTT is a static, local-first HTML/JS application — no install, no server required to run it (open `public/index.html`). All cryptography runs client-side using the Web Crypto API and BigInt arithmetic, built on the audited `@noble/curves`/`@noble/hashes` libraries over the secp256k1 curve. The full source layout, dependency list, and test suite are documented in the root [`README.md`](../README.md) rather than repeated here.'
  ),
  p('In brief, the cryptographic core implements:'),
  bullet(
    '**Pedersen commitments + a Fiat-Shamir non-interactive zero-knowledge proof**, so a device can prove it knows a runtime-entered secret without revealing it.'
  ),
  bullet(
    "**Shamir's Secret Sharing**, so that secret's committed value can be split across a mesh of trusted devices such that any *k* of them reconstruct it, and fewer than *k* reveal nothing about it at all."
  ),
  bullet(
    'A **two-tier threshold model**: a lightweight *authentication* quorum (any enrolled device counts, no cryptographic share ever moves) and a full *recovery* reconstruction (only genuine share-holding devices count, with a minimum number required to be geographically/physically remote from you, so a mesh can\'t be defeated just by possessing every device sitting on the same desk).'
  ),
  bullet(
    'A **duress/decoy mechanism**: entering a separate, pre-configured passcode instead of your real one produces a session that is — by design — indistinguishable from a genuine success, while silently logging the event where only you can find it later.'
  ),
  p(
    '140 automated unit/integration tests (Vitest) and an end-to-end Playwright smoke test covering every flow described below, including real multi-vault cryptographic round trips, back this up — see the root README\'s "Running the tests" section.'
  )
);

// 3. Walkthrough
children.push(heading('3. Walkthrough', HeadingLevel.HEADING_1));
children.push(
  p(
    "This walkthrough follows one user, Alice, from her first vault through enrolling trusted devices, configuring her vault's security, and a full real round trip with three of her trusted devices (Bob, Carol, and Dave) acting as genuine responders — all in the same browser, exactly as this documentation's screenshots were generated."
  )
);

children.push(heading('3.1 Signing in', HeadingLevel.HEADING_2));
children.push(
  p(
    'The Sign On screen is the only screen you see before a vault unlocks. A single dropdown picks which vault to act on — including "+ Create a new vault" — and a short explanation of the two ways a vault can be signed into: **Authentication mode** (a passphrase, optionally followed by a live check-in) and **Recovery mode** (no passphrase at all — the mesh reconstructs the key instead).'
  )
);
children.push(...figure('01-sign-on-empty.png', 'Sign On screen, no vaults yet'));
children.push(p('Creating a vault just needs a name and a passphrase:'));
children.push(...figure('02-sign-on-create-vault-form.png', 'Creating a new vault'));

children.push(heading('3.2 A fresh vault, and its security settings', HeadingLevel.HEADING_2));
children.push(
  p(
    'A brand-new vault has no trusted devices yet, so its Vault settings tab shows a warning that its recovery threshold can\'t currently be met — the same "Vault security" panel where you\'ll later choose how this vault unlocks (§3.4):'
  )
);
children.push(...figure('03-fresh-vault-warnings.png', "A fresh vault's security panel"));

children.push(heading('3.3 Enrolling trusted devices', HeadingLevel.HEADING_2));
children.push(
  p(
    'The Trusted Devices tab is where Alice\'s mesh is built. Two device types are supported: **zrdcp-native** (another IdenTT vault or client, identified by a public key), and **FIDO2/WebAuthn** (a security key, Touch ID, Windows Hello, etc.). Either can be flagged **remote** — not physically co-located with you — which matters for the recovery threshold below.'
  )
);
children.push(...figure('04-add-native-device-form.png', 'Adding a ZRDCP-native device'));
children.push(...figure('05-add-remote-device-form.png', 'Adding a remote ZRDCP-native device'));
children.push(
  p('FIDO2 devices are registered the same way, with real hardware ceremonies still simulated for now (see §4):')
);
children.push(...figure('06-add-fido2-device-form.png', 'Adding a FIDO2/WebAuthn device'));
children.push(
  p(
    "The Trusted Devices tab also shows Alice's own device identity (the public key other vaults would enroll to trust *her*) and the current device list:"
  )
);
children.push(...figure('07-device-list.png', 'Trusted device list'));

children.push(heading('3.4 Mesh size and unlock policy', HeadingLevel.HEADING_2));
children.push(
  p(
    'Back on Vault settings, "Mesh & threshold" configures how large this vault\'s mesh is allowed to grow (4–9 devices) and the two separate thresholds: how many devices must approve a live authentication check, and how many real shares (with how many required to be remote) a recovery needs.'
  )
);
children.push(...figure('08-mesh-threshold-config.png', 'Mesh & threshold configuration'));
children.push(
  p(
    '"Vault security" is where the unlock policy itself is chosen — passphrase only, passphrase plus a live authentication check-in, or recovery-only with no passphrase at all:'
  )
);
children.push(...figure('09-vault-security-policy-selector.png', 'Vault security policy selector'));

children.push(heading('3.5 Duress passcode', HeadingLevel.HEADING_2));
children.push(
  p(
    'A separate, optional passcode can be set for use under coercion. Entering it instead of a real runtime code produces a session that looks and behaves exactly like a genuine success — nothing real is computed or sent — while silently recording the event in this vault\'s own history, visible only after a genuine sign-in (§3.9).'
  )
);
children.push(...figure('10-duress-passcode-section.png', 'Duress and authentication passcode settings'));

children.push(heading('3.6 Multiple vaults, and a real trusted-device mesh', HeadingLevel.HEADING_2));
children.push(
  p(
    'Any number of independently named vaults can coexist in the same browser. Three more — Bob, Carol, and Dave — are created here specifically so they can act as **real** responders to Alice\'s requests below, rather than a simulation:'
  )
);
children.push(...figure('11-sign-on-multiple-vaults.png', 'Sign On screen with multiple vaults'));
children.push(
  p(
    "Once Bob, Carol, and Dave's own identity public keys are enrolled as Alice's trusted devices (Dave flagged remote), Alice's mesh recognizes each of them as a real local vault — not just a name — which is what makes the next two sections genuine cryptography rather than a simulated response."
  )
);

children.push(heading('3.7 Real authentication step-up (2-of-3 approval)', HeadingLevel.HEADING_2));
children.push(
  p(
    "With Alice's unlock policy set to require a live authentication check-in, locking and unlocking her vault now dispatches a real request to her trusted devices:"
  )
);
children.push(...figure('12-auth-stepup-dispatch.png', 'Authentication step-up dispatch'));
children.push(
  p(
    "Each responder sees the pending request in their own vault's Requests → Responses tab, and genuinely approves or denies it:"
  )
);
children.push(...figure('13-responder-mode-pending-authentication-request.png', "A pending authentication request in Bob's Responder inbox"));
children.push(p('Once two of the three real approvals are in, Alice\'s vault reflects it and lets her continue:'));
children.push(...figure('14-auth-stepup-granted.png', 'Authentication step-up granted'));

children.push(heading('3.8 Real recovery reconstruction (3-of-3, including the required remote device)', HeadingLevel.HEADING_2));
children.push(
  p(
    "Switching Alice's vault to recovery-only unlock protects its key with a genuine Shamir split across her mesh — from this point there's no passphrase for this vault at all. Locking it and initiating recovery dispatches a real request to every share-holding device:"
  )
);
children.push(...figure('15-recovery-unlock-dispatch.png', 'Recovery unlock dispatch'));
children.push(...figure('16-responder-mode-pending-recovery-request.png', "A pending recovery request in a responder's inbox"));
children.push(
  p(
    'Each of Bob, Carol, and Dave genuinely decrypts and contributes their own real Shamir share — nothing is simulated here. Once all three responses are in (including Dave, the required remote responder), Alice\'s vault can really reconstruct its key and open:'
  )
);
children.push(...figure('17-recovery-unlock-ready.png', 'Recovery unlock ready to open'));

children.push(heading('3.9 Proving yourself to another application: Create Challenge and Responses', HeadingLevel.HEADING_2));
children.push(
  p(
    "Separately from unlocking her own vault, Alice can prove herself to some *other* application that has issued her a challenge. The Requests tab's **Create Challenge** sub-tab starts one:"
  )
);
children.push(...figure('18-requests-create-challenge.png', 'Create a challenge'));
children.push(
  p(
    "Submitting a challenge switches straight to the **Responses** sub-tab, which is where *every* response-type interaction lives — requests awaiting Alice's own response, and every challenge she's initiated herself, together in one place:"
  )
);
children.push(...figure('19-requests-outgoing-dispatch.png', "Challenges you've initiated, with dispatch rows"));
children.push(
  p(
    '**Runtime-challenge response authentication.** Every device a challenge is dispatched to must independently type back the *exact* runtime code Alice used — an explicit, real-time authentication step layered on top of (not replacing) the underlying cryptographic proof. A device that "responds" with the wrong code — or the right code typed by someone who was never told it — does not count toward the threshold:'
  )
);
children.push(...figure('20-runtime-challenge-outcome-denied.png', 'Runtime-challenge response denied — wrong code entered'));
children.push(p('Typed correctly by enough responders, the same challenge is granted:'));
children.push(...figure('21-runtime-challenge-outcome-granted.png', 'Runtime-challenge response granted — correct code entered'));

children.push(heading('3.10 Duress passcode in action', HeadingLevel.HEADING_2));
children.push(
  p(
    'Entering the duress passcode configured earlier (§3.5), instead of a real runtime code, produces a session shaped identically to a real one — same dispatch rows, same controls — but touches no real cryptography or dispatch, and always reports success:'
  )
);
children.push(...figure('22-duress-decoy-session.png', 'A duress-triggered decoy session'));
children.push(
  p("The only trace is a silent entry in this vault's own history, readable only after a genuine sign-in as its owner:")
);
children.push(...figure('23-history-log.png', 'Vault history log, including the duress trigger'));

children.push(heading('3.11 In-app help, and locking up', HeadingLevel.HEADING_2));
children.push(
  p('An in-app Help tab explains every tab in practical terms, including how to set up real email/SMS sending:')
);
children.push(...figure('24-help-tab.png', 'The in-app Help tab'));
children.push(p('And, as always, locking a vault returns to the Sign On screen with nothing decrypted in memory:'));
children.push(...figure('25-vault-locked.png', 'A locked vault'));

// 4. Project status
children.push(heading('4. Project status', HeadingLevel.HEADING_1));
children.push(
  p(
    '**IdenTT V1.0.** All of the flows shown above are fully implemented, real (not simulated) where described, and covered by 140 automated tests plus an end-to-end browser smoke test. What remains open for a future release: a live reconstruction state machine for a real *external* application\'s challenge session (today\'s real cryptographic reconstruction covers a vault\'s own recovery-mode unlock; the "Create Challenge" flow\'s outcome check against another application is a policy-level evaluator rather than a live external session), real voice/WebAPI dispatch, real FIDO2/WebAuthn hardware ceremonies (currently simulated behind an interface matching the real one), the dissertation\'s AiTM/TLS-origin binding (meaningful once there\'s a real hosted responder site), and optional desktop packaging. See the root [`README.md`](../README.md) for how to run and test the app as it stands today.'
  )
);

children.push(rule());

// Appendix A
children.push(heading('Appendix A — References', HeadingLevel.HEADING_1));
children.push(subhead('Source specification'));
children.push(
  p(
    '1. Singh, S. *Zero-Knowledge Runtime-Generated Dynamic Challenge Protocol (ZRDCP)* — doctoral dissertation; the source specification this project implements.'
  )
);
children.push(subhead('Underlying cryptographic constructions'));
children.push(
  p("2. Pedersen, T. P. (1991). *Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing.* CRYPTO '91."),
  p('3. Shamir, A. (1979). *How to Share a Secret.* Communications of the ACM, 22(11), 612–613.'),
  p("4. Fiat, A., & Shamir, A. (1986). *How to Prove Yourself: Practical Solutions to Identification and Signature Problems.* CRYPTO '86.")
);
children.push(subhead('Software dependencies and specifications'));
children.push(
  p('5. [`@noble/curves`](https://github.com/paulmillr/noble-curves) — audited, dependency-free elliptic-curve library used for all group arithmetic.'),
  p('6. [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — audited hash function library (SHA3-256, as specified by the protocol).'),
  p('7. [WebAuthn (Web Authentication) specification](https://www.w3.org/TR/webauthn-3/) — W3C Recommendation, the standard IdenTT\'s FIDO2 device type targets.'),
  p('8. [Web Cryptography API specification](https://www.w3.org/TR/WebCryptoAPI/) — W3C Recommendation, used for AES-GCM, PBKDF2/HKDF, and secure random generation.')
);
children.push(subhead('Testing and build tools'));
children.push(
  p('9. [Vitest](https://vitest.dev/) — the unit/integration test runner used throughout.'),
  p("10. [Playwright](https://playwright.dev/) — the end-to-end browser automation used for `scripts/smoke-test-ui.mjs` and this documentation's own screenshots."),
  p("11. [esbuild](https://esbuild.github.io/) — bundles the app's ES modules into the single script a `file://` page can load.")
);
children.push(subhead('Project work product (this repository)'));
children.push(p("12. [`README.md`](../README.md) — this project's own build/run instructions, architecture, and source layout."));

// Appendix B
children.push(heading('Appendix B — Glossary', HeadingLevel.HEADING_1));
children.push(
  bullet('**ZRDCP** — Zero-Knowledge Runtime-Generated Dynamic Challenge Protocol; the protocol this app implements.'),
  bullet('**Runtime code / runtime challenge (`C_r`)** — the secret you type at the moment of a challenge; never stored, only committed to and split.'),
  bullet('**Pedersen commitment** — a cryptographic value that "locks in" a secret without revealing it, which can later be proven to have been computed honestly.'),
  bullet('**NIZK proof (Non-Interactive Zero-Knowledge proof)** — the Fiat-Shamir proof that a device knows the runtime code behind a commitment, without revealing the code itself.'),
  bullet("**Shamir share** — one piece of a secret split via Shamir's Secret Sharing; a threshold of pieces reconstructs the secret, fewer reveal nothing."),
  bullet('**Threshold (`k`-of-`n`)** — the minimum number of trusted devices/shares required, out of the total enrolled.'),
  bullet('**Authentication vs. recovery** — two distinct operations against the same mesh: authentication is a lightweight live-approval quorum with no share math; recovery is the full cryptographic reconstruction, requiring real shares and a minimum number of remote responders.'),
  bullet('**Remote device** — a trusted device flagged as not physically co-located with you; recovery requires a minimum number of responding share-holders to be remote.'),
  bullet('**Vault** — a local, encrypted registry of your trusted devices, thresholds, and history, sealed either by a passphrase or by your own mesh (recovery-only unlock policy).'),
  bullet('**Unlock policy** — how a specific vault unlocks: passphrase only, passphrase plus a live authentication check-in, or recovery-only (no passphrase).'),
  bullet('**Responder Mode / "Awaiting your response"** — the real inbox of requests from other local vaults that trust yours, on the Requests tab\'s Responses sub-tab.'),
  bullet('**Runtime-challenge response authentication** — the requirement that a device responding to a dispatched challenge type back the exact runtime code used, as a live authentication factor on top of the cryptographic proof.'),
  bullet('**Duress passcode** — a second, separate code that, entered instead of your real one, produces an indistinguishable fake "success" while silently logging the event.'),
  bullet('**Decoy session (`DECOY_EXEC`)** — the fake session a duress passcode triggers: shaped like a real one, touching no real cryptography or dispatch, always reporting success.'),
  bullet('**FIDO2 / WebAuthn device** — a hardware authenticator (security key, biometric, etc.) enrolled as a trusted device, either as a real share-holder (`full-share`) or an approval-only vote.')
);

const doc = new Document({
  sections: [
    {
      properties: {
        page: { size: { width: 12240, height: 15840 } }, // US Letter (DXA)
      },
      children,
    },
  ],
  styles: {
    default: {
      document: { run: { size: 22 } }, // 11pt
    },
  },
});

const outPath = path.join(docsDir, 'DOCUMENTATION.docx');
const buffer = await Packer.toBuffer(doc);
fs.writeFileSync(outPath, buffer);
console.log('Wrote', outPath, `(${(buffer.length / 1024).toFixed(0)} KB)`);
