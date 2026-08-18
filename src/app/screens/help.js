// IdenTT — Component 5: the Help tab. Inline, practical documentation covering each of the other
// four components plus how to set up real email/SMS sending — adapted from docs/DOCUMENTATION.md
// rather than just linking out to it, per the requirement that this explain "how to use the app"
// from inside the app itself. Static content; no state reads needed.

import { el } from '../ui.js';

function section(title, paragraphs) {
  return el('section', { className: 'card' }, [
    el('h2', { textContent: title }),
    ...paragraphs.map((p) => el('p', { className: 'hint', textContent: p })),
  ]);
}

export async function renderHelpTab(container) {
  container.innerHTML = '';
  container.append(
    section('What IdenTT is', [
      'IdenTT is a local, offline-first implementation of the Zero-Knowledge Runtime-Generated Dynamic Challenge Protocol (ZRDCP): a way to authenticate or recover access to an account using a threshold of trusted devices instead of (or in addition to) a single password, without ever exposing your real secret to any one device or server.',
      'Everything runs in your browser and, optionally, a small local backend you run yourself for real email/SMS. Nothing is sent to any third party unless you explicitly configure that backend.',
    ]),
    section('1. Signing on', [
      'The Sign On screen is the only screen you see before unlocking a vault. Pick a vault from the dropdown to see its sign-in options, or choose "+ Create a new vault" to start fresh.',
      'Authentication mode: enter the vault\'s passphrase. If the vault also requires a live authentication check-in (its own "devices required to authenticate" quorum, set on the Vaults tab), you\'ll be asked to collect that many real approvals from other local vaults next, before it opens.',
      'Recovery mode: for a vault with no passphrase at all. Its unlock key is protected by a real Shamir secret split across its trusted-device mesh — generated once when you switch a vault to this mode (Vaults tab) and reconstructed for real once enough of those devices respond with their genuine shares.',
      'Deleting a vault (from its sign-in panel) removes it and its local scratch data permanently — this cannot be undone.',
    ]),
    section('2. Requests tab', [
      'Two sub-tabs live here: Create Challenge, and Responses. History (below both) is a running log of challenges, responses, and security-relevant changes for this vault, newest first — stored inside the vault itself, so it\'s only ever visible once you\'ve genuinely signed in.',
      'Create Challenge: for proving yourself to some OTHER application that issued a challenge — not for unlocking the vault you\'re currently in (see Vault security below for that). Choose Authentication (a lightweight quorum check) or Recovery (computes a Pedersen commitment + zero-knowledge proof and splits it across your share-holding devices, requiring at least one remote responder). Submitting takes you straight to Responses to track it.',
      'Runtime-challenge response authentication: every device a challenge is dispatched to must independently enter the EXACT runtime code you used before its response counts — a manual, real-time authentication step (you\'d tell trusted responders the code directly, e.g. by phone) that sits on top of, not instead of, the Pedersen/NIZK cryptographic proof. Typing the wrong code, or nothing, means that device\'s response doesn\'t count toward the threshold even though it "responded."',
      'Responses — "Awaiting your response": requests from OTHER local vaults in this same browser that have enrolled this vault as one of their trusted devices. Approving a recovery request really decrypts your genuine Shamir share using this vault\'s own private key — nothing here is simulated.',
      'Responses — "Challenges you\'ve initiated": every challenge you\'ve started this browser session, each with its dispatch rows, the runtime-challenge entry field described above, and an "Evaluate outcome" button. If you\'ve run the local backend (see "Real email/SMS" below), email and SMS rows also get a "Send for real" button that actually delivers the request.',
    ]),
    section('3. Vaults tab', [
      'Vault security: choose how this vault unlocks — passphrase only, passphrase plus a live authentication check-in, or recovery-only (no passphrase, mesh-protected). Switching to recovery-only generates a fresh Shamir split across your currently enrolled share-holding devices; regenerate it any time your mesh changes.',
      'Mesh & threshold: set the target/max number of trusted devices for this vault\'s mesh (4-9), how many devices must approve an authentication check, how many must contribute real shares to a recovery, and how many of those must be flagged remote.',
      'Default authentication code: an optional convenience that prefills the Requests tab\'s runtime-code field. It changes nothing about how a challenge is computed and can always be overridden per attempt.',
      'Duress passcode: a separate secret you can enter INSTEAD of your real runtime code on the Requests tab if you\'re ever forced to authenticate under coercion. Doing so produces a fake "success" that looks identical to a real one — nothing real is sent, decrypted, or reconstructed — while silently recording the event in this vault\'s own history, visible only to you, only after you\'ve genuinely signed in later. Set it here in advance; it\'s useless if configured only after the fact.',
    ]),
    section('4. Trusted Devices tab', [
      'Your device identity: this vault\'s own ZRDCP public key, generated once when the vault was created. Share it with anyone who wants to enroll YOU as one of their trusted devices. The matching private key never leaves this vault.',
      'Trusted devices: the current mesh, and a Remove button for each. Add a ZRDCP-native device (another IdenTT vault or client — paste its public key, or generate a demo keypair for local testing) or a FIDO2/WebAuthn device (currently simulated pending real hardware ceremonies).',
      'A device flagged "remote" counts toward the "minimum remote" recovery requirement on the Vaults tab — the rule that stops someone from recovering your account just by possessing every device that happens to be sitting next to you.',
    ]),
    section('Real email & SMS', [
      'By default every challenge uses SIMULATED dispatch — no message actually leaves your machine, and you manually mark each device\'s response for testing. To send for real, run the small local backend included in the server/ folder: cd server, npm install, cp .env.example .env, fill in your own SMTP (email) and/or Twilio (SMS) credentials, then npm start.',
      'That backend is the only place real credentials ever live — the browser app never sees them, it only calls the backend\'s /send-email and /send-sms endpoints over localhost. You can configure just email, just SMS, both, or neither; whichever is left unconfigured simply reports that it\'s not set up yet when you try to use it.',
      'The backend has no authentication of its own and is meant to run only on your own machine — see server/README.md before considering exposing it any other way.',
    ]),
    section('Security model, briefly', [
      'No single device — including this one — ever holds enough information alone to impersonate you. Recovery requires a real threshold of independently-held Shamir shares, each individually encrypted toward its holder\'s own key; authentication requires a real threshold of live approvals. A vault\'s registry (devices, thresholds, history) only ever exists in plaintext behind whatever unlock policy currently protects that vault.',
    ])
  );
}
