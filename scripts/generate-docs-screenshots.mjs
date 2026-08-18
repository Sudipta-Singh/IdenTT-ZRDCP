// Drives the real built app (public/index.html) through headless Chromium and captures focused,
// section-scoped screenshots at each key phase of the user flow, for use in
// docs/DOCUMENTATION.md. Not part of `npm test` — this is a documentation-generation utility, run
// on demand with:
//   node scripts/generate-docs-screenshots.mjs
// Re-run after any UI change to keep the documentation's screenshots current.
//
// Rewritten for V1 (session 8): the app is now the 5-component tabbed shell (Sign On / Requests /
// Vaults / Trusted Devices / Help) rather than the old single long screen, so this walkthrough —
// like `scripts/smoke-test-ui.mjs`, which it mirrors closely for navigation — follows one
// character (Alice) through vault creation, device enrollment, mesh/threshold and security-policy
// configuration, and the duress passcode; then a real cross-vault Responder Mode round trip with
// Bob/Carol/Dave (three more named vaults sharing this same browser's storage) covering both a
// real 2-of-3 authentication step-up and a real 3-of-3 Shamir recovery reconstruction; then the
// Requests tab's Create Challenge / Responses split, including the new runtime-challenge response
// authentication step (a receiving device must type back the exact runtime code before its
// response counts) and the duress/decoy flow. "Switching devices" between vaults is done with a
// fresh `page.goto()` load, exactly as the smoke test does, mirroring a real responder answering
// from their own separate device/app instance.
import { chromium } from 'playwright';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const indexPath = path.join(__dirname, '..', 'public', 'index.html');
const url = 'file://' + indexPath;
const outDir = path.join(__dirname, '..', 'docs', 'screenshots');
fs.mkdirSync(outDir, { recursive: true });
// Start from a clean slate — old filenames from a previous run shouldn't linger if this session's
// set is smaller, renamed, or reordered.
for (const f of fs.readdirSync(outDir)) fs.unlinkSync(path.join(outDir, f));

const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' });
// Content column is CSS max-width: 640px, centered — a 760-wide viewport keeps a little margin
// without wasting space on the dark background either side.
const page = await browser.newPage({ viewport: { width: 760, height: 1000 } });

let shotCount = 0;
async function shot(name) {
  shotCount += 1;
  const numbered = `${String(shotCount).padStart(2, '0')}-${name}`;
  await page.screenshot({ path: path.join(outDir, numbered) }); // viewport-only, not fullPage
  console.log('📸', numbered);
}

/** Scrolls a section's heading to the top of the viewport before capturing, so each screenshot
 * frames one feature instead of an ever-growing full-page dump. */
async function scrollTo(selector, block = 'start') {
  await page.locator(selector).first().evaluate((el, block) => el.scrollIntoView({ block, behavior: 'instant' }), block);
  await page.waitForTimeout(80); // let layout settle
}

// --- helpers shared in spirit with scripts/smoke-test-ui.mjs -------------------------------

async function goto() {
  await page.goto(url);
  await page.waitForSelector('h2:has-text("How signing in works")');
}
async function createVault(name, passphrase) {
  await page.selectOption('select', '__create__');
  await page.waitForSelector('h3:has-text("Create a new vault")');
  await page.fill('input[placeholder^="Vault name"]', name);
  await page.fill('input[placeholder="Passphrase"]', passphrase);
  await page.fill('input[placeholder="Confirm passphrase"]', passphrase);
  await page.click('button:has-text("Create vault")');
  await page.waitForSelector('h2:has-text("Create a challenge")');
}
async function openVault(name) {
  await page.selectOption('select', name);
  await page.locator('h3', { hasText: `Sign in to "${name}"` }).waitFor();
}
async function unlock(passphrase) {
  await page.fill('input[placeholder="Passphrase"]', passphrase);
  await page.click('button:has-text("Unlock")');
}
async function goAllVaults() {
  await page.click('button:has-text("All vaults")');
  await page.waitForSelector('h2:has-text("How signing in works")');
}
async function goToTab(label) {
  await page.click(`button.tab-button:has-text("${label}")`);
}
async function goToSubTab(label) {
  await page.click(`button.subtab-button:has-text("${label}")`);
}
async function getOwnPubkey() {
  await goToTab('Trusted devices');
  await page.waitForSelector('h2:has-text("Your device identity")');
  return page.inputValue('section:has(h2:has-text("Your device identity")) input');
}
async function addTrustedDevice(name, pubkeyHex, { remote = false } = {}) {
  await goToTab('Trusted devices');
  const section = page.locator('section:has(h2:has-text("Add a ZRDCP-native device"))');
  await section.locator('input[placeholder^="Device name"]').fill(name);
  await section.locator('input[placeholder="Contact address (email/phone/URL)"]').fill(`${name.replace(/\s+/g, '-').toLowerCase()}@example.com`);
  await section.locator('input[placeholder^="Public key (hex)"]').fill(pubkeyHex);
  if (remote) await section.locator('input[type="checkbox"]').check();
  await section.locator('button:has-text("Add zrdcp-native device")').click();
  await page.waitForSelector(`text=${name}`);
}

// =============================================================================================
// PART 1 — Sign On, and Alice's own vault: creation, device enrollment, mesh/threshold, security.
// =============================================================================================

await goto();
await shot('sign-on-empty.png');

await page.selectOption('select', '__create__');
await page.waitForSelector('h3:has-text("Create a new vault")');
await page.fill('input[placeholder^="Vault name"]', 'Alice');
await page.fill('input[placeholder="Passphrase"]', 'alice-demo-pass-123');
await page.fill('input[placeholder="Confirm passphrase"]', 'alice-demo-pass-123');
await shot('sign-on-create-vault-form.png');
await page.click('button:has-text("Create vault")');
await page.waitForSelector('h2:has-text("Create a challenge")');

await goToTab('Vault settings');
await scrollTo('h2:has-text("Vault security")');
await shot('fresh-vault-warnings.png'); // a brand-new vault has no devices yet — Vault security + warnings visible together

await goToTab('Trusted devices');
await scrollTo('h2:has-text("Add a ZRDCP-native device")');
{
  const section = page.locator('section:has(h2:has-text("Add a ZRDCP-native device"))');
  await section.locator('button:has-text("Generate demo keypair")').click();
  await section.locator('input[placeholder^="Device name"]').fill("Spouse's phone");
  await section.locator('input[placeholder="Contact address (email/phone/URL)"]').fill('spouses-phone@example.com');
  await shot('add-native-device-form.png');
  await section.locator('button:has-text("Add zrdcp-native device")').click();
  await page.waitForSelector("text=Spouse's phone");
}

{
  const section = page.locator('section:has(h2:has-text("Add a ZRDCP-native device"))');
  await section.locator('button:has-text("Generate demo keypair")').click();
  await section.locator('input[placeholder^="Device name"]').fill('Remote laptop');
  await section.locator('input[placeholder="Contact address (email/phone/URL)"]').fill('remote-laptop@example.com');
  await section.locator('input[type="checkbox"]').check();
  await shot('add-remote-device-form.png');
  await section.locator('button:has-text("Add zrdcp-native device")').click();
  await page.waitForSelector('text=Remote laptop');
}

await scrollTo('h2:has-text("Add a FIDO2/WebAuthn device")');
{
  const section = page.locator('section:has(h2:has-text("Add a FIDO2/WebAuthn device"))');
  await section.locator('input[placeholder^="Device name"]').fill('YubiKey 5C');
  await section.locator('input[placeholder="Contact address (email/phone/URL)"]').fill('yubikey-owner@example.com');
  await shot('add-fido2-device-form.png');
  // Deliberately not submitted — FIDO2 registration is simulated with a randomized full-share vs.
  // approval-only outcome, which would make Alice's later share-holder counts non-deterministic
  // for this walkthrough. The form itself is what's being documented here.
}

await goToTab('Trusted devices');
await scrollTo('h2:has-text("Trusted devices")');
await shot('device-list.png');

await goToTab('Vault settings');
await scrollTo('h2:has-text("Mesh & threshold")');
await shot('mesh-threshold-config.png');

await scrollTo('h2:has-text("Vault security")');
await shot('vault-security-policy-selector.png');

await scrollTo('h2:has-text("Duress & authentication passcodes")');
await shot('duress-passcode-section.png');

// =============================================================================================
// PART 2 — the Sign On screen with more than one vault (Bob, Carol, Dave — real Responder Mode
// participants below, not throwaway fixtures).
// =============================================================================================

await goAllVaults();
await createVault('Bob', 'bob-demo-pass-123');
const bobPubkey = await getOwnPubkey();
await goAllVaults();
await createVault('Carol', 'carol-demo-pass-123');
const carolPubkey = await getOwnPubkey();
await goAllVaults();
await createVault('Dave', 'dave-demo-pass-123');
const davePubkey = await getOwnPubkey();
await goAllVaults();
await shot('sign-on-multiple-vaults.png');

// =============================================================================================
// PART 3 — real cross-vault Responder Mode, step 1: authentication step-up (2-of-3 approval).
// =============================================================================================

await openVault('Alice');
await unlock('alice-demo-pass-123');
await page.waitForSelector('h2:has-text("Create a challenge")');

await addTrustedDevice('Bob device', bobPubkey);
await addTrustedDevice('Carol device', carolPubkey);
await addTrustedDevice('Dave device', davePubkey, { remote: true });

await goToTab('Vault settings');
{
  const security = page.locator('section:has(h2:has-text("Vault security"))');
  await security.locator('select').selectOption('authentication');
  await security.locator('button:has-text("Update unlock policy")').click();
  await page.waitForSelector('text=Unlock policy set to "authentication".');
}

await page.click('button:has-text("Lock")');
await unlock('alice-demo-pass-123');
await page.waitForSelector('text=step-up authentication required');
await page.click('button:has-text("Notify local responders")');
await page.waitForSelector('text=Notified local responder vault(s)');
await shot('auth-stepup-dispatch.png');

async function respondToAlice(vaultName, passphrase) {
  await goto();
  await openVault(vaultName);
  await unlock(passphrase);
  await page.waitForSelector('h2:has-text("Create a challenge")');
  await goToSubTab('Responses');
  await page.waitForSelector('h2:has-text("Awaiting your response")');
  await scrollTo('h2:has-text("Awaiting your response")');
}

/** Clicks Approve on the (first) pending request from Alice, and — since the next step is usually
 * `respondToAlice()` for a different vault, i.e. an immediate `page.goto()` away from this page —
 * waits for the row to actually disappear first. Approving is async (real crypto + a localStorage
 * write); navigating away before that settles can leave a stale inbox entry behind. */
async function approveAliceRequest() {
  const row = page.locator('#responder-inbox .dispatch-row', { hasText: 'Alice' }).first();
  await row.locator('button:has-text("Approve")').click({ timeout: 15000 });
  await row.waitFor({ state: 'detached', timeout: 10000 });
}

await respondToAlice('Bob', 'bob-demo-pass-123');
await shot('responder-mode-pending-authentication-request.png');
await approveAliceRequest();

await respondToAlice('Carol', 'carol-demo-pass-123');
await approveAliceRequest();

// Dave was notified too (every local-vault-backed trusted device is), but 2/2 is already met by
// Bob+Carol — deny his request here so it doesn't linger in his inbox and confuse the later
// recovery round trip below.
await goto();
await openVault('Dave');
await unlock('dave-demo-pass-123');
await page.waitForSelector('h2:has-text("Create a challenge")');
await goToSubTab('Responses');
await page.waitForSelector('h2:has-text("Awaiting your response")');
await page.locator('#responder-inbox .dispatch-row', { hasText: 'Alice' }).locator('button:has-text("Deny")').click();
await page.waitForTimeout(300);

await goto();
await openVault('Alice');
await unlock('alice-demo-pass-123');
await page.waitForSelector('text=step-up authentication required');
await page.click('button:has-text("Check for responses")');
await page.waitForSelector('text=2/2 real approvals collected');
await shot('auth-stepup-granted.png');
await page.click('button:has-text("Continue")');
await page.waitForSelector('h2:has-text("Create a challenge")');

// =============================================================================================
// PART 4 — real cross-vault Responder Mode, step 2: full Shamir reconstruction (3-of-3, incl. the
// required remote responder).
// =============================================================================================

await goToTab('Vault settings');
{
  const security = page.locator('section:has(h2:has-text("Vault security"))');
  await security.locator('select').selectOption('recovery');
  await security.locator('button:has-text("Update unlock policy")').click();
  await page.waitForSelector('text=Recovery-based unlock enabled');
}

await page.click('button:has-text("Lock")');
await page.waitForSelector('button:has-text("Initiate recovery")');
await page.click('button:has-text("Initiate recovery (notify local responders)")');
await page.waitForSelector('text=Notified local responder vault(s)');
await shot('recovery-unlock-dispatch.png');

await respondToAlice('Bob', 'bob-demo-pass-123');
await shot('responder-mode-pending-recovery-request.png');
await approveAliceRequest();

await respondToAlice('Carol', 'carol-demo-pass-123');
await approveAliceRequest();

await respondToAlice('Dave', 'dave-demo-pass-123');
await approveAliceRequest();

await goto();
await openVault('Alice');
await page.click('button:has-text("Check for responses")');
await page.waitForSelector('text=3/3 real responses collected');
await scrollTo('button:has-text("Attempt to open")', 'center');
await shot('recovery-unlock-ready.png');
await page.click('button:has-text("Attempt to open")');
await page.waitForSelector('h2:has-text("Create a challenge")');

// Switch back to a passphrase for the rest of this walkthrough (and so the closing screenshot is
// the familiar passphrase gate) — also demonstrates that a recovery-only vault can always switch
// back once it's open.
await goToTab('Vault settings');
{
  const security = page.locator('section:has(h2:has-text("Vault security"))');
  await security.locator('select').selectOption('passphrase');
  await security.locator('input[placeholder^="New passphrase"]').fill('alice-demo-pass-123');
  await security.locator('button:has-text("Update unlock policy")').click();
  await page.waitForSelector('text=Unlock policy set to "passphrase".');
}

// =============================================================================================
// PART 5 — Create Challenge / Responses: runtime-challenge response authentication, and the
// duress-passcode/decoy flow.
// =============================================================================================

await goToTab('Requests');
await goToSubTab('Create Challenge');
await scrollTo('h2:has-text("Create a challenge")');
await shot('requests-create-challenge.png');

await page.selectOption('section:has(h2:has-text("Create a challenge")) select', 'authentication');
await page.fill('input[placeholder="Runtime code (C_r)"]', 'real-run-code-1');
await page.click('button:has-text("Initiate challenge")');
await page.waitForSelector('button.subtab-button.active:has-text("Responses")');
await scrollTo('h2:has-text("Challenges you\'ve initiated")');
await shot('requests-outgoing-dispatch.png');

{
  const outgoingSection = page.locator('section:has(h2:has-text("Challenges you\'ve initiated"))');
  const challengeInputs = outgoingSection.locator('.dispatch-list .dispatch-row input[placeholder^="Enter the exact runtime challenge"]');
  await challengeInputs.first().fill('wrong-code-entirely');
  await challengeInputs.nth(1).fill('real-run-code-1');
  await outgoingSection.locator('button:has-text("Evaluate outcome")').first().click();
  await page.waitForSelector('text=would fail.');
  await scrollTo('.outcome-result', 'center');
  await shot('runtime-challenge-outcome-denied.png');
}

await goToSubTab('Create Challenge');
await page.selectOption('section:has(h2:has-text("Create a challenge")) select', 'authentication');
await page.fill('input[placeholder="Runtime code (C_r)"]', 'real-run-code-2');
await page.click('button:has-text("Initiate challenge")');
await page.waitForSelector('button.subtab-button.active:has-text("Responses")');
{
  const outgoingSection = page.locator('section:has(h2:has-text("Challenges you\'ve initiated"))');
  const challengeInputs = outgoingSection.locator('.dispatch-list .dispatch-row input[placeholder^="Enter the exact runtime challenge"]');
  await challengeInputs.first().fill('real-run-code-2');
  await challengeInputs.nth(1).fill('real-run-code-2');
  await outgoingSection.locator('button:has-text("Evaluate outcome")').first().click();
  await page.waitForSelector('text=would succeed.');
  await scrollTo('.outcome-result', 'center');
  await shot('runtime-challenge-outcome-granted.png');
}

await goToTab('Vault settings');
await scrollTo('h2:has-text("Duress & authentication passcodes")');
await page.fill('input[placeholder="New duress passcode"]', 'alice-duress-9999');
await page.fill('input[placeholder="Confirm duress passcode"]', 'alice-duress-9999');
await page.click('button:has-text("Set duress passcode")');
await page.waitForSelector('text=Duress passcode set.');

await goToTab('Requests');
await goToSubTab('Create Challenge');
await page.fill('input[placeholder="Runtime code (C_r)"]', 'alice-duress-9999');
await page.click('button:has-text("Initiate challenge")');
await page.waitForSelector('button.subtab-button.active:has-text("Responses")');
await scrollTo('h2:has-text("Challenges you\'ve initiated")');
await shot('duress-decoy-session.png');
await page.locator('section:has(h2:has-text("Challenges you\'ve initiated")) button:has-text("Evaluate outcome")').first().click();
await page.waitForSelector('text=would succeed.');

await scrollTo('h2:has-text("History")');
await shot('history-log.png');

// =============================================================================================
// PART 6 — Help tab, and locking the vault.
// =============================================================================================

await goToTab('Help');
await page.waitForSelector('h2:has-text("What IdenTT is")');
await shot('help-tab.png');

await goToTab('Requests');
await page.click('button:has-text("Lock")');
await page.waitForSelector('button:has-text("Unlock")');
await shot('vault-locked.png');

await browser.close();
console.log('\nAll screenshots written to', outDir);
