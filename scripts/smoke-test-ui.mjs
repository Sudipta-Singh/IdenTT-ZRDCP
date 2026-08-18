// One-off manual smoke test for the UI, run with:
//   node scripts/smoke-test-ui.mjs
// Not part of `npm test` (Playwright + a real browser is heavier than the unit suite needs) —
// this exists to verify the actual public/index.html works end-to-end via a real Chromium
// instance, since vitest alone never renders DOM/localStorage/WebCrypto together in one page.
//
// Rewritten this session for the 5-component tabbed UI (Sign On / Requests / Vaults / Trusted
// Devices / Help) plus the duress-passcode/decoy mechanism, and again this session for the
// Requests tab's two sub-tabs (Create Challenge / Responses) plus the runtime-challenge response
// authentication step:
//   Part A — Sign On screen basics on a single vault ("Solo"): create via the dropdown's
//            "+ Create a new vault" option, add a device (Trusted Devices tab), lock/unlock
//            (including a wrong-passphrase rejection), reload persistence, and delete-vault UX.
//   Part B — REAL cross-vault Responder Mode, using four vaults (Bob/Carol/Dave/Alice) all living
//            in the same browser storage. Bob/Carol/Dave's own identity public keys are enrolled
//            as Alice's trusted zrdcp-native devices (Dave flagged remote), which is what lets
//            Alice's dispatches land in a REAL inbox for each of them instead of only a simulated
//            one. The script then drives a real 2-of-3 authentication step-up round trip and a
//            real 3-of-3 (incl. 1 remote) Shamir recovery round trip — both via the Requests tab's
//            "Responses" sub-tab, where the real cross-vault inbox now lives.
//   Part C — tab navigation across all 5 components on "Solo", a default authentication code
//            prefilling the Create Challenge sub-tab's runtime-code field, the new
//            runtime-challenge response-authentication step (a real 2-device authentication
//            challenge where one device gets the WRONG code typed back and correctly fails, then
//            a second run where both get the right code and it succeeds), and the full
//            duress-passcode/decoy flow (set a duress passcode, trigger it instead of a real
//            code, confirm the resulting session looks like a normal one and always reports
//            success, then confirm the trigger left a silent entry in the vault's own history).
//            Real email/SMS dispatch (src/dispatch/realDispatch.js + server/) isn't exercised here
//            since it needs the local backend running with real credentials — see server/README.md.
import { chromium } from 'playwright';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const indexPath = path.join(__dirname, '..', 'public', 'index.html');
const url = 'file://' + indexPath;

const browser = await chromium.launch({ executablePath: '/opt/pw-browsers/chromium-1194/chrome-linux/chrome' });
const page = await browser.newPage();
// Expected/benign: every Requests tab render calls checkBackendHealth() (src/dispatch/
// realDispatch.js), which fetch()es the optional local backend's /health endpoint. That call is
// caught in JS (checkBackendHealth never throws), but Chromium still logs the underlying failed
// network request to the console as an 'error' regardless — harmless when, as in this smoke test,
// server/ simply isn't running. Filtered out here so it doesn't mask a real app error.
const IGNORED_CONSOLE_ERROR_PATTERN = /ERR_CONNECTION_REFUSED|Failed to load resource/;
const consoleErrors = [];
page.on('console', (msg) => {
  if (msg.type() === 'error' && !IGNORED_CONSOLE_ERROR_PATTERN.test(msg.text())) consoleErrors.push(msg.text());
});
page.on('pageerror', (err) => consoleErrors.push(String(err)));

// --- small helpers -------------------------------------------------------------------------

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

async function addDemoNativeDevice(name, { remote = false } = {}) {
  await goToTab('Trusted devices');
  const section = page.locator('section:has(h2:has-text("Add a ZRDCP-native device"))');
  await section.locator('button:has-text("Generate demo keypair")').click();
  await section.locator('input[placeholder^="Device name"]').fill(name);
  await section
    .locator('input[placeholder="Contact address (email/phone/URL)"]')
    .fill(`${name.replace(/\s+/g, '-').toLowerCase()}@example.com`);
  if (remote) await section.locator('input[type="checkbox"]').check();
  await section.locator('button:has-text("Add zrdcp-native device")').click();
  await page.waitForSelector(`text=${name}`);
}

async function addTrustedDevice(name, pubkeyHex, { remote = false } = {}) {
  await goToTab('Trusted devices');
  const section = page.locator('section:has(h2:has-text("Add a ZRDCP-native device"))');
  await section.locator('input[placeholder^="Device name"]').fill(name);
  await section
    .locator('input[placeholder="Contact address (email/phone/URL)"]')
    .fill(`${name.replace(/\s+/g, '-').toLowerCase()}@example.com`);
  await section.locator('input[placeholder^="Public key (hex)"]').fill(pubkeyHex);
  if (remote) await section.locator('input[type="checkbox"]').check();
  await section.locator('button:has-text("Add zrdcp-native device")').click();
  await page.waitForSelector(`text=${name}`);
}

function assert(cond, message) {
  if (!cond) throw new Error(message);
}

// ---------------------------------------------------------------------------------------------
// PART A — Sign On screen basics (single vault "Solo")
// ---------------------------------------------------------------------------------------------

await goto();
let firstOptionText = await page.locator('select option').first().textContent();
assert(firstOptionText.includes('(0 available)'), `expected 0 vaults at first boot, got: ${firstOptionText}`);
console.log('✅ Sign On screen shows an empty vault dropdown on first boot');

await createVault('Solo', 'solo-pass-123');
console.log('✅ vault "Solo" created, landed directly in the shell (Requests tab)');

await addDemoNativeDevice('Solo Helper');
let deviceHeading = await page.textContent('h2:has-text("Trusted devices")');
assert(deviceHeading.includes('(1 enrolled'), `expected 1 enrolled device, got: ${deviceHeading}`);
console.log('✅ device added inside a freshly-created vault, via the Trusted Devices tab');

await goAllVaults();
firstOptionText = await page.locator('select option').first().textContent();
assert(firstOptionText.includes('(1 available)'), `expected 1 vault listed, got: ${firstOptionText}`);
assert((await page.locator('select option', { hasText: 'Solo' }).count()) === 1, 'expected "Solo" listed in the dropdown');
console.log('✅ Sign On dropdown lists the created vault');

await openVault('Solo');
let signInHint = await page.textContent('.signon-subsection');
assert(signInHint.includes('Solo'), `expected sign-in panel to name the vault, got: ${signInHint}`);
await unlock('wrong-passphrase');
await page.waitForSelector('text=Wrong passphrase.');
console.log('✅ wrong passphrase correctly rejected on the per-vault sign-in panel');
await unlock('solo-pass-123');
await page.waitForSelector('h2:has-text("Create a challenge")');
await goToTab('Trusted devices');
deviceHeading = await page.textContent('h2:has-text("Trusted devices")');
assert(deviceHeading.includes('(1 enrolled'), `expected device to persist across lock/unlock, got: ${deviceHeading}`);
console.log('✅ correct passphrase unlocks; enrolled device persisted (vault encryption round-trip)');

await goAllVaults();
await createVault('Temp', 'temp-pass-123');
await goAllVaults();
{
  await openVault('Temp');
  await page.click('button:has-text("Delete this vault")');
  await page.click('button:has-text("Really delete")');
  await page.waitForSelector('h2:has-text("How signing in works")');
  const stillThere = await page.locator('select option', { hasText: 'Temp' }).count();
  assert(stillThere === 0, 'expected "Temp" vault to be gone after confirming deletion');
}
console.log('✅ vault deletion (inline confirm, no window.confirm) removes the vault from the dropdown');

// ---------------------------------------------------------------------------------------------
// PART B — real cross-vault Responder Mode (Bob, Carol, Dave, Alice)
// ---------------------------------------------------------------------------------------------

await createVault('Bob', 'bob-pass-123');
const bobPubkey = await getOwnPubkey();
await goAllVaults();
await createVault('Carol', 'carol-pass-123');
const carolPubkey = await getOwnPubkey();
await goAllVaults();
await createVault('Dave', 'dave-pass-123');
const davePubkey = await getOwnPubkey();
await goAllVaults();
await createVault('Alice', 'alice-pass-123');
console.log('✅ four vaults created (Bob, Carol, Dave, Alice), each with its own real identity keypair');

await addTrustedDevice('Bob device', bobPubkey, { remote: false });
await addTrustedDevice('Carol device', carolPubkey, { remote: false });
await addTrustedDevice('Dave device', davePubkey, { remote: true });
deviceHeading = await page.textContent('h2:has-text("Trusted devices")');
assert(deviceHeading.includes('(3 enrolled, 3 share-holding)'), `expected 3 share-holding devices, got: ${deviceHeading}`);
console.log("✅ Bob/Carol/Dave's real identity public keys enrolled as Alice's trusted devices (Dave flagged remote)");

// --- Authentication step-up: real 2-of-3 approval round trip ---------------------------------

{
  await goToTab('Vault settings');
  const security = page.locator('section:has(h2:has-text("Vault security"))');
  await security.locator('select').selectOption('authentication');
  await security.locator('button:has-text("Update unlock policy")').click();
  await page.waitForSelector('text=Unlock policy set to "authentication".');
}
console.log('✅ Alice switched to "authentication" unlock policy');

await page.click('button:has-text("Lock")');
let policyHint = await page.textContent('.signon-subsection');
assert(policyHint.includes('live authentication check-in'), `expected authentication policy hint, got: ${policyHint}`);
await unlock('alice-pass-123');
await page.waitForSelector('text=step-up authentication required');
let approvalStatus = await page.textContent('.recovery-results .hint');
assert(approvalStatus.includes('0/2 real approvals collected'), `expected 0/2 approvals initially, got: ${approvalStatus}`);
await page.click('button:has-text("Notify local responders")');
await page.waitForSelector('text=Notified local responder vault(s)');
assert(await page.isDisabled('button:has-text("Continue")'), 'expected Continue to be disabled before any approvals');
console.log('✅ Alice (locked, authentication policy) dispatched a real step-up request to Bob, Carol, and Dave');

async function respondToAlice(vaultName, passphrase, action, expectedLabelFragment) {
  await goto();
  await openVault(vaultName);
  await unlock(passphrase);
  await page.waitForSelector('h2:has-text("Create a challenge")'); // Requests tab loaded (default sub-tab)
  await goToSubTab('Responses');
  await page.waitForSelector('h2:has-text("Awaiting your response")');
  const row = page.locator('#responder-inbox .dispatch-row', { hasText: 'Alice' });
  await row.waitFor();
  const rowText = await row.textContent();
  assert(rowText.includes(expectedLabelFragment), `expected ${vaultName}'s inbox row to mention "${expectedLabelFragment}", got: ${rowText}`);
  await row.locator(`button:has-text("${action}")`).click();
  await page.waitForTimeout(200);
  const remaining = await page.locator('#responder-inbox .dispatch-row', { hasText: 'Alice' }).count();
  assert(remaining === 0, `expected the "Alice" request to be gone from ${vaultName}'s inbox after ${action}`);
}

await respondToAlice('Bob', 'bob-pass-123', 'Approve', 'wants a live authentication approval');
console.log("✅ Bob really approved Alice's step-up request via his own Responder Mode");
await respondToAlice('Carol', 'carol-pass-123', 'Approve', 'wants a live authentication approval');
console.log("✅ Carol really approved Alice's step-up request via her own Responder Mode");
await respondToAlice('Dave', 'dave-pass-123', 'Deny', 'wants a live authentication approval');
console.log("✅ Dave denied Alice's step-up request (left unapproved on purpose — 2/2 is already met by Bob+Carol)");

await goto();
await openVault('Alice');
await unlock('alice-pass-123');
await page.waitForSelector('text=step-up authentication required');
await page.click('button:has-text("Check for responses")');
approvalStatus = await page.textContent('.recovery-results .hint');
assert(approvalStatus.includes('2/2 real approvals collected'), `expected 2/2 real approvals, got: ${approvalStatus}`);
assert(!(await page.isDisabled('button:has-text("Continue")')), 'expected Continue to be enabled once 2/2 approvals are in');
await page.click('button:has-text("Continue")');
await page.waitForSelector('h1:has-text("IdenTT — \\"Alice\\"")');
console.log('✅ REAL step-up authentication completed end-to-end (2 genuine cross-vault approvals) — Alice unlocked');

// --- Recovery: real Shamir reconstruction round trip (3-of-3, including the 1 required remote) --

{
  await goToTab('Vault settings');
  const security = page.locator('section:has(h2:has-text("Vault security"))');
  await security.locator('select').selectOption('recovery');
  await security.locator('button:has-text("Update unlock policy")').click();
  await page.waitForSelector('text=Recovery-based unlock enabled');
}
console.log('✅ Alice switched to "recovery" unlock policy (no passphrase from here on) — real Shamir split generated');

await page.click('button:has-text("Lock")');
const holderSummary = await page.textContent('.signon-subsection');
assert(holderSummary.includes('Needs 3 real share-holder responses (of 3 enrolled), including 1 remote'), `unexpected recovery holder summary: ${holderSummary}`);
await page.click('button:has-text("Initiate recovery (notify local responders)")');
await page.waitForSelector('text=Notified local responder vault(s)');
console.log('✅ Alice (locked, recovery policy, no passphrase field at all) dispatched a real recovery request to Bob, Carol, and Dave');

await respondToAlice('Bob', 'bob-pass-123', 'Approve', 'wants your real share');
console.log('✅ Bob really unwrapped and contributed his genuine Shamir share');
await respondToAlice('Carol', 'carol-pass-123', 'Approve', 'wants your real share');
console.log('✅ Carol really unwrapped and contributed her genuine Shamir share');
await respondToAlice('Dave', 'dave-pass-123', 'Approve', 'wants your real share');
console.log('✅ Dave (the required remote holder) really unwrapped and contributed his genuine Shamir share');

await goto();
await openVault('Alice');
await page.click('button:has-text("Check for responses")');
const recoveryStatus = await page.textContent('.recovery-results .hint');
assert(
  recoveryStatus.includes('3/3 real responses collected') && recoveryStatus.includes('1/1 required remote responses collected'),
  `expected 3/3 responses incl. 1/1 remote, got: ${recoveryStatus}`
);
assert(!(await page.isDisabled('button:has-text("Attempt to open")')), 'expected "Attempt to open" to be enabled once the threshold is met');
await page.click('button:has-text("Attempt to open")');
await page.waitForSelector('h1:has-text("IdenTT — \\"Alice\\"")');
console.log('✅ REAL Shamir reconstruction completed end-to-end (3 genuine cross-vault shares, incl. the required remote one) — vault opened with NO passphrase, purely from the reconstructed key');

// ---------------------------------------------------------------------------------------------
// PART C — tab navigation, default authentication code, and duress passcode / decoy (on "Solo")
// ---------------------------------------------------------------------------------------------

await goto();
await openVault('Solo');
await unlock('solo-pass-123');
await page.waitForSelector('h2:has-text("Create a challenge")');

for (const label of ['Requests', 'Vault settings', 'Trusted devices', 'Help']) {
  await goToTab(label);
  assert(await page.locator('button.tab-button.active', { hasText: label }).count() === 1, `expected "${label}" tab to become active`);
}
await page.waitForSelector('h2:has-text("What IdenTT is")');
console.log('✅ all 5 components reachable: Sign On (already exercised above) + the 4 shell tabs');

// Default authentication code convenience field.
await goToTab('Vault settings');
await page.fill('input[placeholder="Default authentication code (optional)"]', 'default-code-1');
await page.click('button:has-text("Save default authentication code")');
await page.waitForSelector('text=Saved.');
await goToTab('Requests');
await goToSubTab('Create Challenge');
const prefilledCode = await page.inputValue('input[placeholder="Runtime code (C_r)"]');
assert(prefilledCode === 'default-code-1', `expected the runtime-code field to be prefilled from the default authentication code, got: "${prefilledCode}"`);
console.log('✅ default authentication code prefills the Create Challenge sub-tab\'s runtime-code field');

// --- Runtime-challenge response authentication: a receiving device must enter the EXACT runtime
// challenge before its response counts, over and above the crypto proof itself. Needs a 2nd
// device on Solo since authentication's default kAuthentication is 2.
await addDemoNativeDevice('Solo Helper 2');
await goToTab('Requests');
await goToSubTab('Create Challenge');
await page.selectOption('section:has(h2:has-text("Create a challenge")) select', 'authentication');
await page.fill('input[placeholder="Runtime code (C_r)"]', 'real-run-code-1');
await page.click('button:has-text("Initiate challenge")');
await page.waitForSelector('button.subtab-button.active:has-text("Responses")');
{
  const outgoingSection = page.locator('section:has(h2:has-text("Challenges you\'ve initiated"))');
  const challengeInputs = outgoingSection.locator('.dispatch-list .dispatch-row input[placeholder^="Enter the exact runtime challenge"]');
  await challengeInputs.first().fill('wrong-code-entirely');
  await challengeInputs.nth(1).fill('real-run-code-1');
  await outgoingSection.locator('button:has-text("Evaluate outcome")').first().click();
  await page.waitForSelector('text=would fail.');
  const denyReason = await outgoingSection.locator('.outcome-result').first().textContent();
  assert(denyReason.includes('Only 1/2'), `expected only the correctly-typed device to count, got: ${denyReason}`);
}
console.log('✅ a receiving device typing the WRONG runtime challenge correctly fails to authenticate, even though it "responded"');

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
}
console.log('✅ both devices typing the exact runtime challenge correctly authenticates and grants the request');

// Duress passcode: set it, then trigger a decoy challenge with it instead of a real code.
await goToTab('Vault settings');
await page.fill('input[placeholder="New duress passcode"]', 'duress-9999');
await page.fill('input[placeholder="Confirm duress passcode"]', 'duress-9999');
await page.click('button:has-text("Set duress passcode")');
await page.waitForSelector('text=Duress passcode set.');
console.log('✅ duress passcode configured');

await goToTab('Requests');
await goToSubTab('Create Challenge');
await page.fill('input[placeholder="Runtime code (C_r)"]', 'duress-9999');
await page.click('button:has-text("Initiate challenge")');
await page.waitForSelector('button.subtab-button.active:has-text("Responses")');
await page.waitForSelector('text=Session');
const dispatchRowCount = await page.locator('.dispatch-list .dispatch-row').count();
assert(dispatchRowCount >= 1, 'expected the decoy session to render at least one dispatch row, same as a real session would');
const dispatchRowText = await page.locator('.recovery-results .dispatch-list').first().textContent();
assert(!dispatchRowText.includes('Responder link'), 'decoy dispatch rows should withhold real payload/link details');
await page.locator('section:has(h2:has-text("Challenges you\'ve initiated")) button:has-text("Evaluate outcome")').first().click();
await page.waitForSelector('text=would succeed.');
console.log('✅ duress passcode produced an indistinguishable "success" session instead of a real challenge');

const historyText = await page.textContent('h2:has-text("History")');
assert(historyText.match(/History \((\d+)\)/) && Number(historyText.match(/History \((\d+)\)/)[1]) >= 1, `expected at least 1 history entry, got: ${historyText}`);
const historyBody = await page.locator('section:has(h2:has-text("History"))').textContent();
assert(historyBody.includes('Duress passcode used'), `expected the history log to (silently) record the duress trigger, got: ${historyBody}`);
console.log('✅ the duress trigger was silently recorded in this vault\'s own history — visible only after genuine sign-in, exactly as intended');

// ---------------------------------------------------------------------------------------------

if (consoleErrors.length) {
  console.error('❌ console errors detected:', consoleErrors);
  process.exitCode = 1;
} else {
  console.log('✅ no console errors');
}

await browser.close();
console.log(consoleErrors.length ? '\nSMOKE TEST FAILED' : '\nSMOKE TEST PASSED');
