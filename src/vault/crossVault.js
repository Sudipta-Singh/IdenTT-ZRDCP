// IdenTT — the cross-vault "wire" that makes Responder Mode real for local testing: an inbox per
// recipient identity public key, and two small per-vault scratch areas (real reconstruction
// shares collected so far, real authentication approvals collected so far). All of it is
// unencrypted local scratch data, by design:
//   - an inbox entry addressed to a device is either an approval request (nothing secret in it)
//     or a Shamir share already individually ECDH-wrapped toward that one recipient (see
//     `src/crypto/shareWrap.js`) — so leaving the envelope itself unencrypted at rest discloses
//     nothing an eavesdropper on the wrapped ciphertext couldn't already see;
//   - the recipient's plaintext response (an approval flag, or an unwrapped `{x, y}` share) is
//     written back into the REQUESTING vault's own scratch area so that vault's still-locked gate
//     screen can poll for it without needing to unlock anything to check.
//
// This is the real, working substitute for actual network dispatch (email/SMS/webhook — still
// simulated, see `src/dispatch/simulate.js`, and still Phase 6). Two named vaults in the same
// browser can genuinely complete a full request/response/reconstruct round trip through this
// module with no network and no simulation shortcut — see `src/recovery/respond.js` and
// `docs/PLAN.md` §3.3 for how the pieces fit together.

function inboxKeyFor(publicKeyHex) {
  return `identt.inbox.${encodeURIComponent(publicKeyHex)}.v1`;
}
function reconstructionKeyFor(vaultName) {
  return `identt.vault.${encodeURIComponent(vaultName)}.reconstruction.v1`;
}
function authApprovalsKeyFor(vaultName) {
  return `identt.vault.${encodeURIComponent(vaultName)}.authApprovals.v1`;
}

async function readJson(storageAdapter, key, fallback) {
  const raw = await storageAdapter.getItem(key);
  return raw === null ? fallback : JSON.parse(raw);
}

// --- Inbox: pending requests addressed to one identity public key ------------------------------

/**
 * @typedef {object} InboxEntry
 * @property {string} id
 * @property {'vault-unlock-recovery'|'vault-unlock-authentication'} kind
 * @property {string} fromVaultName - which local vault is asking, and where a response gets
 *   written back to.
 * @property {string} deviceId - this entry's id in the ASKING vault's own device registry (so the
 *   response can be attributed to the right mesh member).
 * @property {object|null} wrappedShare - present only for kind 'vault-unlock-recovery'.
 * @property {string} createdAt
 */

export async function pushInbox(storageAdapter, recipientPublicKeyHex, entry) {
  const key = inboxKeyFor(recipientPublicKeyHex);
  const list = await readJson(storageAdapter, key, []);
  list.push(entry);
  await storageAdapter.setItem(key, JSON.stringify(list));
}

/** @returns {InboxEntry[]} */
export async function listInbox(storageAdapter, recipientPublicKeyHex) {
  return readJson(storageAdapter, inboxKeyFor(recipientPublicKeyHex), []);
}

export async function removeInboxEntry(storageAdapter, recipientPublicKeyHex, entryId) {
  const key = inboxKeyFor(recipientPublicKeyHex);
  const list = await readJson(storageAdapter, key, []);
  await storageAdapter.setItem(key, JSON.stringify(list.filter((e) => e.id !== entryId)));
}

// --- Reconstruction: real decrypted shares collected so far, for ONE (locked) vault ------------

/** @returns {{deviceId: string, x: number, y: string}[]} `y` is a decimal-string-encoded BigInt
 * (JSON has no BigInt type — see `src/crypto/shareWrap.js`'s own share (de)serialization for the
 * same convention). */
export async function listReconstructionShares(storageAdapter, vaultName) {
  return readJson(storageAdapter, reconstructionKeyFor(vaultName), []);
}

export async function pushReconstructionShare(storageAdapter, vaultName, { deviceId, x, y }) {
  const key = reconstructionKeyFor(vaultName);
  const list = await readJson(storageAdapter, key, []);
  // A given device only ever contributes one share to a given split — replace, don't duplicate,
  // so re-approving (or a stray double-click) can't skew the collected count.
  const next = list.filter((s) => s.deviceId !== deviceId);
  next.push({ deviceId, x, y: y.toString() });
  await storageAdapter.setItem(key, JSON.stringify(next));
}

export async function clearReconstructionShares(storageAdapter, vaultName) {
  await storageAdapter.removeItem(reconstructionKeyFor(vaultName));
}

// --- Authentication: real approvals collected so far, for ONE (already-unsealed) vault ---------

/** @returns {{deviceId: string, approvedAt: string}[]} */
export async function listAuthApprovals(storageAdapter, vaultName) {
  return readJson(storageAdapter, authApprovalsKeyFor(vaultName), []);
}

export async function pushAuthApproval(storageAdapter, vaultName, { deviceId }) {
  const key = authApprovalsKeyFor(vaultName);
  const list = await readJson(storageAdapter, key, []);
  if (list.some((a) => a.deviceId === deviceId)) return; // already recorded, don't duplicate
  list.push({ deviceId, approvedAt: new Date().toISOString() });
  await storageAdapter.setItem(key, JSON.stringify(list));
}

export async function clearAuthApprovals(storageAdapter, vaultName) {
  await storageAdapter.removeItem(authApprovalsKeyFor(vaultName));
}
