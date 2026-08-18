// IdenTT — browser-wide (not per-vault) directories: which named vaults exist in this browser,
// and which of THIS browser's own vaults owns a given ZRDCP identity public key. The second index
// is what makes Responder Mode real rather than simulated for local testing: when vault "Alice"
// enrolls vault "Bob"'s identity public key as a trusted zrdcp-native device, this index lets
// Alice's dispatch code recognize "this trusted device is actually vault Bob, sitting right here
// in this same browser" and deliver a genuine request into Bob's inbox (see `crossVault.js`)
// instead of only a simulated one.
//
// Deliberately unencrypted — vault *names* and *identity public keys* aren't secret (a public key
// is, by definition, meant to be shared with anyone enrolling that device as a trusted peer), so
// there's no reason these small indexes need to sit behind a passphrase. What's actually sensitive
// (the registry: contact channels, thresholds, device relationships) still only ever lives inside
// each vault's own passphrase/key-sealed blob.

const VAULTS_INDEX_KEY = 'identt.vaults.index.v1';
const IDENTITY_INDEX_KEY = 'identt.identities.index.v1';

async function readJson(storageAdapter, key, fallback) {
  const raw = await storageAdapter.getItem(key);
  return raw === null ? fallback : JSON.parse(raw);
}

/** @returns {{name: string, createdAt: string}[]} */
export async function listVaultNames(storageAdapter) {
  return readJson(storageAdapter, VAULTS_INDEX_KEY, []);
}

export async function registerVaultName(storageAdapter, name) {
  const list = await listVaultNames(storageAdapter);
  if (list.some((v) => v.name === name)) {
    throw new Error(`a vault named "${name}" already exists`);
  }
  list.push({ name, createdAt: new Date().toISOString() });
  await storageAdapter.setItem(VAULTS_INDEX_KEY, JSON.stringify(list));
}

export async function unregisterVaultName(storageAdapter, name) {
  const list = await listVaultNames(storageAdapter);
  await storageAdapter.setItem(VAULTS_INDEX_KEY, JSON.stringify(list.filter((v) => v.name !== name)));
}

/** @returns {Object<string, string>} publicKeyHex -> vaultName */
async function identityMap(storageAdapter) {
  return readJson(storageAdapter, IDENTITY_INDEX_KEY, {});
}

/** Idempotent — safe to call every time a vault is unlocked, not just at creation, so a vault
 * that existed before this index did (or was migrated from the legacy single-vault scheme) gets
 * registered the first time it's next opened. */
export async function registerIdentity(storageAdapter, publicKeyHex, vaultName) {
  const map = await identityMap(storageAdapter);
  map[publicKeyHex] = vaultName;
  await storageAdapter.setItem(IDENTITY_INDEX_KEY, JSON.stringify(map));
}

export async function unregisterIdentitiesForVault(storageAdapter, vaultName) {
  const map = await identityMap(storageAdapter);
  for (const [pubKey, name] of Object.entries(map)) {
    if (name === vaultName) delete map[pubKey];
  }
  await storageAdapter.setItem(IDENTITY_INDEX_KEY, JSON.stringify(map));
}

/** @returns {string|null} the local vault name that owns `publicKeyHex`, or null if it belongs to
 * no vault present in this browser (the normal case — most trusted devices are real external
 * hardware/people, not another local IdenTT vault). */
export async function findVaultNameForPublicKey(storageAdapter, publicKeyHex) {
  const map = await identityMap(storageAdapter);
  return map[publicKeyHex] ?? null;
}
