// IdenTT — per-vault metadata that must be readable BEFORE the vault is unlocked: which unlock
// policy it uses, and — for a `recovery`-policy vault — the persisted, per-device-wrapped Shamir
// split of its own unlock key. Deliberately unencrypted, stored alongside (not inside) the sealed
// vault blob, for the same reason `directory.js` is unencrypted: you can't ask "which challenge do
// I need to pass to open this vault" from data that's itself locked behind that challenge — and
// each individual wrapped share here is already encrypted toward its one intended recipient
// device's public key (see `src/crypto/shareWrap.js`), so leaving the envelope itself in the open
// discloses nothing an attacker couldn't derive from the registry's device list anyway.

export const UNLOCK_POLICIES = Object.freeze({
  PASSPHRASE: 'passphrase',
  AUTHENTICATION: 'authentication',
  RECOVERY: 'recovery',
});

function metaKeyFor(vaultName) {
  return `identt.vault.${encodeURIComponent(vaultName)}.meta.v1`;
}

const DEFAULT_META = { unlockPolicy: UNLOCK_POLICIES.PASSPHRASE, recoverySplit: null };

/**
 * @returns {{ unlockPolicy: 'passphrase'|'authentication'|'recovery', recoverySplit: null | {
 *   kRecovery: number, minRemoteForRecovery: number, holderCount: number,
 *   shares: { deviceId: string, deviceName: string, devicePublicKeyHex: string, isRemote: boolean,
 *             wrapped: object }[]
 * } }}
 */
export async function getVaultMeta(storageAdapter, vaultName) {
  const raw = await storageAdapter.getItem(metaKeyFor(vaultName));
  return raw === null ? { ...DEFAULT_META } : JSON.parse(raw);
}

export async function setVaultMeta(storageAdapter, vaultName, meta) {
  await storageAdapter.setItem(metaKeyFor(vaultName), JSON.stringify(meta));
}

export async function deleteVaultMeta(storageAdapter, vaultName) {
  await storageAdapter.removeItem(metaKeyFor(vaultName));
}
