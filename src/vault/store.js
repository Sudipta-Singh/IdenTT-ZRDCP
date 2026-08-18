// IdenTT — ties one sealed vault (vault.js) to a storage adapter (storage.js) and gives back/
// takes a plain registry object (registry.js). This is the low-level, single-vault engine;
// `src/vault/directory.js` tracks WHICH named vaults exist, and `src/app/main.js` composes the
// two so the app can support multiple named local vaults (added so Responder Mode — see
// src/recovery/respond.js — has a real second party to test against in one browser).

import { seal, open, sealWithKey, openWithKey } from './vault.js';
import { createRegistry } from '../registry/registry.js';
import { generateIdentityKeypair } from '../crypto/curve.js';

/** Storage key for one named vault's sealed blob. `encodeURIComponent` keeps arbitrary vault
 * names (spaces, punctuation, unicode) safe to embed in a localStorage key. Exported so
 * `src/app/main.js` can migrate a legacy (pre-multi-vault) single vault's raw blob straight across
 * without going through seal/open — it's already sealed, it just needs a new home. */
export function storageKeyFor(vaultName) {
  return `identt.vault.${encodeURIComponent(vaultName)}.sealed.v1`;
}

export function createVaultStore(storageAdapter, vaultName) {
  const STORAGE_KEY = storageKeyFor(vaultName);

  return {
    /** True if this named vault has been created before (does not require any secret to check). */
    async exists() {
      return (await storageAdapter.getItem(STORAGE_KEY)) !== null;
    },

    /**
     * Creates a brand-new empty registry, seals it under `passphrase`, and persists it. Overwrites
     * any existing vault of this name. Also generates this device's own persistent ZRDCP identity
     * keypair (`registry.localIdentity`) — distinct from the trusted-device list, which holds
     * OTHER devices' public keys. This is the key every outgoing share gets wrapped with (see
     * src/crypto/shareWrap.js).
     */
    async createNew(passphrase, initialThreshold) {
      const registry = { ...createRegistry(initialThreshold), localIdentity: generateIdentityKeypair() };
      await this.save(passphrase, registry);
      return registry;
    },

    /**
     * Opens the persisted vault with `passphrase`, returning the plain registry object.
     * Transparently migrates older vaults so they keep working without user action:
     *   - vaults created before `localIdentity` existed (Phase 1) get one generated;
     *   - vaults created before the authentication/recovery threshold split existed (Phase 2's
     *     single `threshold.k`) get mapped onto the new shape: `kAuthentication` defaults to 2,
     *     `kRecovery` becomes `max(old k, 3)`, `minRemoteForRecovery` defaults to 1, and
     *     `targetN` gets clamped into the now-required 4-9 range.
     */
    async load(passphrase) {
      const raw = await storageAdapter.getItem(STORAGE_KEY);
      if (raw === null) throw new Error('No vault exists yet — call createNew() first.');
      const sealedVault = JSON.parse(raw);
      const registry = await open(passphrase, sealedVault);
      return this._migrate(registry, (r) => this.save(passphrase, r));
    },

    /** Same as `load()`, but for a `recovery`-unlock-policy vault: opens with a raw HKDF key
     * (see `src/vault/vault.js`'s `sealWithKey`/`openWithKey`) instead of a passphrase — the key
     * a successful mesh reconstruction produces (`src/vault/unlockRecovery.js`). */
    async loadWithKey(keyHex) {
      const raw = await storageAdapter.getItem(STORAGE_KEY);
      if (raw === null) throw new Error('No vault exists yet — call createNew() first.');
      const sealedVault = JSON.parse(raw);
      const registry = await openWithKey(keyHex, sealedVault);
      return this._migrate(registry, (r) => this.saveWithKey(keyHex, r));
    },

    async _migrate(registry, resave) {
      let needsSave = false;
      if (!registry.localIdentity) {
        registry.localIdentity = generateIdentityKeypair();
        needsSave = true;
      }
      if (!registry.threshold || !('kAuthentication' in registry.threshold)) {
        const old = registry.threshold || {};
        registry.threshold = {
          targetN: Math.min(Math.max(old.targetN ?? 6, 4), 9),
          kAuthentication: 2,
          kRecovery: Math.max(old.k ?? 3, 3),
          minRemoteForRecovery: 1,
        };
        registry.version = 2;
        needsSave = true;
      }
      if (needsSave) await resave(registry);
      return registry;
    },

    /** Re-seals `registry` under `passphrase` and persists it, replacing whatever was there. */
    async save(passphrase, registry) {
      const sealedVault = await seal(passphrase, registry);
      await storageAdapter.setItem(STORAGE_KEY, JSON.stringify(sealedVault));
    },

    /** Re-seals `registry` under a raw HKDF key (`recovery`-unlock-policy vaults) and persists it. */
    async saveWithKey(keyHex, registry) {
      const sealedVault = await sealWithKey(keyHex, registry);
      await storageAdapter.setItem(STORAGE_KEY, JSON.stringify(sealedVault));
    },

    async destroy() {
      await storageAdapter.removeItem(STORAGE_KEY);
    },
  };
}

/** The pre-multi-vault (session 1-5) fixed storage key — kept only so `src/app/main.js` can
 * detect and migrate a vault created before this feature existed into the new named-vault scheme
 * (see `migrateLegacyVault` there). Not used for anything new. */
export const LEGACY_SINGLE_VAULT_STORAGE_KEY = 'identt.vault.v1';
