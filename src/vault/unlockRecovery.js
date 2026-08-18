// IdenTT — the crypto behind `recovery`-unlock-policy vaults: protecting a vault not with
// something the owner has to remember, but with a Shamir split across the vault's own trusted
// mesh (the same math Phase 2 built for reconstructing a runtime-entered secret — see
// `src/recovery/initiate.js` — reused here to protect the vault's OWN unlock key instead of a
// value an external application is challenging).
//
// One deliberate difference from `initiate.js`'s external-challenge flow: there is no Pedersen
// commitment or Fiat-Shamir proof here. That machinery exists so a set of RESPONDING nodes can
// verify the INITIATOR genuinely knows a secret it typed in, before releasing anything — it's a
// proof-of-knowledge over a value the user supplies. A vault's unlock key is never typed in by
// anyone; it's generated fresh by this module, so there's nothing to prove knowledge of and no
// phishing-relay risk this step could mitigate. Keeping it out avoids implying a security property
// that isn't actually present for this use case.

import { randomScalar, scalarToHex } from '../crypto/curve.js';
import { split, reconstruct } from '../crypto/shamir.js';
import { wrapShare } from '../crypto/shareWrap.js';
import { shareHoldingDevices, remoteShareHoldingDevices, ecdhPublicKeyForDevice } from '../registry/registry.js';

export class VaultUnlockRecoveryError extends Error {
  constructor(message) {
    super(message);
    this.name = 'VaultUnlockRecoveryError';
  }
}

/**
 * Generates a fresh random vault-unlock key, splits it across the registry's current
 * share-holding devices (sized to `kRecovery`), and wraps one share per device — exactly like a
 * RECOVERY_INIT dispatch, but the "secret" is this vault's own future encryption key rather than a
 * user-typed runtime code, and the split is persisted (see `src/vault/meta.js`) rather than only
 * dispatched once. Call this from an ALREADY-UNLOCKED vault (you need `registry.localIdentity` to
 * wrap shares, and you need the mesh to be real) when the user opts into recovery-based unlock, or
 * again later via `regenerateRecoverySplit`-style re-invocation after the mesh changes.
 *
 * @param {object} args
 * @param {object} args.registry - the unlocked registry (must include `localIdentity`).
 * @returns {Promise<{ keyHex: string, recoverySplit: object }>} `keyHex` is the new vault
 *   encryption key (32-byte scalar, hex) — caller re-seals the vault with it
 *   (`src/vault/vault.js`'s `sealWithKey`) and must NOT persist `keyHex` itself anywhere;
 *   `recoverySplit` is the JSON-serializable, safe-to-store-in-the-open metadata (see
 *   `src/vault/meta.js`) that lets the mesh reconstruct `keyHex` later.
 */
export async function enableRecoveryUnlock({ registry }) {
  if (!registry.localIdentity) {
    throw new VaultUnlockRecoveryError('this vault has no local device identity yet — cannot wrap shares');
  }
  const { kRecovery, minRemoteForRecovery } = registry.threshold;
  const holders = shareHoldingDevices(registry);
  if (holders.length < kRecovery) {
    throw new VaultUnlockRecoveryError(
      `only ${holders.length} share-holding device(s) enrolled, but recovery-unlock requires ${kRecovery} — enroll more zrdcp-native or PRF-capable fido2 devices, or lower kRecovery first.`
    );
  }
  const remoteHolders = remoteShareHoldingDevices(registry);
  if (remoteHolders.length < minRemoteForRecovery) {
    throw new VaultUnlockRecoveryError(
      `recovery-unlock requires at least ${minRemoteForRecovery} remote share-holding device(s), but only ${remoteHolders.length} are enrolled/flagged remote.`
    );
  }

  // The vault's brand-new unlock key — high-entropy already, so (unlike H(C_r) in the external
  // flow) it needs no hashing before being split; it IS the value being protected.
  const secretScalar = randomScalar();
  const shares = split(secretScalar, { n: holders.length, k: kRecovery });

  const wrappedShares = [];
  for (let i = 0; i < holders.length; i++) {
    const device = holders[i];
    const wrapped = await wrapShare({
      share: shares[i],
      senderIdentity: registry.localIdentity,
      recipientPublicKeyHex: ecdhPublicKeyForDevice(device),
    });
    wrappedShares.push({
      deviceId: device.id,
      deviceName: device.name,
      devicePublicKeyHex: ecdhPublicKeyForDevice(device),
      isRemote: Boolean(device.isRemote),
      wrapped,
    });
  }

  return {
    keyHex: scalarToHex(secretScalar),
    recoverySplit: {
      kRecovery,
      minRemoteForRecovery,
      holderCount: holders.length,
      shares: wrappedShares,
    },
  };
}

/**
 * Given a persisted `recoverySplit` and the real decrypted shares collected so far (from
 * `src/vault/crossVault.js`'s reconstruction scratch area — each one a genuine unwrapped Shamir
 * share, not a simulated approval), checks whether the count + remote-diversity policy is met and,
 * if so, reconstructs the vault's unlock key for real via Lagrange interpolation.
 *
 * @param {object} args
 * @param {object} args.recoverySplit - from `src/vault/meta.js`.
 * @param {{deviceId: string, x: number, y: string}[]} args.collectedShares
 * @returns {{ ok: true, keyHex: string } | { ok: false, reason: string, collectedCount: number,
 *   remoteCollectedCount: number }}
 */
export function attemptReconstruction({ recoverySplit, collectedShares }) {
  const { kRecovery, minRemoteForRecovery, shares: splitShares } = recoverySplit;
  const remoteDeviceIds = new Set(splitShares.filter((s) => s.isRemote).map((s) => s.deviceId));

  // Only count shares that actually belong to THIS split (guards against stale entries left over
  // from a since-regenerated split, where device ids may no longer line up with the same x/share).
  const validDeviceIds = new Set(splitShares.map((s) => s.deviceId));
  const usable = collectedShares.filter((s) => validDeviceIds.has(s.deviceId));

  const collectedCount = usable.length;
  const remoteCollectedCount = usable.filter((s) => remoteDeviceIds.has(s.deviceId)).length;

  if (collectedCount < kRecovery || remoteCollectedCount < minRemoteForRecovery) {
    const parts = [`${collectedCount}/${kRecovery} real responses collected`];
    parts.push(`${remoteCollectedCount}/${minRemoteForRecovery} required remote responses collected`);
    return { ok: false, reason: parts.join(' · '), collectedCount, remoteCollectedCount };
  }

  const points = usable.slice(0, kRecovery).map((s) => ({ x: s.x, y: BigInt(s.y) }));
  const reconstructed = reconstruct(points); // already a properly-reduced scalar (bigint)
  return { ok: true, keyHex: scalarToHex(reconstructed) };
}
