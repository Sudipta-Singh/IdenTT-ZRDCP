// IdenTT — Phase 2: challenge initiation & dispatch, for both operations the user asked this
// mechanism to serve:
//   - 'authentication' — a lightweight liveness/consent check for ongoing use. Any kAuthentication
//     devices (any type, any participation mode) approving is enough. No Shamir split — nothing
//     needs reconstructing, so no share ever leaves the device.
//   - 'recovery'       — the dissertation's full flow (§5.2 CHALLENGE_INPUT -> DISPATCH_SHARES).
//     Requires kRecovery real Shamir shares back (only share-holding devices count), with at
//     least minRemoteForRecovery of the responding share-holders flagged `isRemote`.
//
// Reconstruction itself (INTERPOLATING -> AUTHENTICATED) is still Phase 4 territory for a REAL
// session. This module also exposes `evaluateChallengeOutcome` — a policy-only (no decryption)
// simulation harness for locally testing "does this combination of responses satisfy the
// threshold + remote-diversity rules," per the user's request not to stand up real second/third
// device vaults for testing. See evaluateOutcome's own doc for why it doesn't do real
// cryptographic reconstruction.

import { commit, prove } from '../crypto/pedersen.js';
import { split } from '../crypto/shamir.js';
import { wrapShare } from '../crypto/shareWrap.js';
import { buildRecoveryInit, buildShareDelivery, generateSessionId } from '../protocol/messages.js';
import { simulateDispatchToDevice } from '../dispatch/simulate.js';
import { shareHoldingDevices, remoteShareHoldingDevices, ecdhPublicKeyForDevice } from '../registry/registry.js';

export class RecoveryInitiationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RecoveryInitiationError';
  }
}

/**
 * Starts a challenge session for either purpose. Deliberately returns no secret material (not the
 * runtime code, not `m`/`r`, not any plaintext share, not any private key) — only wire-safe
 * messages (each dispatch entry carries its challenge message and, for recovery share-holders,
 * its already-AES-GCM-encrypted SHARE_DELIVERY) and dispatch log entries, matching what a real
 * device would actually have in scope once this function returns.
 *
 * @param {object} args
 * @param {object} args.registry - must have `localIdentity` (see src/vault/store.js).
 * @param {string} args.runtimeEntropy - the user-entered C_r.
 * @param {'authentication'|'recovery'} [args.purpose] - defaults to 'recovery'.
 * @param {string} [args.contextId] - defaults to a fresh random one if omitted.
 * @param {string} [args.certHash] - §4.1 AiTM binding; omitted until Phase 5.
 * @returns {{ sessionId: string, contextId: string, purpose: string, requiredK: number,
 *   minRemoteForRecovery: number|null, recoveryInit: object, dispatches: object[] }}
 */
export async function initiateRecovery({ registry, runtimeEntropy, purpose = 'recovery', contextId, certHash }) {
  if (purpose !== 'authentication' && purpose !== 'recovery') {
    throw new RecoveryInitiationError(`purpose must be 'authentication' or 'recovery', got '${purpose}'`);
  }
  if (!registry.localIdentity) {
    throw new RecoveryInitiationError(
      'this vault has no local device identity yet — reload the vault (VaultStore.load migrates older vaults automatically) before initiating a challenge'
    );
  }
  if (!runtimeEntropy || typeof runtimeEntropy !== 'string') {
    throw new RecoveryInitiationError('runtime code is required');
  }

  const { kAuthentication, kRecovery, minRemoteForRecovery } = registry.threshold;
  const requiredK = purpose === 'authentication' ? kAuthentication : kRecovery;
  const holders = shareHoldingDevices(registry);

  if (purpose === 'authentication') {
    if (registry.devices.length < requiredK) {
      throw new RecoveryInitiationError(
        `only ${registry.devices.length} device(s) enrolled, but authentication requires ${requiredK} approvals — enroll more trusted devices, or lower kAuthentication.`
      );
    }
  } else {
    if (holders.length < requiredK) {
      throw new RecoveryInitiationError(
        `only ${holders.length} share-holding device(s) enrolled, but recovery requires ${requiredK} — recovery cannot proceed. Enroll more zrdcp-native or PRF-capable fido2 devices, or lower kRecovery.`
      );
    }
    const remoteHolders = remoteShareHoldingDevices(registry);
    if (remoteHolders.length < minRemoteForRecovery) {
      throw new RecoveryInitiationError(
        `recovery requires at least ${minRemoteForRecovery} remote share-holding device(s), but only ${remoteHolders.length} enrolled/flagged remote — recovery cannot proceed. Flag an existing share-holding device as remote, enroll another, or lower minRemoteForRecovery.`
      );
    }
  }

  const sessionId = generateSessionId();
  const effectiveContextId = contextId ?? sessionId;

  const { K, m, r } = commit(runtimeEntropy);
  const proof = prove({ m, r, K, contextId: effectiveContextId, certHash });
  const recoveryInit = buildRecoveryInit({
    sessionId,
    K,
    proof,
    contextId: effectiveContextId,
    purpose,
    certHash,
  });

  const dispatches = [];

  if (purpose === 'authentication') {
    // No share math — every device gets the challenge; any kAuthentication approvals suffice.
    for (const device of registry.devices) {
      dispatches.push(
        simulateDispatchToDevice({
          device,
          sessionId,
          purpose,
          recoveryInitMessage: recoveryInit,
          shareDeliveryMessage: null,
        })
      );
    }
  } else {
    // n = the number of devices that can actually hold a share, per §2.2 — not the registry's
    // aspirational targetN, which may not be fully enrolled yet.
    const shares = split(m, { n: holders.length, k: requiredK });

    for (let i = 0; i < holders.length; i++) {
      const device = holders[i];
      const share = shares[i];
      const wrapped = await wrapShare({
        share,
        senderIdentity: registry.localIdentity,
        recipientPublicKeyHex: ecdhPublicKeyForDevice(device),
      });
      const shareDelivery = buildShareDelivery({ sessionId, nodeIndex: share.x, wrapped });
      dispatches.push(
        simulateDispatchToDevice({
          device,
          sessionId,
          purpose,
          recoveryInitMessage: recoveryInit,
          shareDeliveryMessage: shareDelivery,
        })
      );
    }

    const holderIds = new Set(holders.map((d) => d.id));
    for (const device of registry.devices) {
      if (holderIds.has(device.id)) continue; // already dispatched above, with a share
      dispatches.push(
        simulateDispatchToDevice({
          device,
          sessionId,
          purpose,
          recoveryInitMessage: recoveryInit,
          shareDeliveryMessage: null,
        })
      );
    }
  }

  return {
    sessionId,
    contextId: effectiveContextId,
    purpose,
    requiredK,
    minRemoteForRecovery: purpose === 'recovery' ? minRemoteForRecovery : null,
    recoveryInit,
    dispatches,
  };
}
