// IdenTT — DECOY_EXEC: what happens when a challenge on the Requests tab is initiated with the
// vault's duress passcode (src/vault/duress.js) instead of its real runtime code. Builds a session
// object shaped EXACTLY like `initiateRecovery`'s (src/recovery/initiate.js) — same fields, same
// dispatch-row shape — so the UI renders it with the exact same components
// (`renderRecoveryResults`/`renderOutcome` in src/app/screens/requests.js) and looks identical to
// a real one. The differences are only ever on the inside:
//   - no real Pedersen commitment/NIZK proof is computed, no Shamir split happens, and nothing is
//     ever actually dispatched (real or simulated) — `buildDecoySession` never touches
//     src/dispatch/simulate.js or src/dispatch/realDispatch.js;
//   - `decoyOutcome` always reports success, regardless of what per-device responses the coerced
//     user (or their coercer) picks in the UI, because the entire point of a decoy is that it can't
//     be made to visibly fail.
// The only record of any of this is a `duress-triggered` entry appended to the vault's own history
// (src/vault/history.js) — which, being stored inside the encrypted registry, is silent to anyone
// without genuine owner-level access.

import { generateSessionId } from '../protocol/messages.js';

/**
 * @param {object} args
 * @param {object} args.registry - the open vault's registry (for its device list + thresholds —
 *   used only to make the fake dispatch rows look plausible, never for any real cryptography).
 * @param {'authentication'|'recovery'} [args.purpose]
 * @returns {object} a session shaped like `initiateRecovery`'s return value, plus `decoy: true`.
 */
export function buildDecoySession({ registry, purpose = 'recovery' }) {
  const sessionId = generateSessionId();
  const { kAuthentication, kRecovery, minRemoteForRecovery } = registry.threshold;
  const requiredK = purpose === 'authentication' ? kAuthentication : kRecovery;

  const dispatches = registry.devices.map((device) => {
    const primaryContact = device.contactChannels[0] ?? { kind: 'email', address: '(none)' };
    return {
      deviceId: device.id,
      deviceName: device.name,
      deviceType: device.type,
      channelKind: primaryContact.kind,
      address: primaryContact.address,
      hasShare: device.type === 'zrdcp-native' || device.participationMode === 'full-share',
      isRemote: !!device.isRemote,
      payloadPreview: '(withheld)',
      responderLink: '',
      simulated: true,
    };
  });

  return {
    sessionId,
    contextId: sessionId,
    purpose,
    requiredK,
    minRemoteForRecovery: purpose === 'recovery' ? minRemoteForRecovery : null,
    recoveryInit: { pedersen_commitment: sessionId },
    dispatches,
    decoy: true,
  };
}

/** Always reports a granted outcome, formatted to match evaluateChallengeOutcome's real shape —
 * see src/recovery/evaluateOutcome.js for the honest equivalent this deliberately mirrors. */
export function decoyOutcome(session) {
  const remoteRequired = session.minRemoteForRecovery ?? 0;
  return {
    granted: true,
    purpose: session.purpose,
    requiredK: session.requiredK,
    minRemoteForRecovery: session.minRemoteForRecovery,
    successCount: session.requiredK,
    remoteSuccessCount: remoteRequired,
    reason:
      session.purpose === 'authentication'
        ? `${session.requiredK}/${session.requiredK} required approvals received.`
        : `${session.requiredK}/${session.requiredK} share-holders responded, including ${remoteRequired}/${remoteRequired} required remote device(s).`,
  };
}
