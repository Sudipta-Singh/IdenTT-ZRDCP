// IdenTT — local simulation harness for "does this combination of device responses satisfy the
// policy," per the user's explicit request: don't stand up an actual second/third device vault to
// test recovery — instead let the Recovery UI (and the smoke test) mark each dispatched device's
// hypothetical response as success/fail, and evaluate the outcome from that.
//
// IMPORTANT — what this deliberately does NOT do: perform real cryptographic reconstruction
// (unwrapShare + Lagrange interpolation). That path is already covered end-to-end by
// test/recovery-initiate.test.js, using key material this module has no business holding (a real
// trusted device's private key never lives in the initiator's vault — that's the entire point of
// asymmetric share wrapping). What genuinely needs testing here, and couldn't be exercised without
// a feature like this, is the POLICY layer: counting successful approvals against kAuthentication/
// kRecovery, and — new in this session — enforcing the "recovery needs at least one remote
// share-holder among the successes" rule. That's pure bookkeeping over the dispatch list + a
// success/fail map, which is exactly what this module is.

/**
 * @param {object} args
 * @param {ReturnType<typeof import('./initiate.js').initiateRecovery>} args.session - the value
 *   `initiateRecovery` resolved to (its `purpose`/`requiredK`/`minRemoteForRecovery`/`dispatches`
 *   are what this function reads — nothing else).
 * @param {Object<string, 'success'|'fail'>} args.responses - deviceId -> outcome, as chosen in
 *   the UI or scripted in the smoke test. Devices with no entry are treated as non-responsive
 *   (same as 'fail' for threshold-counting purposes).
 * @returns {object} outcome details; `granted` is the headline result.
 */
export function evaluateChallengeOutcome({ session, responses }) {
  const successDispatches = session.dispatches.filter((d) => responses[d.deviceId] === 'success');

  if (session.purpose === 'authentication') {
    const successCount = successDispatches.length;
    const granted = successCount >= session.requiredK;
    return {
      granted,
      purpose: 'authentication',
      requiredK: session.requiredK,
      successCount,
      reason: granted
        ? `${successCount}/${session.requiredK} required approvals received.`
        : `Only ${successCount}/${session.requiredK} required approvals received.`,
    };
  }

  // recovery
  const successShareHolders = successDispatches.filter((d) => d.hasShare);
  const successRemoteShareHolders = successShareHolders.filter((d) => d.isRemote);
  const metCount = successShareHolders.length >= session.requiredK;
  const metRemote = successRemoteShareHolders.length >= session.minRemoteForRecovery;
  const granted = metCount && metRemote;

  let reason;
  if (granted) {
    reason = `${successShareHolders.length}/${session.requiredK} share-holders responded, including ${successRemoteShareHolders.length}/${session.minRemoteForRecovery} required remote device(s).`;
  } else if (!metCount) {
    reason = `Only ${successShareHolders.length}/${session.requiredK} required share-holders responded successfully.`;
  } else {
    reason = `${successShareHolders.length}/${session.requiredK} share-holders responded, but only ${successRemoteShareHolders.length}/${session.minRemoteForRecovery} required remote device(s) among them.`;
  }

  return {
    granted,
    purpose: 'recovery',
    requiredK: session.requiredK,
    minRemoteForRecovery: session.minRemoteForRecovery,
    successCount: successShareHolders.length,
    remoteSuccessCount: successRemoteShareHolders.length,
    metCount,
    metRemote,
    reason,
  };
}
