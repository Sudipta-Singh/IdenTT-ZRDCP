// IdenTT — per-vault event history log, stored INSIDE the registry itself (registry.history)
// rather than as a separate storage key. That's a deliberate choice: riding along with the
// vault's existing seal/unseal means a history entry only ever becomes readable to someone who
// has genuinely authenticated as the vault's owner (passphrase, step-up authentication, or a real
// mesh recovery — whichever this vault's unlock policy requires). That's what makes a duress/decoy
// trigger "silently flagged" (see src/vault/duress.js and src/recovery/decoy.js) without needing
// any separate secure side-channel: the flag sits behind the exact same gate as everything else.
//
// Consumed by the Requests/Challenge tab (src/app/screens/requests.js) as the "history" half of
// that component's spec, and also written to by the Vaults and Devices tabs for security-relevant
// changes (policy switches, device enroll/remove, responder approvals) so it reads as a real audit
// trail rather than just a challenge log.

import { makeId } from '../registry/schema.js';

export const HISTORY_KINDS = Object.freeze({
  CHALLENGE_INITIATED: 'challenge-initiated',
  CHALLENGE_OUTCOME: 'challenge-outcome',
  DURESS_TRIGGERED: 'duress-triggered',
  DEVICE_ADDED: 'device-added',
  DEVICE_REMOVED: 'device-removed',
  UNLOCK_POLICY_CHANGED: 'unlock-policy-changed',
  THRESHOLD_UPDATED: 'threshold-updated',
  RESPONDER_APPROVED: 'responder-approved',
  RESPONDER_DENIED: 'responder-denied',
  REAL_DISPATCH_SENT: 'real-dispatch-sent',
});

// Keeps the vault blob from growing without bound over a long real-world lifetime. Oldest entries
// fall off first — `appendHistory` always keeps the most recent MAX_HISTORY_ENTRIES.
const MAX_HISTORY_ENTRIES = 500;

/**
 * Returns a NEW registry (registries are treated as immutable, same convention as registry.js)
 * with one more history entry appended.
 * @param {object} registry
 * @param {{ kind: string, detail?: object }} args
 */
export function appendHistory(registry, { kind, detail = {} }) {
  const entry = { id: makeId('hist'), kind, detail, at: new Date().toISOString() };
  const history = [...(registry.history ?? []), entry].slice(-MAX_HISTORY_ENTRIES);
  return { ...registry, history };
}

/** @returns {{id: string, kind: string, detail: object, at: string}[]} newest first. */
export function listHistory(registry) {
  return [...(registry.history ?? [])].reverse();
}

export function clearHistory(registry) {
  return { ...registry, history: [] };
}
