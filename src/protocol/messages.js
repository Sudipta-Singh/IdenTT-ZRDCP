// IdenTT — wire message builders, matching dissertation §5.1 "JSON Message Schemas" as closely as
// possible. Two message types: RECOVERY_INIT (broadcast to every trusted device, carries the
// public commitment + NIZK proof) and SHARE_DELIVERY (sent per-recipient, carries that recipient's
// encrypted share). These are plain JSON-serializable objects — this module has no I/O, dispatch
// (src/dispatch/simulate.js) is what actually "sends" them.

import { pointToHex } from '../crypto/curve.js';

const PROTOCOL_VERSION = 'ZRDCP/1.0';

function hex0x(str) {
  return str.startsWith('0x') ? str : '0x' + str;
}

/**
 * §5.1 "Recovery Initialization Request (RECOVERY_INIT)". One of these is broadcast to every
 * trusted device in the mesh (regardless of device type or participation mode) — it's how each
 * node independently verifies the request is legitimate before doing anything else, per the
 * two-independent-mechanisms design in `test/integration.test.js`.
 *
 * Extended beyond the dissertation's literal schema with a `purpose` field, reflecting the user's
 * requirement that the same commitment/proof mechanism serve two distinct operations:
 * `'authentication'` (lightweight, any device type, no share reconstruction — `message_type`
 * becomes `AUTH_CHALLENGE`) and `'recovery'` (the dissertation's original full flow, unchanged
 * `message_type: 'RECOVERY_INIT'`).
 *
 * @param {object} args
 * @param {string} args.sessionId
 * @param {object} args.K - the Pedersen commitment point (from `commit()`), NOT yet hex-encoded.
 * @param {object} args.proof - `{ t, s1, s2 }` (from `prove()`).
 * @param {string} args.contextId
 * @param {'authentication'|'recovery'} [args.purpose] - defaults to 'recovery' for backward
 *   compatibility with Phase 2's original recovery-only flow.
 * @param {string} [args.certHash] - §4.1 AiTM binding; omitted until Phase 5.
 * @param {number} [args.timestampMs] - defaults to `Date.now()`; parameterized for testability.
 */
export function buildRecoveryInit({ sessionId, K, proof, contextId, purpose = 'recovery', certHash, timestampMs }) {
  return {
    protocol_version: PROTOCOL_VERSION,
    message_type: purpose === 'authentication' ? 'AUTH_CHALLENGE' : 'RECOVERY_INIT',
    purpose,
    session_id: sessionId,
    context_id: contextId,
    pedersen_commitment: hex0x(pointToHex(K)),
    nizk_t: hex0x(pointToHex(proof.t)),
    nizk_proof_s1: hex0x(proof.s1.toString(16)),
    nizk_proof_s2: hex0x(proof.s2.toString(16)),
    context_binding: {
      tls_cert_hash: certHash ? hex0x(certHash) : null,
      timestamp: timestampMs ?? Date.now(),
    },
  };
}

/**
 * §5.1 "Encrypted Share Distribution (SHARE_DELIVERY)". One per share-holding recipient. Not sent
 * to approval-only fido2 devices, which get a plain notification instead (see
 * src/dispatch/simulate.js) — they hold no share to deliver.
 *
 * Deviates from the dissertation's illustrative schema in one way, called out explicitly rather
 * than silently: an `iv` field is added, since AES-GCM requires a nonce to decrypt and the
 * dissertation's example JSON didn't include one (likely just an omission in an illustrative
 * schema, not an intentional design choice to leave it out).
 *
 * @param {object} args
 * @param {string} args.sessionId
 * @param {number} args.nodeIndex - matches the Shamir share's `x` coordinate.
 * @param {ReturnType<typeof import('../crypto/shareWrap.js').wrapShare>} args.wrapped
 */
export function buildShareDelivery({ sessionId, nodeIndex, wrapped }) {
  return {
    protocol_version: PROTOCOL_VERSION,
    message_type: 'SHARE_DELIVERY',
    session_id: sessionId,
    node_index: nodeIndex,
    wrap_method: wrapped.method,
    ephemeral_dh_pubkey: hex0x(wrapped.senderPublicKeyHex),
    iv: hex0x(wrapped.ivHex),
    encrypted_share: hex0x(wrapped.ciphertextHex),
  };
}

export function generateSessionId() {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  return '0x' + Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}
