// ZRDCP crypto core — hash function H() and Fiat-Shamir challenge derivation.
//
// Dissertation §2: "H: {0,1}* -> Z_q* is a cryptographic hash function (SHA3-256)."

import { sha3_256 } from '@noble/hashes/sha3.js';
import { bytesToScalar } from './curve.js';

const enc = new TextEncoder();

function toBytes(input) {
  if (input instanceof Uint8Array) return input;
  if (typeof input === 'string') return enc.encode(input);
  throw new TypeError('toBytes: expected string or Uint8Array');
}

/**
 * H(x) — dissertation's hash-to-scalar function. Hashes arbitrary input with SHA3-256 and
 * reduces the digest mod the scalar field order, landing the result in Z_q as specified.
 *
 * Used two ways in the spec, both handled by this one function:
 *   - H(C_r): hash the user's runtime entropy into the field before committing/splitting it.
 *   - H(K || t || ContextID [|| H(Cert_TLS)]): the Fiat-Shamir challenge derivation (§2.1 step 2,
 *     extended in §4.1). Callers build the concatenated input with `concatForChallenge` below so
 *     the domain separation between fields is unambiguous.
 */
export function H(input) {
  const digest = sha3_256(toBytes(input));
  return bytesToScalar(digest);
}

/**
 * Builds the exact byte string the Fiat-Shamir challenge is hashed from:
 *   c = H( K || t || ContextID [|| H(Cert_TLS)] )
 * Each field is length-prefixed so concatenation is unambiguous (avoids the classic
 * "concatenation collision" pitfall where H(a||b) could equal H(a'||b') for differently-split
 * a/b). `certHash` is optional — omitted pre-Phase-5, included once AiTM/origin binding (§4.1)
 * is wired up.
 */
export function concatForChallenge({ commitmentHex, tHex, contextId, certHash }) {
  const parts = [commitmentHex, tHex, contextId];
  if (certHash !== undefined) parts.push(certHash);
  return parts.map((p) => `${p.length}:${p}`).join('|');
}
