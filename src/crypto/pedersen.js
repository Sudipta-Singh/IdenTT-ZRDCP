// ZRDCP crypto core — Pedersen commitment + Fiat-Shamir NIZK proof of knowledge.
//
// Dissertation §2.1 "Non-Interactive Zero-Knowledge (NIZK) Commitment Generation".
//
// Goal: the initiating device (A_1) proves it knows the runtime entropy C_r (and the blinding
// factor r) that open a commitment K, without revealing C_r or r to the verifying nodes.

import { G, H as Hgen, ORDER, mod, randomScalar, pointToHex } from './curve.js';
import { H, concatForChallenge } from './hash.js';

/**
 * §2.1: "A_1 selects a secure random blinding factor r ... and computes a Pedersen Commitment K:
 *   K = g^H(Cr) * h^r (mod p)"
 *
 * @param {string|Uint8Array} runtimeEntropy - the user-entered C_r.
 * @param {bigint} [r] - blinding factor; generated randomly if omitted (normal use). Accepting it
 *   as a parameter exists solely so tests can pin it down for reproducible assertions.
 * @returns {{K: import('@noble/curves/abstract/curve.js').ProjPointType, m: bigint, r: bigint}}
 *   K is the commitment point; m = H(C_r) and r are the values needed to open/prove it, and must
 *   be kept secret by the caller (never transmitted).
 */
export function commit(runtimeEntropy, r = randomScalar()) {
  const m = H(runtimeEntropy); // H(C_r), the value actually being committed to
  const K = G.multiply(m).add(Hgen.multiply(r));
  return { K, m, r };
}

/**
 * §2.1 steps 1-3: builds the NIZK proof that the prover knows (m, r) such that K = g^m * h^r,
 * using the Fiat-Shamir heuristic to make the (normally interactive) sigma protocol
 * non-interactive.
 *
 * @param {object} args
 * @param {bigint} args.m - H(C_r), from `commit`.
 * @param {bigint} args.r - blinding factor, from `commit`.
 * @param {object} args.K - commitment point, from `commit`.
 * @param {string} args.contextId - binds the proof to this specific session (dissertation's
 *   ContextID) so a proof can't be replayed against a different session.
 * @param {string} [args.certHash] - §4.1 AiTM binding; omitted until Phase 5 wires up real origin
 *   binding.
 */
export function prove({ m, r, K, contextId, certHash }) {
  // 1. Random Commitment: select w1, w2, compute t = g^w1 * h^w2
  const w1 = randomScalar();
  const w2 = randomScalar();
  const t = G.multiply(w1).add(Hgen.multiply(w2));

  // 2. Challenge Derivation: c = H(K || t || ContextID [|| H(Cert_TLS)])
  const c = H(
    concatForChallenge({
      commitmentHex: pointToHex(K),
      tHex: pointToHex(t),
      contextId,
      certHash,
    })
  );

  // 3. Response Generation: s1 = w1 + c*m (mod q), s2 = w2 + c*r (mod q)
  const s1 = mod(w1 + mod(c * m));
  const s2 = mod(w2 + mod(c * r));

  return { t, s1, s2, c };
}

/**
 * §2.1 step 4, "Verification Equation at Secondary Nodes S_i":
 *   g^s1 * h^s2 == t * K^c (mod p)
 *
 * The verifier independently recomputes the challenge `c` from (K, t, contextId, certHash) rather
 * than trusting the `c` embedded in the proof — this is what makes the whole thing sound: a
 * cheating prover can't pick s1/s2 first and back-solve for a matching c.
 *
 * @returns {boolean} true iff the proof is valid for this K/contextId/certHash.
 */
export function verify({ K, proof, contextId, certHash }) {
  const { t, s1, s2 } = proof;

  const c = H(
    concatForChallenge({
      commitmentHex: pointToHex(K),
      tHex: pointToHex(t),
      contextId,
      certHash,
    })
  );

  const lhs = G.multiply(mod(s1)).add(Hgen.multiply(mod(s2)));
  const rhs = t.add(K.multiply(mod(c)));

  return lhs.equals(rhs);
}

export const CURVE_ORDER = ORDER;
