// ZRDCP crypto core — Shamir's Secret Sharing over the scalar field.
//
// Dissertation §2.2 "Multi-Party Information-Theoretic Reconstruction" and §2.3 (soundness proof).

import { ORDER, mod, modInverse, randomScalar } from './curve.js';

/**
 * §2.2 step 1: "A_1 constructs a random polynomial f(x) in R_q[x] of degree k-1:
 *   f(x) = a_0 + SUM_{m=1}^{k-1} (a_m * x^m) (mod q)  where a_0 = H(C_r)"
 * step 2: shares are v_i = f(i) (mod q) for i = 1..n.
 *
 * @param {bigint} secret - a_0, the value being shared (H(C_r) in the protocol, but this function
 *   is generic — the caller decides what secret goes in).
 * @param {object} opts
 * @param {number} opts.n - total number of shares to generate.
 * @param {number} opts.k - reconstruction threshold; the polynomial has degree k-1.
 * @returns {{x: number, y: bigint}[]} n shares. `x` is the node index (1-based, matches the
 *   dissertation's node_index field in SHARE_DELIVERY); `y` is f(x).
 */
export function split(secret, { n, k }) {
  if (!Number.isInteger(n) || !Number.isInteger(k) || k < 1 || n < k) {
    throw new RangeError(`split: invalid (n=${n}, k=${k}) — require 1 <= k <= n`);
  }

  // a_0 = secret; a_1..a_{k-1} random coefficients in Z_q.
  const coefficients = [mod(secret)];
  for (let i = 1; i < k; i++) coefficients.push(randomScalar());

  const evaluate = (x) => {
    // Horner's method: evaluate the degree-(k-1) polynomial at x, mod q.
    let y = 0n;
    for (let i = coefficients.length - 1; i >= 0; i--) {
      y = mod(y * BigInt(x) + coefficients[i]);
    }
    return y;
  };

  const shares = [];
  for (let x = 1; x <= n; x++) shares.push({ x, y: evaluate(x) });
  return shares;
}

/**
 * General Lagrange interpolation: given points on a degree-(len-1) polynomial, evaluate that
 * polynomial at an arbitrary point `atX`. `reconstruct` below is the special case atX=0 that the
 * protocol actually uses (recovering a_0 = H(C_r)). The general form is exposed too because it's
 * useful for (a) testing the §2.3 soundness property directly, and (b) potential future share
 * renewal/rotation, which needs to evaluate the polynomial at new x-values.
 *
 * @param {{x: number, y: bigint}[]} points
 * @param {bigint|number} atX
 */
export function lagrangeInterpolate(points, atX) {
  const xs = new Set(points.map((s) => s.x));
  if (xs.size !== points.length) {
    throw new RangeError('lagrangeInterpolate: duplicate x-values — cannot interpolate');
  }
  if (points.length === 0) {
    throw new RangeError('lagrangeInterpolate: need at least one point');
  }
  const target = BigInt(atX);

  let result = 0n;
  for (const j of points) {
    let num = 1n;
    let den = 1n;
    for (const m of points) {
      if (m.x === j.x) continue;
      num = mod(num * (target - BigInt(m.x)));
      den = mod(den * BigInt(j.x - m.x));
    }
    const lj = mod(num * modInverse(den));
    result = mod(result + mod(j.y * lj));
  }
  return result;
}

/**
 * §2.2 step 3: Lagrange interpolation at x=0 to recover a_0 = H(C_r) from any k of the n shares:
 *   H(C_r) = SUM_{j=1}^{k} ( v_j * l_j(0) ) (mod q)
 *   where l_j(0) = PROD_{m != j}^{k} ( -m / (j - m) ) (mod q)
 *
 * Requires at least `k` shares to have been generated with that same `k` — passing fewer, or a
 * set with duplicate x-values, produces a meaningless (not a securely-blinded) result rather than
 * throwing, matching the dissertation's point that <k shares carry no information at all about
 * the secret. Callers are responsible for only calling this once k distinct shares are in hand.
 *
 * @param {{x: number, y: bigint}[]} shares - k (or more — only the first k are used) shares.
 * @returns {bigint} the reconstructed secret a_0.
 */
export function reconstruct(shares) {
  return lagrangeInterpolate(shares, 0n);
}

export const FIELD_ORDER = ORDER;
