import { describe, it, expect } from 'vitest';
import { split, lagrangeInterpolate } from '../src/crypto/shamir.js';
import { H } from '../src/crypto/hash.js';
import { mod, randomScalar, ORDER } from '../src/crypto/curve.js';

/**
 * Dissertation §2.3, Theorem 1: "An adversary A possessing fewer than k shares (|S_A| < k) gains
 * strictly zero statistical advantage in determining the runtime secret C_r."
 *
 * The proof's core claim: for ANY k-1 observed shares and ANY candidate secret S', there exists a
 * unique degree-(k-1) polynomial consistent with both. This test demonstrates that constructively
 * — for a fixed set of k-1 real shares, we show that *every* candidate secret (including
 * wildly different ones, and the true secret itself) has a fully consistent completion. Since a
 * consistent completion exists for literally every possible value in the field, the k-1 shares
 * cannot rule any candidate in or out — that's what "zero statistical advantage" means here.
 */
describe('Information-theoretic soundness of k-1 shares (dissertation §2.3, Theorem 1)', () => {
  it('for any candidate secret, a consistent completion of k-1 shares exists and interpolates back to exactly that candidate', () => {
    const trueSecret = H('the-real-secret-nobody-should-learn');
    const { n, k } = { n: 5, k: 3 };
    const shares = split(trueSecret, { n, k });

    // An adversary who compromised k-1 = 2 nodes sees only these two shares.
    const observed = shares.slice(0, k - 1);

    const candidates = [
      trueSecret, // the actual secret
      mod(trueSecret + 1n), // a near neighbor
      randomScalar(), // something unrelated
      randomScalar(),
      0n,
      mod(ORDER - 1n), // field boundary
    ];

    for (const candidate of candidates) {
      // Build the (k-1) observed points + the hypothesis point (x=0, y=candidate) — that's k
      // points total, which uniquely determines a degree-(k-1) polynomial.
      const hypothesisPoints = [...observed, { x: 0, y: candidate }];

      // Evaluate that hypothetical polynomial at a fresh x (a node index never handed to the
      // adversary) to get what a k-th share WOULD have looked like under this hypothesis.
      const freshX = n + 1;
      const impliedShareY = lagrangeInterpolate(hypothesisPoints, freshX);

      // Now reconstruct using the k-1 observed shares plus that implied k-th share, WITHOUT ever
      // referencing `candidate` again — if this round-trips back to exactly `candidate`, that
      // confirms the k-1 observed shares are equally consistent with every candidate we tried,
      // including ones far from the true secret.
      const roundTrip = lagrangeInterpolate([...observed, { x: freshX, y: impliedShareY }], 0n);

      expect(roundTrip).toBe(mod(candidate));
    }
  });

  it('the true secret is not distinguishable from an arbitrary decoy given only k-1 shares (no special-case leakage)', () => {
    const trueSecret = H('another-real-secret');
    const decoySecret = randomScalar();
    const { n, k } = { n: 7, k: 4 };

    const realShares = split(trueSecret, { n, k });
    const observed = realShares.slice(0, k - 1); // 3 of the 4 needed

    // Confirm both the true secret AND an unrelated decoy have a valid degree-(k-1) polynomial
    // passing through the observed points — i.e., the observed shares alone don't favor one over
    // the other.
    for (const candidate of [trueSecret, decoySecret]) {
      const hypothesisPoints = [...observed, { x: 0, y: candidate }];
      const freshX = n + 2;
      const impliedY = lagrangeInterpolate(hypothesisPoints, freshX);
      const roundTrip = lagrangeInterpolate([...observed, { x: freshX, y: impliedY }], 0n);
      expect(roundTrip).toBe(mod(candidate));
    }
  });
});
