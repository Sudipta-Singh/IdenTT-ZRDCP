import { describe, it, expect } from 'vitest';
import { split, reconstruct, lagrangeInterpolate } from '../src/crypto/shamir.js';
import { H } from '../src/crypto/hash.js';
import { ORDER, mod, randomScalar } from '../src/crypto/curve.js';

describe("Shamir's Secret Sharing (dissertation §2.2)", () => {
  it('any k of n shares reconstruct the exact secret', () => {
    const secret = H('the-actual-runtime-secret');
    const shares = split(secret, { n: 5, k: 3 });

    expect(reconstruct(shares.slice(0, 3))).toBe(secret);
  });

  it('every distinct k-sized subset reconstructs the SAME secret (matches the §3 "2-of-3" example)', () => {
    const secret = mod(123456789012345678901234567890n);
    const shares = split(secret, { n: 3, k: 2 });
    const [s1, s2, s3] = shares;

    expect(reconstruct([s1, s2])).toBe(secret);
    expect(reconstruct([s1, s3])).toBe(secret);
    expect(reconstruct([s2, s3])).toBe(secret);
  });

  it('works at the edges: k=1 (any single share is the secret-derived point) and k=n (need all shares)', () => {
    const secret = H('edge-case-secret');

    const k1 = split(secret, { n: 4, k: 1 });
    expect(reconstruct([k1[0]])).toBe(secret);

    const kn = split(secret, { n: 4, k: 4 });
    expect(reconstruct(kn)).toBe(secret);
  });

  it('rejects invalid (n, k) configurations', () => {
    expect(() => split(1n, { n: 3, k: 5 })).toThrow(); // k > n
    expect(() => split(1n, { n: 3, k: 0 })).toThrow(); // k < 1
  });

  it('rejects reconstruction with duplicate x-values', () => {
    const secret = H('dup-test');
    const shares = split(secret, { n: 3, k: 2 });
    expect(() => reconstruct([shares[0], shares[0]])).toThrow();
  });

  it('fewer than k shares does NOT reconstruct the true secret (structurally — see soundness.test.js for the formal property)', () => {
    const secret = H('undersupplied');
    const shares = split(secret, { n: 5, k: 4 });
    // Only 2 of the required 4 — reconstruct() will happily compute *something* (fitting a
    // lower-degree curve through the given points), but it won't be the real secret.
    const wrong = reconstruct(shares.slice(0, 2));
    expect(wrong).not.toBe(secret);
  });

  it('a tampered share causes reconstruction to silently diverge from the true secret', () => {
    const secret = H('integrity-check');
    const shares = split(secret, { n: 5, k: 3 });
    const tampered = shares.slice(0, 3).map((s, i) => (i === 1 ? { ...s, y: mod(s.y + 1n) } : s));

    // Note: Shamir reconstruction alone has NO tamper-detection built in — this is exactly why
    // the wire protocol (§5.1) encrypts each share with AES-GCM (authenticated encryption) before
    // transport, and the app must not accept a share whose GCM auth tag fails, upstream of
    // ever calling reconstruct(). This test documents that the raw math provides no such check.
    expect(reconstruct(tampered)).not.toBe(secret);
  });

  it('lagrangeInterpolate at x=0 is equivalent to reconstruct()', () => {
    const secret = H('equivalence-check');
    const shares = split(secret, { n: 4, k: 3 });
    expect(lagrangeInterpolate(shares.slice(0, 3), 0n)).toBe(reconstruct(shares.slice(0, 3)));
  });

  it('shares are well-formed field elements (0 <= y < ORDER)', () => {
    const secret = randomScalar();
    const shares = split(secret, { n: 6, k: 3 });
    for (const s of shares) {
      expect(s.y >= 0n).toBe(true);
      expect(s.y < ORDER).toBe(true);
    }
  });
});
