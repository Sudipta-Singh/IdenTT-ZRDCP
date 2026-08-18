import { describe, it, expect } from 'vitest';
import { commit, prove, verify } from '../src/crypto/pedersen.js';
import { randomScalar } from '../src/crypto/curve.js';

describe('Pedersen commitment + Fiat-Shamir NIZK (dissertation §2.1)', () => {
  it('honest proof verifies (K = g^H(Cr) * h^r, and the verification equation holds)', () => {
    const { K, m, r } = commit('my-runtime-secret-phrase-42');
    const contextId = 'session-abc123';
    const proof = prove({ m, r, K, contextId });

    expect(verify({ K, proof, contextId })).toBe(true);
  });

  it('is a real zero-knowledge proof: verification succeeds without the verifier ever seeing C_r or r', () => {
    const { K, m, r } = commit('correct horse battery staple');
    const contextId = 'session-zk-check';
    const proof = prove({ m, r, K, contextId });

    // The only things handed to verify() are public: K, the proof (t, s1, s2), and contextId.
    // m and r never appear on the verifier's side of this call.
    const ok = verify({ K, proof, contextId });
    expect(ok).toBe(true);
  });

  it('rejects a proof checked against a different ContextID (replay protection across sessions)', () => {
    const { K, m, r } = commit('some-entropy');
    const proof = prove({ m, r, K, contextId: 'session-1' });

    expect(verify({ K, proof, contextId: 'session-2' })).toBe(false);
  });

  it('rejects a proof for the wrong commitment (someone else\'s K)', () => {
    const a = commit('entropy-A');
    const b = commit('entropy-B');
    const contextId = 'session-swap';
    const proofForA = prove({ m: a.m, r: a.r, K: a.K, contextId });

    expect(verify({ K: b.K, proof: proofForA, contextId })).toBe(false);
  });

  it('rejects a tampered response (s1 flipped) even against the right K/contextId', () => {
    const { K, m, r } = commit('tamper-me');
    const contextId = 'session-tamper';
    const proof = prove({ m, r, K, contextId });
    const tampered = { ...proof, s1: proof.s1 + 1n };

    expect(verify({ K, proof: tampered, contextId })).toBe(false);
  });

  it('rejects a forged proof from someone who does not know m/r (cannot fake t/s1/s2 without the secret)', () => {
    const { K } = commit('victim-secret');
    const contextId = 'session-forge';
    // An attacker without m, r can at best pick random-looking t, s1, s2.
    const forged = { t: commit('unrelated').K, s1: randomScalar(), s2: randomScalar() };

    expect(verify({ K, proof: forged, contextId })).toBe(false);
  });

  it('§4.1 AiTM binding: a proof bound to one TLS cert hash fails verification under a different one', () => {
    const { K, m, r } = commit('phish-me-not');
    const contextId = 'session-aitm';
    const realCertHash = 'cert-hash-genuine-origin';
    const proof = prove({ m, r, K, contextId, certHash: realCertHash });

    // Proxy relays the session to a different (its own) origin -> different cert hash.
    expect(verify({ K, proof, contextId, certHash: 'cert-hash-attacker-proxy' })).toBe(false);
    // But verifies fine against the real origin's cert hash.
    expect(verify({ K, proof, contextId, certHash: realCertHash })).toBe(true);
  });

  it('same runtime entropy produces different commitments each time (blinding factor randomizes K)', () => {
    const a = commit('same-secret');
    const b = commit('same-secret');
    expect(a.K.equals(b.K)).toBe(false); // different random r each call
    expect(a.m).toBe(b.m); // but H(Cr) itself is deterministic
  });
});
