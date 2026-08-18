import { describe, it, expect } from 'vitest';
import { commit, prove, verify } from '../src/crypto/pedersen.js';
import { split, reconstruct } from '../src/crypto/shamir.js';

/**
 * End-to-end simulation of one full ZRDCP recovery round using only the Phase 0 crypto core
 * (no dispatch/wire-protocol layer yet — that's Phase 2). Mirrors the state machine in §5.2:
 * CHALLENGE_INPUT -> DISPATCH_SHARES -> INTERPOLATING -> AUTHENTICATED.
 *
 * Worth calling out an implementation decision this test makes explicit, since the dissertation
 * doesn't fully spell it out: the NIZK proof and the Shamir reconstruction are two INDEPENDENT
 * mechanisms serving different purposes, not one feeding the other.
 *   - The NIZK proof (K, t, s1, s2) is broadcast to every node as part of RECOVERY_INIT. Each
 *     node can independently verify() it against the publicly-known K/contextId — this is how a
 *     node decides "yes, this request is legitimate" WITHOUT needing any reconstructed secret.
 *   - The Shamir shares of H(C_r) are what get reconstructed once k nodes cooperate — this is how
 *     the mesh recovers the actual credential material (e.g., to derive a new device key), a
 *     separate concern from request-legitimacy.
 * A node can therefore verify the proof immediately (before agreeing to release its share), and
 * the initiator separately proves it can later reconstruct H(C_r) from k returned shares.
 */
describe('Full recovery round (Phase 0 crypto core only, dissertation §5.2 state machine)', () => {
  it('CHALLENGE_INPUT -> DISPATCH_SHARES -> INTERPOLATING -> AUTHENTICATED', () => {
    const contextId = `session-${Date.now()}`;

    // [CHALLENGE_INPUT] user enters runtime code; A_1 commits to it and proves knowledge.
    const { K, m, r } = commit('user-entered-runtime-code');
    const proof = prove({ m, r, K, contextId });

    // Every node independently verifies the broadcast proof before agreeing to participate.
    expect(verify({ K, proof, contextId })).toBe(true);

    // [DISPATCH_SHARES] split H(C_r) = m into a 2-of-3 mesh and hand shares to 3 nodes.
    const shares = split(m, { n: 3, k: 2 });
    expect(shares).toHaveLength(3);

    // Simulate: node 2 is offline (DEGRADED_MESH-style scenario), nodes 1 and 3 respond.
    const returnedShares = [shares[0], shares[2]];

    // [INTERPOLATING] reconstruct H(C_r) from the k returned shares.
    const reconstructed = reconstruct(returnedShares);

    // [AUTHENTICATED] reconstructed value matches what was originally committed to.
    expect(reconstructed).toBe(m);
  });

  it('a node that never verified the NIZK proof still cannot forge a valid share on its own', () => {
    const { m } = commit('another-runtime-code');
    const shares = split(m, { n: 5, k: 3 });

    // An adversary holding only 2 (< k) genuine shares plus a made-up third "share" will NOT
    // reconstruct the true secret.
    const forgedThird = { x: 99, y: 12345n };
    const attempted = reconstruct([shares[0], shares[1], forgedThird]);

    expect(attempted).not.toBe(m);
  });
});
