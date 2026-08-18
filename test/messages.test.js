import { describe, it, expect } from 'vitest';
import { buildRecoveryInit, buildShareDelivery, generateSessionId } from '../src/protocol/messages.js';
import { commit, prove, verify } from '../src/crypto/pedersen.js';
import { pointFromHex, hexToScalar } from '../src/crypto/curve.js';
import { wrapShare } from '../src/crypto/shareWrap.js';
import { generateIdentityKeypair } from '../src/crypto/curve.js';

describe('Wire message builders (dissertation §5.1)', () => {
  it('buildRecoveryInit produces every field the dissertation schema specifies (plus a fix-up)', () => {
    const { K, m, r } = commit('a-runtime-code');
    const contextId = 'session-msg-test';
    const proof = prove({ m, r, K, contextId });
    const sessionId = generateSessionId();

    const msg = buildRecoveryInit({ sessionId, K, proof, contextId, timestampMs: 1786318380000 });

    expect(msg.protocol_version).toBe('ZRDCP/1.0');
    expect(msg.message_type).toBe('RECOVERY_INIT');
    expect(msg.session_id).toBe(sessionId);
    expect(msg.pedersen_commitment).toMatch(/^0x[0-9a-f]+$/);
    expect(msg.nizk_t).toMatch(/^0x[0-9a-f]+$/);
    expect(msg.nizk_proof_s1).toMatch(/^0x[0-9a-f]+$/);
    expect(msg.nizk_proof_s2).toMatch(/^0x[0-9a-f]+$/);
    expect(msg.context_binding.timestamp).toBe(1786318380000);
    expect(msg.context_binding.tls_cert_hash).toBeNull();
  });

  it('a RECOVERY_INIT message survives JSON round-trip and its proof still verifies after being parsed back', () => {
    const { K, m, r } = commit('round-trip-me');
    const contextId = 'session-roundtrip';
    const proof = prove({ m, r, K, contextId });
    const sessionId = generateSessionId();

    const msg = buildRecoveryInit({ sessionId, K, proof, contextId });
    const wire = JSON.parse(JSON.stringify(msg)); // simulate actually sending this over email/SMS/WebAPI as JSON

    const parsedK = pointFromHex(wire.pedersen_commitment);
    const parsedProof = {
      t: pointFromHex(wire.nizk_t),
      s1: hexToScalar(wire.nizk_proof_s1.slice(2)),
      s2: hexToScalar(wire.nizk_proof_s2.slice(2)),
    };

    expect(verify({ K: parsedK, proof: parsedProof, contextId: wire.context_id })).toBe(true);
  });

  it('buildShareDelivery includes an iv field (a documented addition beyond the illustrative schema)', async () => {
    const sender = generateIdentityKeypair();
    const recipient = generateIdentityKeypair();
    const wrapped = await wrapShare({
      share: { x: 1, y: 123n },
      senderIdentity: sender,
      recipientPublicKeyHex: recipient.publicKeyHex,
    });
    const sessionId = generateSessionId();
    const msg = buildShareDelivery({ sessionId, nodeIndex: 1, wrapped });

    expect(msg.message_type).toBe('SHARE_DELIVERY');
    expect(msg.node_index).toBe(1);
    expect(msg.ephemeral_dh_pubkey).toBe('0x' + sender.publicKeyHex);
    expect(msg.iv).toMatch(/^0x[0-9a-f]+$/);
    expect(msg.encrypted_share).toMatch(/^0x[0-9a-f]+$/);
  });

  it('generateSessionId produces unique, well-formed ids', () => {
    const a = generateSessionId();
    const b = generateSessionId();
    expect(a).not.toBe(b);
    expect(a).toMatch(/^0x[0-9a-f]{32}$/);
  });
});
