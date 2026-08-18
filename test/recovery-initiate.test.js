import { describe, it, expect } from 'vitest';
import { initiateRecovery, RecoveryInitiationError } from '../src/recovery/initiate.js';
import { createRegistry, addDevice } from '../src/registry/registry.js';
import { createZrdcpNativeDevice, createFidoDevice } from '../src/registry/schema.js';
import { generateIdentityKeypair, pointFromHex, hexToScalar, H } from '../src/crypto/index.js';
import { verify } from '../src/crypto/pedersen.js';
import { unwrapShare } from '../src/crypto/shareWrap.js';
import { reconstruct } from '../src/crypto/shamir.js';
import { simulateRegister, deriveKeypairFromPrfOutput, simulateGetPrfOutput, PRF_SALT } from '../src/fido/simulate.js';

const emailChannel = (addr) => ({ kind: 'email', address: addr });

/** Builds a registry with a realistic mixed mesh: 2 zrdcp-native (one remote), 1 full-share
 * fido2 (remote), 1 approval-only fido2 — and returns the raw material tests need to
 * independently decrypt/verify everything `initiateRecovery` produces (private keys
 * `initiateRecovery` itself never returns). */
async function buildMixedMeshRegistry({ kRecovery = 3, kAuthentication = 2, minRemoteForRecovery = 1 } = {}) {
  const localIdentity = generateIdentityKeypair();
  let registry = { ...createRegistry({ targetN: 4, kAuthentication, kRecovery, minRemoteForRecovery }), localIdentity };

  const nativeA = generateIdentityKeypair();
  const deviceA = createZrdcpNativeDevice({
    name: 'Laptop A (local)',
    contactChannels: [emailChannel('a@example.com')],
    publicKeyHex: nativeA.publicKeyHex,
    isRemote: false,
  });
  registry = addDevice(registry, deviceA);

  const nativeB = generateIdentityKeypair();
  const deviceB = createZrdcpNativeDevice({
    name: 'Laptop B (remote)',
    contactChannels: [emailChannel('b@example.com')],
    publicKeyHex: nativeB.publicKeyHex,
    isRemote: true,
  });
  registry = addDevice(registry, deviceB);

  const fidoFullCredential = await simulateRegister({ name: 'YubiKey (PRF)', prfHint: true });
  const fidoFullDevice = createFidoDevice({
    name: 'YubiKey (PRF)',
    contactChannels: [emailChannel('yubikey-owner@example.com')],
    credential: fidoFullCredential,
    isRemote: true,
  });
  registry = addDevice(registry, fidoFullDevice);

  const fidoApprovalCredential = await simulateRegister({ name: 'Old key (no PRF)', prfHint: false });
  const fidoApprovalDevice = createFidoDevice({
    name: 'Old key (no PRF)',
    contactChannels: [emailChannel('oldkey-owner@example.com')],
    credential: fidoApprovalCredential,
  });
  registry = addDevice(registry, fidoApprovalDevice);

  return {
    registry,
    privateKeys: { deviceA: nativeA.privateKeyHex, deviceB: nativeB.privateKeyHex },
    fidoFullCredential,
    ids: { deviceA: deviceA.id, deviceB: deviceB.id, fidoFull: fidoFullDevice.id, fidoApproval: fidoApprovalDevice.id },
  };
}

describe('Recovery initiation & dispatch (Phase 2, dissertation §5.1/§5.2 CHALLENGE_INPUT -> DISPATCH_SHARES)', () => {
  it('dispatches to every device, sends shares only to share-holders, and the mesh can reconstruct the secret', async () => {
    const { registry, privateKeys, fidoFullCredential, ids } = await buildMixedMeshRegistry({ kRecovery: 3 });

    const session = await initiateRecovery({ registry, runtimeEntropy: 'my-runtime-code-42', purpose: 'recovery' });
    expect(session.purpose).toBe('recovery');
    expect(session.requiredK).toBe(3);
    expect(session.minRemoteForRecovery).toBe(1);

    // Every one of the 4 devices got dispatched to.
    expect(session.dispatches).toHaveLength(4);

    const byId = Object.fromEntries(session.dispatches.map((d) => [d.deviceId, d]));
    expect(byId[ids.deviceA].hasShare).toBe(true);
    expect(byId[ids.deviceB].hasShare).toBe(true);
    expect(byId[ids.fidoFull].hasShare).toBe(true);
    expect(byId[ids.fidoApproval].hasShare).toBe(false); // approval-only: no share
    expect(byId[ids.deviceB].isRemote).toBe(true);
    expect(byId[ids.deviceA].isRemote).toBe(false);

    // The RECOVERY_INIT proof verifies independently (as any node receiving it would check).
    const K = pointFromHex(session.recoveryInit.pedersen_commitment);
    const proof = {
      t: pointFromHex(session.recoveryInit.nizk_t),
      s1: hexToScalar(session.recoveryInit.nizk_proof_s1.slice(2)),
      s2: hexToScalar(session.recoveryInit.nizk_proof_s2.slice(2)),
    };
    expect(verify({ K, proof, contextId: session.contextId })).toBe(true);

    // Reconstruct via all 3 share-holders (k=3, and this mesh only has 3): deviceA, remote
    // deviceB, and the fido full-share device.
    const shareA = await unwrapShare({
      wrapped: parseShareDeliveryWrapped(byId[ids.deviceA]),
      recipientPrivateKeyHex: privateKeys.deviceA,
    });
    const shareB = await unwrapShare({
      wrapped: parseShareDeliveryWrapped(byId[ids.deviceB]),
      recipientPrivateKeyHex: privateKeys.deviceB,
    });
    const fidoPrfOutput = await simulateGetPrfOutput(fidoFullCredential, PRF_SALT);
    const fidoPrivateKeyHex = deriveKeypairFromPrfOutput(fidoPrfOutput).privateKeyHex;
    const shareFido = await unwrapShare({
      wrapped: parseShareDeliveryWrapped(byId[ids.fidoFull]),
      recipientPrivateKeyHex: fidoPrivateKeyHex,
    });

    const reconstructed = reconstruct([shareA, shareB, shareFido]);
    expect(reconstructed).toBe(H('my-runtime-code-42'));
  });

  it('refuses to initiate recovery when fewer share-holding devices are enrolled than kRecovery requires', async () => {
    const localIdentity = generateIdentityKeypair();
    let registry = { ...createRegistry({ targetN: 4, kRecovery: 3 }), localIdentity };
    const only = generateIdentityKeypair();
    registry = addDevice(
      registry,
      createZrdcpNativeDevice({ name: 'Only device', contactChannels: [emailChannel('x@example.com')], publicKeyHex: only.publicKeyHex })
    );

    await expect(initiateRecovery({ registry, runtimeEntropy: 'code', purpose: 'recovery' })).rejects.toThrow(
      RecoveryInitiationError
    );
  });

  it('refuses to initiate recovery when no share-holding device is flagged remote', async () => {
    const localIdentity = generateIdentityKeypair();
    let registry = { ...createRegistry({ targetN: 4, kRecovery: 3, minRemoteForRecovery: 1 }), localIdentity };
    for (const name of ['Local A', 'Local B', 'Local C']) {
      const kp = generateIdentityKeypair();
      registry = addDevice(
        registry,
        createZrdcpNativeDevice({
          name,
          contactChannels: [emailChannel(`${name.replace(/\s/g, '').toLowerCase()}@example.com`)],
          publicKeyHex: kp.publicKeyHex,
          // deliberately no isRemote: true anywhere in this mesh
        })
      );
    }

    await expect(initiateRecovery({ registry, runtimeEntropy: 'code', purpose: 'recovery' })).rejects.toThrow(
      /remote share-holding device/
    );
  });

  it('refuses to initiate without a local device identity', async () => {
    const registry = createRegistry({ targetN: 4, kRecovery: 3 }); // no localIdentity attached
    await expect(initiateRecovery({ registry, runtimeEntropy: 'code', purpose: 'recovery' })).rejects.toThrow(
      RecoveryInitiationError
    );
  });

  it('every dispatch includes a responder link', async () => {
    const { registry } = await buildMixedMeshRegistry({ kRecovery: 3 });
    const session = await initiateRecovery({ registry, runtimeEntropy: 'code', purpose: 'recovery' });
    for (const dispatch of session.dispatches) {
      expect(dispatch.responderLink).toContain(session.sessionId);
    }
  });

  it('two different recovery sessions for the same runtime code produce unrelated session ids and ciphertexts', async () => {
    const { registry } = await buildMixedMeshRegistry({ kRecovery: 3 });
    const s1 = await initiateRecovery({ registry, runtimeEntropy: 'same-code', purpose: 'recovery' });
    const s2 = await initiateRecovery({ registry, runtimeEntropy: 'same-code', purpose: 'recovery' });
    expect(s1.sessionId).not.toBe(s2.sessionId);
    expect(s1.recoveryInit.pedersen_commitment).not.toBe(s2.recoveryInit.pedersen_commitment); // fresh blinding factor
  });

  describe('authentication purpose (lightweight quorum, no share math)', () => {
    it('dispatches AUTH_CHALLENGE to every device and needs only kAuthentication approvals — any device type', async () => {
      const { registry } = await buildMixedMeshRegistry({ kAuthentication: 2 });
      const session = await initiateRecovery({ registry, runtimeEntropy: 'auth-code', purpose: 'authentication' });

      expect(session.purpose).toBe('authentication');
      expect(session.requiredK).toBe(2);
      expect(session.minRemoteForRecovery).toBeNull();
      expect(session.recoveryInit.message_type).toBe('AUTH_CHALLENGE');
      // No shares sent to anyone, including share-holding devices — authentication never splits.
      expect(session.dispatches.every((d) => d.hasShare === false)).toBe(true);
      expect(session.dispatches).toHaveLength(4);
    });

    it('refuses to initiate authentication when fewer devices are enrolled than kAuthentication requires', async () => {
      const localIdentity = generateIdentityKeypair();
      let registry = { ...createRegistry({ targetN: 4, kAuthentication: 3 }), localIdentity };
      const only = generateIdentityKeypair();
      registry = addDevice(
        registry,
        createZrdcpNativeDevice({ name: 'Only device', contactChannels: [emailChannel('x@example.com')], publicKeyHex: only.publicKeyHex })
      );
      await expect(initiateRecovery({ registry, runtimeEntropy: 'code', purpose: 'authentication' })).rejects.toThrow(
        RecoveryInitiationError
      );
    });
  });
});

/**
 * Reverses `buildShareDelivery`'s wire encoding back into the `{ method, senderPublicKeyHex,
 * ivHex, ciphertextHex }` shape `unwrapShare` expects — exactly what a real recipient device
 * would do after receiving a SHARE_DELIVERY message over email/SMS/WebAPI.
 */
function parseShareDeliveryWrapped(dispatch) {
  const msg = dispatch.shareDeliveryMessage;
  const strip0x = (hex) => (hex.startsWith('0x') ? hex.slice(2) : hex);
  return {
    method: msg.wrap_method,
    senderPublicKeyHex: strip0x(msg.ephemeral_dh_pubkey),
    ivHex: strip0x(msg.iv),
    ciphertextHex: strip0x(msg.encrypted_share),
  };
}
