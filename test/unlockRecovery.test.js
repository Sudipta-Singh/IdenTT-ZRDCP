import { describe, it, expect } from 'vitest';
import { enableRecoveryUnlock, attemptReconstruction, VaultUnlockRecoveryError } from '../src/vault/unlockRecovery.js';
import { unwrapShare } from '../src/crypto/shareWrap.js';
import { sealWithKey, openWithKey } from '../src/vault/vault.js';
import { createRegistry, addDevice } from '../src/registry/registry.js';
import { createZrdcpNativeDevice } from '../src/registry/schema.js';
import { generateIdentityKeypair } from '../src/crypto/curve.js';

const emailChannel = (addr) => ({ kind: 'email', address: addr });

/** A registry ("Alice's") with 3 native share-holders (one remote) plus her own localIdentity —
 * mirrors buildMixedMeshRegistry from test/recovery-initiate.test.js but only zrdcp-native, since
 * unlockRecovery.js's contract only cares about share-holding devices in general. Returns each
 * holder's real private key too, so the test can independently unwrap/reconstruct exactly like a
 * real responder device would. */
function buildAliceRegistry({ kRecovery = 3, minRemoteForRecovery = 1 } = {}) {
  const localIdentity = generateIdentityKeypair();
  let registry = { ...createRegistry({ targetN: 4, kRecovery, minRemoteForRecovery }), localIdentity };

  const holderKeys = {};
  const addHolder = (name, isRemote) => {
    const kp = generateIdentityKeypair();
    holderKeys[name] = kp.privateKeyHex;
    registry = addDevice(
      registry,
      createZrdcpNativeDevice({
        name,
        contactChannels: [emailChannel(`${name.toLowerCase()}@example.com`)],
        publicKeyHex: kp.publicKeyHex,
        isRemote,
      })
    );
  };
  addHolder('Local A', false);
  addHolder('Remote B', true);
  addHolder('Local C', false);

  return { registry, holderKeys };
}

describe('enableRecoveryUnlock', () => {
  it('refuses when there are fewer share-holders than kRecovery', async () => {
    const localIdentity = generateIdentityKeypair();
    const registry = { ...createRegistry({ targetN: 4, kRecovery: 3 }), localIdentity };
    await expect(enableRecoveryUnlock({ registry })).rejects.toThrow(VaultUnlockRecoveryError);
  });

  it('refuses when no share-holder is flagged remote', async () => {
    const localIdentity = generateIdentityKeypair();
    let registry = { ...createRegistry({ targetN: 4, kRecovery: 3, minRemoteForRecovery: 1 }), localIdentity };
    for (const name of ['A', 'B', 'C']) {
      const kp = generateIdentityKeypair();
      registry = addDevice(
        registry,
        createZrdcpNativeDevice({ name, contactChannels: [emailChannel(`${name}@x.com`)], publicKeyHex: kp.publicKeyHex })
      );
    }
    await expect(enableRecoveryUnlock({ registry })).rejects.toThrow(/remote/);
  });

  it('produces one wrapped share per holder, and a recoverySplit safe to store in the open (no keyHex inside it)', async () => {
    const { registry } = buildAliceRegistry();
    const { keyHex, recoverySplit } = await enableRecoveryUnlock({ registry });
    expect(keyHex).toMatch(/^[0-9a-f]{64}$/);
    expect(recoverySplit.shares).toHaveLength(3);
    expect(recoverySplit.kRecovery).toBe(3);
    expect(recoverySplit.minRemoteForRecovery).toBe(1);
    expect(JSON.stringify(recoverySplit)).not.toContain(keyHex); // the split never embeds the secret it protects
    const remoteFlags = recoverySplit.shares.map((s) => s.isRemote);
    expect(remoteFlags).toEqual([false, true, false]); // Local A, Remote B, Local C, in enrollment order
  });
});

describe('attemptReconstruction', () => {
  it('denies with too few collected shares', async () => {
    const { registry } = buildAliceRegistry();
    const { recoverySplit } = await enableRecoveryUnlock({ registry });
    const result = attemptReconstruction({ recoverySplit, collectedShares: [] });
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/0\/3/);
  });

  it('denies when count is met but the remote responder never came in', async () => {
    const { registry, holderKeys } = buildAliceRegistry();
    const { recoverySplit } = await enableRecoveryUnlock({ registry });

    // Unwrap 2 LOCAL holders' shares for real (exactly what a responder vault would do) — skip
    // the remote one on purpose.
    const localShares = recoverySplit.shares.filter((s) => !s.isRemote);
    const collected = [];
    for (const s of localShares) {
      const unwrapped = await unwrapShare({ wrapped: s.wrapped, recipientPrivateKeyHex: holderKeys[s.deviceName] });
      collected.push({ deviceId: s.deviceId, x: unwrapped.x, y: unwrapped.y.toString() });
    }
    const result = attemptReconstruction({ recoverySplit, collectedShares: collected });
    expect(result.ok).toBe(false);
    expect(result.reason).toMatch(/0\/1 required remote/);
  });

  it('reconstructs the exact original keyHex once enough real shares (incl. the remote one) are collected, and that key really opens a vault sealed under it', async () => {
    const { registry, holderKeys } = buildAliceRegistry();
    const { keyHex, recoverySplit } = await enableRecoveryUnlock({ registry });

    const collected = [];
    for (const s of recoverySplit.shares) {
      const unwrapped = await unwrapShare({ wrapped: s.wrapped, recipientPrivateKeyHex: holderKeys[s.deviceName] });
      collected.push({ deviceId: s.deviceId, x: unwrapped.x, y: unwrapped.y.toString() });
    }
    const result = attemptReconstruction({ recoverySplit, collectedShares: collected });
    expect(result.ok).toBe(true);
    expect(result.keyHex).toBe(keyHex);

    // And the reconstructed key is really usable — not just numerically equal.
    const sealed = await sealWithKey(keyHex, { secretData: 42 });
    const opened = await openWithKey(result.keyHex, sealed);
    expect(opened).toEqual({ secretData: 42 });
  });

  it('ignores stale collected shares left over from a since-regenerated split (unknown device ids)', async () => {
    const { registry } = buildAliceRegistry();
    const { recoverySplit } = await enableRecoveryUnlock({ registry });
    const result = attemptReconstruction({
      recoverySplit,
      collectedShares: [
        { deviceId: 'stale-device-from-old-split', x: 1, y: '123' },
        { deviceId: 'also-stale', x: 2, y: '456' },
      ],
    });
    expect(result.ok).toBe(false);
    expect(result.collectedCount).toBe(0);
  });
});
