import { describe, it, expect } from 'vitest';
import { createRegistry, addDevice } from '../src/registry/registry.js';
import { createZrdcpNativeDevice, CONTACT_KINDS } from '../src/registry/schema.js';
import { G, randomScalar, pointToHex } from '../src/crypto/curve.js';
import { buildDecoySession, decoyOutcome } from '../src/recovery/decoy.js';

function demoDevice(name, { isRemote = false } = {}) {
  const pub = G.multiply(randomScalar());
  return createZrdcpNativeDevice({
    name,
    contactChannels: [{ kind: CONTACT_KINDS.EMAIL, address: `${name}@example.com` }],
    publicKeyHex: pointToHex(pub),
    isRemote,
  });
}

function registryWithDevices(n) {
  let registry = createRegistry();
  for (let i = 0; i < n; i++) {
    registry = addDevice(registry, demoDevice(`device-${i}`, { isRemote: i === 0 }));
  }
  return registry;
}

describe('decoy.js (DECOY_EXEC)', () => {
  it('buildDecoySession is shaped like a real initiateRecovery session', () => {
    const registry = registryWithDevices(3);
    const session = buildDecoySession({ registry, purpose: 'recovery' });
    expect(session.decoy).toBe(true);
    expect(session.purpose).toBe('recovery');
    expect(session.requiredK).toBe(registry.threshold.kRecovery);
    expect(session.minRemoteForRecovery).toBe(registry.threshold.minRemoteForRecovery);
    expect(session.sessionId).toBeTypeOf('string');
    expect(session.recoveryInit.pedersen_commitment).toBeTypeOf('string');
    expect(session.dispatches).toHaveLength(3);
    for (const d of session.dispatches) {
      expect(d).toHaveProperty('deviceId');
      expect(d).toHaveProperty('deviceName');
      expect(d).toHaveProperty('channelKind');
      expect(d).toHaveProperty('address');
      expect(d).toHaveProperty('hasShare');
      expect(d).toHaveProperty('isRemote');
    }
  });

  it('withholds real payload/link details on every dispatch row', () => {
    const registry = registryWithDevices(2);
    const session = buildDecoySession({ registry });
    for (const d of session.dispatches) {
      expect(d.payloadPreview).toBe('(withheld)');
      expect(d.responderLink).toBe('');
    }
  });

  it('minRemoteForRecovery is null for an authentication-purpose decoy, same as a real session', () => {
    const registry = registryWithDevices(2);
    const session = buildDecoySession({ registry, purpose: 'authentication' });
    expect(session.minRemoteForRecovery).toBeNull();
    expect(session.requiredK).toBe(registry.threshold.kAuthentication);
  });

  it('decoyOutcome always reports success, in the same shape evaluateChallengeOutcome uses', () => {
    const registry = registryWithDevices(3);
    const recoverySession = buildDecoySession({ registry, purpose: 'recovery' });
    const outcome = decoyOutcome(recoverySession);
    expect(outcome.granted).toBe(true);
    expect(outcome.purpose).toBe('recovery');
    expect(outcome.successCount).toBe(outcome.requiredK);
    expect(outcome.remoteSuccessCount).toBe(outcome.minRemoteForRecovery);
    expect(outcome.reason).toContain('share-holders responded');

    const authSession = buildDecoySession({ registry, purpose: 'authentication' });
    const authOutcome = decoyOutcome(authSession);
    expect(authOutcome.granted).toBe(true);
    expect(authOutcome.reason).toContain('required approvals received');
  });

  it('never touches the real device count requirement — works even with zero devices', () => {
    const registry = createRegistry();
    const session = buildDecoySession({ registry, purpose: 'authentication' });
    expect(session.dispatches).toEqual([]);
    expect(decoyOutcome(session).granted).toBe(true);
  });
});
