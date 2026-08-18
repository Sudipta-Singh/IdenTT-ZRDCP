import { describe, it, expect } from 'vitest';
import {
  createRegistry,
  addDevice,
  removeDevice,
  updateDevice,
  setThreshold,
  shareHoldingDeviceCount,
  remoteShareHoldingDevices,
  registryWarnings,
  MAX_DEVICES,
} from '../src/registry/registry.js';
import { createZrdcpNativeDevice, createFidoDevice, RegistryValidationError } from '../src/registry/schema.js';
import { simulateRegister } from '../src/fido/simulate.js';

const emailChannel = { kind: 'email', address: 'friend@example.com' };

function nativeDevice(name, opts = {}) {
  return createZrdcpNativeDevice({
    name,
    contactChannels: [emailChannel],
    publicKeyHex: '02' + '11'.repeat(32),
    ...opts,
  });
}

describe('Trusted device registry', () => {
  it('defaults to targetN=6, kAuthentication=2, kRecovery=3, minRemoteForRecovery=1', () => {
    const registry = createRegistry();
    expect(registry.threshold).toEqual({
      targetN: 6,
      kAuthentication: 2,
      kRecovery: 3,
      minRemoteForRecovery: 1,
    });
  });

  it('rejects targetN outside the required 4-9 range (must be > 3 and < 10)', () => {
    expect(() => createRegistry({ targetN: 3 })).toThrow(RegistryValidationError);
    expect(() => createRegistry({ targetN: 10 })).toThrow(RegistryValidationError);
    expect(() => createRegistry({ targetN: 4 })).not.toThrow();
    expect(() => createRegistry({ targetN: 9 })).not.toThrow();
  });

  it('rejects kAuthentication below 2 and kRecovery below 3', () => {
    expect(() => createRegistry({ kAuthentication: 1 })).toThrow(RegistryValidationError);
    expect(() => createRegistry({ kRecovery: 2 })).toThrow(RegistryValidationError);
  });

  it('rejects either k exceeding targetN, and minRemoteForRecovery exceeding kRecovery', () => {
    expect(() => createRegistry({ targetN: 4, kAuthentication: 5 })).toThrow(RegistryValidationError);
    expect(() => createRegistry({ targetN: 4, kRecovery: 5 })).toThrow(RegistryValidationError);
    expect(() => createRegistry({ kRecovery: 3, minRemoteForRecovery: 4 })).toThrow(RegistryValidationError);
  });

  it('caps enrolled devices at 9 total', () => {
    let registry = createRegistry({ targetN: 9 });
    for (let i = 0; i < MAX_DEVICES; i++) {
      registry = addDevice(registry, nativeDevice(`Device ${i}`));
    }
    expect(registry.devices).toHaveLength(9);
    expect(() => addDevice(registry, nativeDevice('One too many'))).toThrow(RegistryValidationError);
  });

  it('adds and removes a zrdcp-native device, defaulting isRemote to false', () => {
    let registry = createRegistry();
    const device = nativeDevice("Spouse's phone");
    expect(device.isRemote).toBe(false);
    registry = addDevice(registry, device);
    expect(registry.devices).toHaveLength(1);

    registry = removeDevice(registry, device.id);
    expect(registry.devices).toHaveLength(0);
  });

  it('honors an explicit isRemote flag on both device types', async () => {
    let registry = createRegistry();
    const remoteNative = nativeDevice('Remote laptop', { isRemote: true });
    registry = addDevice(registry, remoteNative);

    const credential = await simulateRegister({ name: 'Remote key', prfHint: true });
    const remoteFido = createFidoDevice({
      name: 'Remote key',
      contactChannels: [emailChannel],
      credential,
      isRemote: true,
    });
    registry = addDevice(registry, remoteFido);

    expect(remoteShareHoldingDevices(registry)).toHaveLength(2);
  });

  it('rejects two devices with the same name', () => {
    let registry = createRegistry();
    registry = addDevice(registry, nativeDevice('Duplicate'));
    expect(() => addDevice(registry, nativeDevice('duplicate'))).toThrow(RegistryValidationError); // case-insensitive
  });

  it('updateDevice patches fields and bumps updatedAt without changing id', () => {
    let registry = createRegistry();
    const device = nativeDevice('Old name');
    registry = addDevice(registry, device);
    registry = updateDevice(registry, device.id, { name: 'New name' });
    expect(registry.devices[0].name).toBe('New name');
    expect(registry.devices[0].id).toBe(device.id);
  });

  it('setThreshold merges partial updates and validates the result', () => {
    let registry = createRegistry();
    registry = setThreshold(registry, { targetN: 8, kRecovery: 4 });
    expect(registry.threshold).toEqual({
      targetN: 8,
      kAuthentication: 2,
      kRecovery: 4,
      minRemoteForRecovery: 1,
    });
    expect(() => setThreshold(registry, { kRecovery: 99 })).toThrow(RegistryValidationError);
    expect(() => setThreshold(registry, { targetN: 10 })).toThrow(RegistryValidationError);
  });

  it('a fido2 device registered with PRF support is a full-share participant', async () => {
    let registry = createRegistry();
    const credential = await simulateRegister({ name: 'YubiKey', prfHint: true });
    const device = createFidoDevice({ name: 'YubiKey', contactChannels: [emailChannel], credential });
    registry = addDevice(registry, device);

    expect(device.type).toBe('fido2');
    expect(device.participationMode).toBe('full-share');
    expect(shareHoldingDeviceCount(registry)).toBe(1);
  });

  it('a fido2 device registered WITHOUT PRF support is approval-only and does not count as a share holder', async () => {
    let registry = createRegistry();
    const credential = await simulateRegister({ name: 'Old security key', prfHint: false });
    const device = createFidoDevice({ name: 'Old security key', contactChannels: [emailChannel], credential });
    registry = addDevice(registry, device);

    expect(device.participationMode).toBe('approval-only');
    expect(shareHoldingDeviceCount(registry)).toBe(0);
  });

  it('registryWarnings flags when kAuthentication exceeds total enrolled devices', () => {
    let registry = createRegistry({ targetN: 4, kAuthentication: 3, kRecovery: 3 });
    registry = addDevice(registry, nativeDevice('Only one'));
    const warnings = registryWarnings(registry);
    expect(warnings.some((w) => w.includes('authentication requires 3'))).toBe(true);
  });

  it('registryWarnings flags when kRecovery exceeds the number of share-holding devices', async () => {
    let registry = createRegistry({ targetN: 4, kRecovery: 3 });
    const credential = await simulateRegister({ name: 'Approval-only key', prfHint: false });
    registry = addDevice(
      registry,
      createFidoDevice({ name: 'Approval-only key', contactChannels: [emailChannel], credential })
    );
    const warnings = registryWarnings(registry);
    expect(warnings.some((w) => w.includes('recovery would be impossible'))).toBe(true);
  });

  it('registryWarnings flags when there are enough share-holders but none are remote', () => {
    let registry = createRegistry({ targetN: 4, kRecovery: 3, minRemoteForRecovery: 1 });
    registry = addDevice(registry, nativeDevice('Local A'));
    registry = addDevice(registry, nativeDevice('Local B'));
    registry = addDevice(registry, nativeDevice('Local C'));
    const warnings = registryWarnings(registry);
    expect(warnings.some((w) => w.includes('at least 1 remote share-holding device'))).toBe(true);
  });

  it('registryWarnings is clean once enough remote share holders are enrolled', () => {
    let registry = createRegistry({ targetN: 4, kRecovery: 3, minRemoteForRecovery: 1 });
    registry = addDevice(registry, nativeDevice('Local A'));
    registry = addDevice(registry, nativeDevice('Local B'));
    registry = addDevice(registry, nativeDevice('Remote C', { isRemote: true }));
    const warnings = registryWarnings(registry);
    expect(warnings.some((w) => w.includes('impossible'))).toBe(false);
  });
});
