// IdenTT — trusted-device registry CRUD (pure functions, no I/O).
//
// A registry is a plain JSON-serializable object:
//   { version, threshold: { targetN, kAuthentication, kRecovery, minRemoteForRecovery }, devices: [...], updatedAt }
//
// Per the user's requirements:
//   - `targetN` — the mesh size you're building toward. Must be strictly between 3 and 10 (i.e.
//     4-9 devices) — an arbitrary-but-bounded mesh size, not the earlier fixed "6". Advisory, not
//     a hard floor: you can have fewer devices enrolled than targetN while building out your mesh
//     (registryWarnings() flags it). The actual device count IS hard-capped at 9 (see addDevice)
//     — the mesh can never exceed the upper bound regardless of targetN.
//   - `kAuthentication` — devices needed to approve a lightweight AUTHENTICATION challenge (proof
//     of liveness/consent for ongoing use). Any device type counts; no secret reconstruction is
//     involved. Minimum 2.
//   - `kRecovery` — devices needed to approve + actually reconstruct the secret for a full
//     RECOVERY. Requires real Shamir shares (only share-holding devices count), not just
//     approvals. Minimum 3.
//   - `minRemoteForRecovery` — of the kRecovery approvers, at least this many must be flagged
//     `isRemote` (not physically co-located with the primary device), so possessing every
//     co-located device isn't sufficient to recover the account. Minimum 1.

import { RegistryValidationError } from './schema.js';

const CURRENT_VERSION = 2;
const MAX_DEVICES = 9;
const MIN_TARGET_N = 4; // strictly greater than 3
const MAX_TARGET_N = 9; // strictly less than 10

export function createRegistry({ targetN = 6, kAuthentication = 2, kRecovery = 3, minRemoteForRecovery = 1 } = {}) {
  const threshold = { targetN, kAuthentication, kRecovery, minRemoteForRecovery };
  validateThreshold(threshold);
  return {
    version: CURRENT_VERSION,
    threshold,
    devices: [],
    updatedAt: new Date().toISOString(),
  };
}

function validateThreshold({ targetN, kAuthentication, kRecovery, minRemoteForRecovery }) {
  if (!Number.isInteger(targetN) || targetN < MIN_TARGET_N || targetN > MAX_TARGET_N) {
    throw new RegistryValidationError(
      `targetN must be an integer greater than 3 and less than 10 (i.e. ${MIN_TARGET_N}-${MAX_TARGET_N}); got ${targetN}`
    );
  }
  if (!Number.isInteger(kAuthentication) || kAuthentication < 2) {
    throw new RegistryValidationError('kAuthentication must be an integer >= 2');
  }
  if (!Number.isInteger(kRecovery) || kRecovery < 3) {
    throw new RegistryValidationError('kRecovery must be an integer >= 3');
  }
  if (kAuthentication > targetN) {
    throw new RegistryValidationError(`kAuthentication (${kAuthentication}) cannot exceed targetN (${targetN})`);
  }
  if (kRecovery > targetN) {
    throw new RegistryValidationError(`kRecovery (${kRecovery}) cannot exceed targetN (${targetN})`);
  }
  if (!Number.isInteger(minRemoteForRecovery) || minRemoteForRecovery < 1) {
    throw new RegistryValidationError('minRemoteForRecovery must be an integer >= 1');
  }
  if (minRemoteForRecovery > kRecovery) {
    throw new RegistryValidationError(
      `minRemoteForRecovery (${minRemoteForRecovery}) cannot exceed kRecovery (${kRecovery})`
    );
  }
}

function touch(registry) {
  return { ...registry, updatedAt: new Date().toISOString() };
}

/** Returns a NEW registry object with `device` appended (registries are treated as immutable). */
export function addDevice(registry, device) {
  if (registry.devices.length >= MAX_DEVICES) {
    throw new RegistryValidationError(
      `this mesh already has the maximum of ${MAX_DEVICES} trusted devices — remove one before adding another`
    );
  }
  const nameCollision = registry.devices.some(
    (d) => d.name.toLowerCase() === device.name.toLowerCase()
  );
  if (nameCollision) {
    throw new RegistryValidationError(`a device named "${device.name}" already exists`);
  }
  return touch({ ...registry, devices: [...registry.devices, device] });
}

export function removeDevice(registry, deviceId) {
  const exists = registry.devices.some((d) => d.id === deviceId);
  if (!exists) {
    throw new RegistryValidationError(`no device with id ${deviceId}`);
  }
  return touch({ ...registry, devices: registry.devices.filter((d) => d.id !== deviceId) });
}

export function updateDevice(registry, deviceId, patch) {
  let found = false;
  const devices = registry.devices.map((d) => {
    if (d.id !== deviceId) return d;
    found = true;
    return { ...d, ...patch, id: d.id, updatedAt: new Date().toISOString() };
  });
  if (!found) throw new RegistryValidationError(`no device with id ${deviceId}`);
  return touch({ ...registry, devices });
}

export function setThreshold(registry, patch) {
  const next = { ...registry.threshold, ...patch };
  validateThreshold(next);
  return touch({ ...registry, threshold: next });
}

/**
 * How many currently-enrolled devices actually contribute to reconstructing the secret — i.e.
 * zrdcp-native devices plus fido2 devices in 'full-share' mode. Approval-only fido2 devices are
 * excluded, since (per the hybrid model) they can approve an AUTHENTICATION challenge but hold no
 * share, so they can never contribute to a RECOVERY reconstruction. Useful for warning the user if
 * kRecovery exceeds this count, which would make recovery mathematically impossible even with
 * every approval-only device also agreeing.
 */
export function shareHoldingDeviceCount(registry) {
  return shareHoldingDevices(registry).length;
}

/** The actual list of devices that hold real share math (see shareHoldingDeviceCount's doc). */
export function shareHoldingDevices(registry) {
  return registry.devices.filter(
    (d) => d.type === 'zrdcp-native' || d.participationMode === 'full-share'
  );
}

/** Share-holding devices flagged `isRemote` — the pool recovery's remote requirement draws from. */
export function remoteShareHoldingDevices(registry) {
  return shareHoldingDevices(registry).filter((d) => d.isRemote);
}

/**
 * The ECDH-capable public key to wrap a share under, for any share-holding device — a
 * zrdcp-native device's own identity key, or a fido2 full-share device's PRF-derived key. This is
 * the one place that knows "which public key field" so callers (recovery orchestration) don't
 * have to branch on device type themselves.
 */
export function ecdhPublicKeyForDevice(device) {
  if (device.type === 'zrdcp-native') return device.publicKeyHex;
  if (device.type === 'fido2' && device.participationMode === 'full-share') {
    return device.fido.derivedPublicKeyHex;
  }
  throw new RegistryValidationError(
    `device ${device.id} (${device.name}) is not share-holding — it has no ECDH-capable public key`
  );
}

/**
 * Non-fatal warnings about the current registry state, surfaced by the UI rather than thrown —
 * none of these block saving (you're allowed to build up your mesh incrementally).
 */
export function registryWarnings(registry) {
  const warnings = [];
  const { targetN, kAuthentication, kRecovery, minRemoteForRecovery } = registry.threshold;
  const enrolled = registry.devices.length;
  const holders = shareHoldingDevices(registry);
  const remoteHolders = remoteShareHoldingDevices(registry);

  if (enrolled < targetN) {
    warnings.push(`${enrolled} of ${targetN} target trusted devices enrolled.`);
  }
  if (enrolled > 0 && enrolled < MIN_TARGET_N) {
    warnings.push(`A valid mesh needs at least ${MIN_TARGET_N} trusted devices — currently ${enrolled}.`);
  }
  if (enrolled > 0 && enrolled < kAuthentication) {
    warnings.push(
      `Only ${enrolled} device(s) enrolled, but authentication requires ${kAuthentication} approvals — authentication would be impossible.`
    );
  }
  if (enrolled > 0 && holders.length < kRecovery) {
    warnings.push(
      `Only ${holders.length} enrolled device(s) can hold a real share, but recovery requires ${kRecovery} — recovery would be impossible even with full approval. Add more zrdcp-native or PRF-capable FIDO2 devices, or lower kRecovery.`
    );
  }
  if (enrolled > 0 && holders.length >= kRecovery && remoteHolders.length < minRemoteForRecovery) {
    warnings.push(
      `Recovery requires at least ${minRemoteForRecovery} remote share-holding device(s), but only ${remoteHolders.length} enrolled/flagged as remote — recovery would be impossible even with enough approvals.`
    );
  }
  return warnings;
}

export { MAX_DEVICES, MIN_TARGET_N, MAX_TARGET_N };
