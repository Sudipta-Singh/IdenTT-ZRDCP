// IdenTT — trusted-device registry data model.
//
// A "trusted device" is anything that can act as a node S_i in a ZRDCP recovery mesh. There are
// two kinds, reflecting the user's requirement that FIDO2/WebAuthn hardware be treated as a
// first-class trusted device type alongside devices running the ZRDCP app itself:
//
//   - 'zrdcp-native' — a peer running this same app/protocol. Identified by a public key used to
//     wrap its Shamir share (ECDH + AES-GCM, per dissertation §2.2 step 2).
//   - 'fido2'        — a WebAuthn authenticator (security key, Touch ID, Windows Hello, etc.).
//     Identified by its credential ID + public key from registration. Its `participationMode`
//     (decided at enrollment, see src/fido/simulate.js) is either:
//       - 'full-share'    — holds a genuine Shamir share, wrapped with a key derived from the
//                           authenticator's PRF/hmac-secret extension output. A successful
//                           WebAuthn assertion is what unwraps it.
//       - 'approval-only' — holds no share math. A successful WebAuthn assertion counts as one
//                           of the k approvals needed, but contributes nothing to reconstructing
//                           H(C_r) itself. (Authenticators without PRF support fall here.)
//
// This module only defines shapes + small pure validators — no I/O, no crypto. See registry.js
// for the CRUD operations that build on it.

export const DEVICE_TYPES = Object.freeze({
  ZRDCP_NATIVE: 'zrdcp-native',
  FIDO2: 'fido2',
});

export const PARTICIPATION_MODES = Object.freeze({
  FULL_SHARE: 'full-share',
  APPROVAL_ONLY: 'approval-only',
});

export const CONTACT_KINDS = Object.freeze({
  EMAIL: 'email',
  SMS: 'sms',
  VOICE: 'voice',
  WEBAPI: 'webapi',
  RESPONDER_LINK: 'responder-link',
});

function assert(condition, message) {
  if (!condition) throw new RegistryValidationError(message);
}

export class RegistryValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RegistryValidationError';
  }
}

function nowIso() {
  return new Date().toISOString();
}

let idCounter = 0;
/** Simple, dependency-free unique ID generator (avoids pulling in a uuid package for this). */
export function makeId(prefix = 'dev') {
  idCounter += 1;
  const rand = globalThis.crypto.getRandomValues(new Uint8Array(8));
  const randHex = Array.from(rand, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${prefix}_${Date.now().toString(36)}_${idCounter}_${randHex}`;
}

export function validateContactChannel(channel) {
  assert(channel && typeof channel === 'object', 'contact channel must be an object');
  assert(
    Object.values(CONTACT_KINDS).includes(channel.kind),
    `contact channel kind must be one of: ${Object.values(CONTACT_KINDS).join(', ')}`
  );
  assert(typeof channel.address === 'string' && channel.address.length > 0, 'contact channel address is required');
}

/**
 * @param {object} args
 * @param {string} args.name - human-readable label, e.g. "Sudipta's laptop".
 * @param {object[]} args.contactChannels - how to reach this device during dispatch.
 * @param {string} args.publicKeyHex - ECDH public key (compressed SEC1 hex) for share wrapping.
 * @param {boolean} [args.isRemote] - true if this device is NOT physically co-located with the
 *   primary device (e.g. kept at a different address, carried by someone else). Recovery requires
 *   at least one remote share-holding device among its approvers (`registry.threshold.minRemoteForRecovery`)
 *   so that possession of every device in one place isn't sufficient to recover the account.
 */
export function createZrdcpNativeDevice({ name, contactChannels, publicKeyHex, isRemote = false }) {
  assert(typeof name === 'string' && name.trim().length > 0, 'device name is required');
  assert(Array.isArray(contactChannels) && contactChannels.length > 0, 'at least one contact channel is required');
  contactChannels.forEach(validateContactChannel);
  assert(typeof publicKeyHex === 'string' && /^[0-9a-fA-F]+$/.test(publicKeyHex), 'publicKeyHex must be a hex string');

  return {
    id: makeId('zrdcp'),
    type: DEVICE_TYPES.ZRDCP_NATIVE,
    name: name.trim(),
    contactChannels,
    publicKeyHex,
    isRemote: Boolean(isRemote),
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
}

/**
 * @param {object} args
 * @param {string} args.name
 * @param {object[]} args.contactChannels
 * @param {boolean} [args.isRemote] - see `createZrdcpNativeDevice`'s doc for what this means.
 * @param {object} args.credential - shape produced by src/fido/simulate.js (or, later, a real
 *   navigator.credentials.create() result adapted to the same shape): { credentialId,
 *   publicKeyJwk, prfSupported, transports, simulated }.
 */
export function createFidoDevice({ name, contactChannels, credential, isRemote = false }) {
  assert(typeof name === 'string' && name.trim().length > 0, 'device name is required');
  assert(Array.isArray(contactChannels) && contactChannels.length > 0, 'at least one contact channel is required');
  contactChannels.forEach(validateContactChannel);
  assert(credential && typeof credential.credentialId === 'string', 'credential.credentialId is required');
  assert(credential.publicKeyJwk && typeof credential.publicKeyJwk === 'object', 'credential.publicKeyJwk is required');
  assert(typeof credential.prfSupported === 'boolean', 'credential.prfSupported must be boolean');

  const participationMode = credential.prfSupported
    ? PARTICIPATION_MODES.FULL_SHARE
    : PARTICIPATION_MODES.APPROVAL_ONLY;

  if (participationMode === PARTICIPATION_MODES.FULL_SHARE) {
    assert(
      typeof credential.derivedPublicKeyHex === 'string' && credential.derivedPublicKeyHex.length > 0,
      'a PRF-capable credential must include derivedPublicKeyHex (see src/fido/simulate.js)'
    );
  }

  return {
    id: makeId('fido'),
    type: DEVICE_TYPES.FIDO2,
    name: name.trim(),
    contactChannels,
    fido: {
      credentialId: credential.credentialId,
      publicKeyJwk: credential.publicKeyJwk,
      prfSupported: credential.prfSupported,
      // ECDH-capable public key derived from this device's PRF output (see
      // src/fido/simulate.js's module comment for the full mechanism) — null for approval-only
      // devices, which never hold share math and so never need one.
      derivedPublicKeyHex: credential.derivedPublicKeyHex ?? null,
      transports: credential.transports ?? [],
      simulated: credential.simulated ?? false,
    },
    participationMode,
    isRemote: Boolean(isRemote),
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
}
