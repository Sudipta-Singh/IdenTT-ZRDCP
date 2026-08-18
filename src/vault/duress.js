// IdenTT — duress passcode: a secondary runtime code that, when entered on the Requests tab
// instead of the real one, must produce an indistinguishable fake "success" while silently
// logging the event — modeled on the dissertation's DECOY_EXEC state. See src/recovery/decoy.js
// for the fake-session builder this unlocks, and src/vault/history.js for why the resulting log
// entry is only ever visible to someone who has genuinely authenticated as the vault's owner.
//
// The passcode itself is never stored reversibly — only a salted PBKDF2 hash, the same pattern
// src/vault/vault.js already uses to turn a passphrase into a key, adapted here with `deriveBits`
// (a comparable digest) instead of `deriveKey` (an unextractable AES-GCM key), since this needs to
// be *compared* against future input, not used to encrypt anything.
//
// Also home to the optional "default authentication code" convenience field (component 3's
// "authentication passcodes"): unlike the duress code and the protocol's normal runtime codes,
// this one is intentionally stored in plain text (inside the already-encrypted vault blob) purely
// to prefill the runtime-code field on the Requests tab — it remains fully overridable per attempt,
// and skipping it changes nothing about how a challenge is computed.

const SUBTLE = globalThis.crypto.subtle;
const ITERATIONS = 210_000;

function randomBytes(len) {
  return globalThis.crypto.getRandomValues(new Uint8Array(len));
}
function toB64(bytes) {
  return btoa(String.fromCharCode(...bytes));
}
function fromB64(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

async function pbkdf2Hash(passcode, saltBytes, iterations) {
  const keyMaterial = await SUBTLE.importKey('raw', new TextEncoder().encode(passcode), 'PBKDF2', false, [
    'deriveBits',
  ]);
  const bits = await SUBTLE.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations, hash: 'SHA-256' }, keyMaterial, 256);
  return toB64(new Uint8Array(bits));
}

export class DuressError extends Error {
  constructor(message) {
    super(message);
    this.name = 'DuressError';
  }
}

/** Returns a NEW registry with `registry.duressPasscode` set to a salted hash of `passcode`. */
export async function setDuressPasscode(registry, passcode) {
  if (!passcode || passcode.length < 4) {
    throw new DuressError('duress passcode must be at least 4 characters');
  }
  const salt = randomBytes(16);
  const hash = await pbkdf2Hash(passcode, salt, ITERATIONS);
  return { ...registry, duressPasscode: { salt: toB64(salt), hash, iterations: ITERATIONS } };
}

/** Returns a NEW registry with the duress passcode removed. */
export function clearDuressPasscode(registry) {
  const { duressPasscode, ...rest } = registry;
  return rest;
}

export function hasDuressPasscode(registry) {
  return !!registry.duressPasscode;
}

/** @returns {Promise<boolean>} true iff `candidate` hashes to the stored duress passcode. Safe to
 * call with an empty/undefined candidate or a vault with no duress passcode configured — both
 * simply return false rather than throwing, since this sits on the hot path of every ordinary
 * (non-duress) challenge initiation. */
export async function isDuressPasscode(registry, candidate) {
  if (!registry.duressPasscode || !candidate) return false;
  const salt = fromB64(registry.duressPasscode.salt);
  const hash = await pbkdf2Hash(candidate, salt, registry.duressPasscode.iterations);
  return hash === registry.duressPasscode.hash;
}

/** Returns a NEW registry with the optional plaintext "default authentication code" set/cleared. */
export function setDefaultAuthCode(registry, code) {
  return { ...registry, defaultAuthCode: code ? code : null };
}

export function getDefaultAuthCode(registry) {
  return registry.defaultAuthCode ?? null;
}
