// IdenTT — passphrase-sealed local vault.
//
// The trusted-device registry (names, contact channels, public keys) is sensitive enough that it
// shouldn't sit on disk/localStorage in plaintext. This module seals/opens it with a
// passphrase-derived AES-GCM key. Built entirely on WebCrypto, which is available identically in
// the browser and in modern Node — so this is unit-testable under Vitest with zero DOM shims, and
// the exact same code runs in the shipped app.

const SUBTLE = globalThis.crypto.subtle;

// OWASP's 2023 minimum recommendation for PBKDF2-HMAC-SHA256. Stored alongside each sealed vault
// so it can be safely raised later without breaking the ability to open older vaults.
export const DEFAULT_PBKDF2_ITERATIONS = 210_000;

const enc = new TextEncoder();
const dec = new TextDecoder();

export function randomBytes(len) {
  return globalThis.crypto.getRandomValues(new Uint8Array(len));
}

function toB64(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function fromB64(str) {
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function deriveKey(passphrase, salt, iterations) {
  const keyMaterial = await SUBTLE.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return SUBTLE.deriveKey(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts `plaintextObj` (any JSON-serializable value) under a key derived from `passphrase`.
 * A fresh random salt and IV are generated every call, so sealing the same object twice with the
 * same passphrase produces different ciphertext (standard AES-GCM hygiene — never reuse an IV
 * under the same key).
 *
 * @returns {object} a plain JSON-serializable "sealed vault" record — safe to write to disk.
 */
export async function seal(passphrase, plaintextObj, iterations = DEFAULT_PBKDF2_ITERATIONS) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKey(passphrase, salt, iterations);
  const plaintext = enc.encode(JSON.stringify(plaintextObj));
  const ciphertextBuf = await SUBTLE.encrypt({ name: 'AES-GCM', iv }, key, plaintext);

  return {
    v: 1,
    kdf: 'PBKDF2-SHA256',
    iterations,
    salt: toB64(salt),
    iv: toB64(iv),
    ciphertext: toB64(new Uint8Array(ciphertextBuf)),
  };
}

/**
 * Decrypts a sealed vault record produced by `seal`. Throws `WrongPassphraseOrCorruptVaultError`
 * if the passphrase is wrong OR the ciphertext was tampered with — AES-GCM's authentication tag
 * makes those two cases indistinguishable by design, which is exactly what you want (no oracle
 * telling an attacker "close, but the passphrase was wrong" vs "the file is corrupted").
 */
export async function open(passphrase, sealedVault) {
  const salt = fromB64(sealedVault.salt);
  const iv = fromB64(sealedVault.iv);
  const key = await deriveKey(passphrase, salt, sealedVault.iterations);

  try {
    const plaintextBuf = await SUBTLE.decrypt(
      { name: 'AES-GCM', iv },
      key,
      fromB64(sealedVault.ciphertext)
    );
    return JSON.parse(dec.decode(plaintextBuf));
  } catch {
    throw new WrongPassphraseOrCorruptVaultError();
  }
}

export class WrongPassphraseOrCorruptVaultError extends Error {
  constructor() {
    super('Wrong passphrase, or the vault data is corrupted/tampered.');
    this.name = 'WrongPassphraseOrCorruptVaultError';
  }
}

const RAW_KEY_INFO = enc.encode('ZRDCP/1.0 IdenTT vault-unlock-key AES-GCM');

async function deriveKeyFromRawMaterial(keyBytes, salt) {
  const keyMaterial = await SUBTLE.importKey('raw', keyBytes, 'HKDF', false, ['deriveKey']);
  return SUBTLE.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt, info: RAW_KEY_INFO },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function hexToBytesLocal(hex) {
  const clean = hex.length % 2 ? '0' + hex : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/**
 * Seals `plaintextObj` under a key derived (via HKDF, not PBKDF2) directly from `keyHex` — 32
 * bytes of already-high-entropy key material, NOT a human passphrase. This is what a
 * `recovery`-unlock-policy vault uses instead of `seal()`: the key material is a freshly generated
 * random scalar (see `src/vault/unlockRecovery.js`) that is itself protected by being Shamir-split
 * across the vault's own trusted-device mesh, rather than by anything the user has to remember.
 * PBKDF2's deliberate slowness exists to blunt brute-forcing a low-entropy human passphrase — it
 * would be pure wasted CPU here, since `keyHex` is already uniformly random and never brute-forced
 * directly (an attacker would have to break Shamir's secrecy property instead).
 */
export async function sealWithKey(keyHex, plaintextObj) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKeyFromRawMaterial(hexToBytesLocal(keyHex), salt);
  const plaintext = enc.encode(JSON.stringify(plaintextObj));
  const ciphertextBuf = await SUBTLE.encrypt({ name: 'AES-GCM', iv }, key, plaintext);

  return {
    v: 1,
    kdf: 'HKDF-SHA256-rawkey',
    salt: toB64(salt),
    iv: toB64(iv),
    ciphertext: toB64(new Uint8Array(ciphertextBuf)),
  };
}

/** Inverse of `sealWithKey`. Throws `WrongPassphraseOrCorruptVaultError` (same class — the failure
 * mode is identical: wrong key or tampered ciphertext, indistinguishable by AES-GCM design) if
 * `keyHex` doesn't match or the data was tampered with. */
export async function openWithKey(keyHex, sealedVault) {
  const salt = fromB64(sealedVault.salt);
  const iv = fromB64(sealedVault.iv);
  const key = await deriveKeyFromRawMaterial(hexToBytesLocal(keyHex), salt);

  try {
    const plaintextBuf = await SUBTLE.decrypt({ name: 'AES-GCM', iv }, key, fromB64(sealedVault.ciphertext));
    return JSON.parse(dec.decode(plaintextBuf));
  } catch {
    throw new WrongPassphraseOrCorruptVaultError();
  }
}
