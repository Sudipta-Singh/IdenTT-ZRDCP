// ZRDCP crypto core — group setup.
//
// Concretizes the dissertation's generic group G of prime order q as the secp256k1 elliptic
// curve. See README.md in this directory for the notation mapping.

import { secp256k1, secp256k1_hasher } from '@noble/curves/secp256k1.js';

export { secp256k1 };

/** Scalar field order (dissertation's `q`). All exponents/blinding factors live mod this. */
export const ORDER = secp256k1.Point.Fn.ORDER;

/** Base generator (dissertation's `g`). */
export const G = secp256k1.Point.BASE;

/**
 * Second Pedersen generator (dissertation's `h`), derived via hash-to-curve of a fixed domain
 * string rather than as `t * G` for a known `t` — this is what makes it "independent" of G with
 * no discoverable discrete-log relationship, which is required for the commitment's binding
 * property to hold. See RFC 9380 for the hash-to-curve construction used under the hood.
 */
export const H = secp256k1_hasher.hashToCurve(
  new TextEncoder().encode('ZRDCP/1.0 Pedersen generator h — nothing-up-my-sleeve')
);

/** Reduce a bigint into [0, ORDER). Handles negative inputs (JS `%` keeps the sign). */
export function mod(x) {
  const r = x % ORDER;
  return r < 0n ? r + ORDER : r;
}

/** A cryptographically random scalar in [1, ORDER). Used for blinding factors and NIZK nonces. */
export function randomScalar() {
  // secp256k1.utils.randomSecretKey() returns a uniformly random valid scalar as bytes.
  const bytes = secp256k1.utils.randomSecretKey();
  return bytesToScalar(bytes);
}

export function bytesToScalar(bytes) {
  let x = 0n;
  for (const b of bytes) x = (x << 8n) | BigInt(b);
  return mod(x);
}

/** Serialize a curve point to a hex string (compressed SEC1 form) for transport/hashing. */
export function pointToHex(point) {
  return point.toHex(true);
}

/** Inverse of `pointToHex` — parses a compressed SEC1 hex string back into a curve point.
 * Accepts an optional "0x" prefix, since wire messages (src/protocol/messages.js) use one. */
export function pointFromHex(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  return secp256k1.Point.fromHex(clean);
}

const HEX_CHARS = '0123456789abcdef';

/** Fixed-width (32-byte) big-endian hex encoding of a scalar — the private-key wire format used
 * throughout this app (device identities, both sides of an ECDH exchange). */
export function scalarToHex(scalar) {
  let hex = mod(scalar).toString(16);
  while (hex.length < 64) hex = '0' + hex;
  return hex;
}

export function hexToScalar(hex) {
  return mod(BigInt('0x' + hex));
}

export function hexToBytes(hex) {
  const clean = hex.length % 2 ? '0' + hex : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

export function bytesToHex(bytes) {
  let out = '';
  for (const b of bytes) out += HEX_CHARS[b >> 4] + HEX_CHARS[b & 0xf];
  return out;
}

/**
 * Generates a device's own persistent ZRDCP identity keypair (distinct from the trusted-device
 * registry, which holds OTHER devices' public keys). This is the SK_{A_1}/PK_{A_1} the
 * dissertation's §2.2 share-wrapping formula refers to — every device running IdenTT has one,
 * generated once (at vault creation) and reused for every ECDH exchange with every peer.
 */
export function generateIdentityKeypair() {
  const privateScalar = randomScalar();
  const publicPoint = G.multiply(privateScalar);
  return {
    privateKeyHex: scalarToHex(privateScalar),
    publicKeyHex: pointToHex(publicPoint),
  };
}

/** Modular exponentiation: base^exp mod ORDER, exp >= 0. Used for modular inverse below. */
export function modPow(base, exp) {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = mod(result * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return result;
}

/**
 * Modular multiplicative inverse of `x` mod ORDER, via Fermat's little theorem (ORDER is prime
 * for secp256k1's scalar field, so x^(ORDER-2) === x^-1 mod ORDER for any x != 0).
 */
export function modInverse(x) {
  const xr = mod(x);
  if (xr === 0n) throw new RangeError('modInverse: 0 has no inverse');
  return modPow(xr, ORDER - 2n);
}
