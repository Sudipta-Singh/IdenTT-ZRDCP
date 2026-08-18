// IdenTT — per-recipient encryption of a single Shamir share.
//
// Dissertation §2.2 step 2: "Individual shares v_i = f(i) (mod q) are encrypted under the public
// keys PK_{S_i} of n secondary nodes: E_{S_i}(v_i) = AES-GCM-256_{ECDH(SK_{A_1}, PK_{S_i})}(v_i)"
//
// This module implements exactly that: an ECDH shared secret (between the initiating device's own
// persistent identity key and a recipient's public key) is used, via HKDF, to derive an AES-GCM
// key that wraps one share. It is deliberately the ONLY wrapping mechanism in the app — see
// src/fido/simulate.js's `deriveKeypairFromPrfOutput` for how a FIDO2 full-share device gets an
// ECDH-capable public key out of its WebAuthn PRF output, so it can be wrapped for exactly the
// same way as a zrdcp-native device's key. That equivalence is what makes the hybrid
// zrdcp-native/fido2 mesh from src/registry/ work with one wrapping code path instead of two.
//
// Note on key reuse: the dissertation's formula uses the initiator's static SK_{A_1} for every
// recipient (not a fresh ephemeral key per share). This implementation follows that literally.
// A true one-time ephemeral sender key per session would add forward secrecy against a future
// compromise of the device's long-term identity key — worth considering as a Phase 6+ hardening,
// noted here rather than silently changed.

import { secp256k1, hexToBytes, bytesToHex } from './curve.js';

const SUBTLE = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();
const HKDF_INFO = enc.encode('ZRDCP/1.0 share-wrap AES-GCM key');

async function deriveAesKey(sharedSecretBytes) {
  const keyMaterial = await SUBTLE.importKey('raw', sharedSecretBytes, 'HKDF', false, ['deriveKey']);
  return SUBTLE.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: HKDF_INFO },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

function serializeShare(share) {
  return enc.encode(JSON.stringify({ x: share.x, y: share.y.toString() }));
}

function deserializeShare(bytes) {
  const obj = JSON.parse(dec.decode(bytes));
  return { x: obj.x, y: BigInt(obj.y) };
}

/**
 * Encrypts one Shamir share `{x, y}` for a single recipient, using ECDH between the sender's
 * identity keypair and the recipient's public key.
 *
 * @param {object} args
 * @param {{x: number, y: bigint}} args.share
 * @param {{privateKeyHex: string, publicKeyHex: string}} args.senderIdentity - the local device's
 *   own persistent ZRDCP identity keypair (`registry.localIdentity`).
 * @param {string} args.recipientPublicKeyHex - the recipient's ECDH-capable public key: either a
 *   zrdcp-native device's `publicKeyHex`, or a fido2 full-share device's `fido.derivedPublicKeyHex`.
 * @returns {{method: string, senderPublicKeyHex: string, ivHex: string, ciphertextHex: string}}
 *   JSON-serializable wrapped share, matching the shape of the dissertation's SHARE_DELIVERY
 *   message (`ephemeral_dh_pubkey` -> `senderPublicKeyHex` here — see the module note on why it's
 *   the sender's static key rather than a true ephemeral one; `encrypted_share` -> `ciphertextHex`,
 *   which already carries the AES-GCM authentication tag appended by WebCrypto).
 */
export async function wrapShare({ share, senderIdentity, recipientPublicKeyHex }) {
  const sharedSecret = secp256k1.getSharedSecret(
    hexToBytes(senderIdentity.privateKeyHex),
    hexToBytes(recipientPublicKeyHex)
  );
  const key = await deriveAesKey(sharedSecret);
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const ciphertextBuf = await SUBTLE.encrypt({ name: 'AES-GCM', iv }, key, serializeShare(share));

  return {
    method: 'ecdh-secp256k1-hkdf-aes256gcm',
    senderPublicKeyHex: senderIdentity.publicKeyHex,
    ivHex: bytesToHex(iv),
    ciphertextHex: bytesToHex(new Uint8Array(ciphertextBuf)),
  };
}

/**
 * Reverses `wrapShare`: the recipient recomputes the same ECDH shared secret using their own
 * private key and the sender's public key (included in the wrapped payload), then decrypts.
 *
 * @param {object} args
 * @param {ReturnType<typeof wrapShare>} args.wrapped
 * @param {string} args.recipientPrivateKeyHex - the recipient's own private key: a zrdcp-native
 *   device's identity private key, or a fido2 full-share device's PRF-derived private key
 *   (recomputed fresh from a WebAuthn assertion each time — never stored).
 * @returns {{x: number, y: bigint}}
 */
export async function unwrapShare({ wrapped, recipientPrivateKeyHex }) {
  const sharedSecret = secp256k1.getSharedSecret(
    hexToBytes(recipientPrivateKeyHex),
    hexToBytes(wrapped.senderPublicKeyHex)
  );
  const key = await deriveAesKey(sharedSecret);
  try {
    const plaintextBuf = await SUBTLE.decrypt(
      { name: 'AES-GCM', iv: hexToBytes(wrapped.ivHex) },
      key,
      hexToBytes(wrapped.ciphertextHex)
    );
    return deserializeShare(new Uint8Array(plaintextBuf));
  } catch {
    throw new ShareUnwrapError();
  }
}

export class ShareUnwrapError extends Error {
  constructor() {
    super('Could not unwrap share: wrong key, or the payload was tampered with in transit.');
    this.name = 'ShareUnwrapError';
  }
}
