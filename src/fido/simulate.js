// IdenTT — simulated FIDO2/WebAuthn ceremonies (Phase 1 scaffold, extended in Phase 2 with
// PRF-based key derivation).
//
// Real WebAuthn registration/authentication (navigator.credentials.create()/get()) requires a
// secure context (https:// or http://localhost) AND a relying-party backend to issue challenges
// and verify attestations/assertions — neither of which a bare `file://` static page can provide.
// Per the plan (docs/PLAN.md), real WebAuthn is deferred to the same later phase as real
// Twilio/SMTP integration, once a small local server exists.
//
// This module produces objects SHAPED like real WebAuthn results (credential ID, a public key,
// a prfSupported flag, transports) so every other layer — schema.js's createFidoDevice,
// registry.js, and the Phase 2 share-wrapping/dispatch logic — can be built and tested against the
// real interface now, and swapped to a real `src/fido/webauthn.js` later without touching any
// calling code. That real module should export the same function signatures used here:
// `simulateRegister({ name, prfHint }) -> credential`,
// `simulateAssert(credential, challenge) -> assertion`, and
// `simulateGetPrfOutput(credential, salt) -> Uint8Array`.
//
// How a full-share FIDO2 device becomes ECDH-capable (§3.1 of the plan): A_1 cannot compute a
// PRF output itself — only the authenticator can, and only with the owner's consent. So instead
// of trying to wrap a share directly under a PRF-derived symmetric key (which A_1 could never
// produce on its own), the device's PRF output — for one FIXED, well-known salt — is used to
// deterministically derive a full secp256k1 keypair (`deriveKeypairFromPrfOutput`). The resulting
// PUBLIC key is registered exactly like a zrdcp-native device's public key, so
// `src/crypto/shareWrap.js` can wrap shares for it with the exact same ECDH code path. At
// (future, real) recovery time, the device re-derives the identical private key by performing one
// more WebAuthn assertion with the PRF extension and the same fixed salt — nothing is ever stored.

import { H } from '../crypto/hash.js';
import { G, mod, scalarToHex, pointToHex } from '../crypto/curve.js';

/** Fixed, well-known PRF salt for deriving this app's share-wrapping keypair. Not a secret — its
 * only job is domain-separating IdenTT's derived key from whatever else might read this
 * authenticator's PRF output for a different salt. */
const PRF_SALT = 'ZRDCP/1.0 IdenTT share-wrap-keypair v1';

function randomHex(byteLen) {
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(byteLen));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Deterministically turns a 32-byte PRF output into a secp256k1 keypair: hash it into the scalar
 * field (same `H()` used throughout the crypto core) to get a private scalar, then derive the
 * public point the usual way. Same PRF output in -> same keypair out, every time — which is
 * exactly the property that lets a hardware-gated PRF stand in for a stored private key.
 */
export function deriveKeypairFromPrfOutput(prfOutputBytes) {
  const privateScalar = mod(H(prfOutputBytes));
  const publicPoint = G.multiply(privateScalar);
  return {
    privateKeyHex: scalarToHex(privateScalar),
    publicKeyHex: pointToHex(publicPoint),
  };
}

/**
 * Simulates the WebAuthn PRF extension's output for a given credential + salt: a real
 * authenticator computes roughly HMAC-SHA256(per-credential secret, salt); this stands in with an
 * HMAC over the credential's in-memory-only simulated secret. Deterministic for the same
 * credential + salt (mirrors a real authenticator giving the same answer every time it's asked).
 */
export async function simulateGetPrfOutput(credential, salt) {
  if (!credential._debugPrfSeed) {
    throw new Error(
      'simulateGetPrfOutput: this credential has no PRF seed — either it was registered without prfSupported, or (realistically) this in-memory simulation does not outlive the session it was created in.'
    );
  }
  const hmacKey = await globalThis.crypto.subtle.importKey(
    'raw',
    credential._debugPrfSeed,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await globalThis.crypto.subtle.sign('HMAC', hmacKey, new TextEncoder().encode(salt));
  return new Uint8Array(sig);
}

function base64url(bytes) {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Simulates registering a new FIDO2 credential (`navigator.credentials.create()`).
 *
 * Generates a real ES256 (P-256) keypair via WebCrypto so the public key shape matches what a
 * genuine authenticator would produce (COSE ES256 is what WebAuthn actually uses), even though
 * no real hardware is involved yet. The private key is intentionally NOT returned or stored
 * anywhere — a real authenticator never releases its private key either, so nothing later in the
 * pipeline should ever expect to have it.
 *
 * @param {object} args
 * @param {string} args.name - label for logging/debugging only.
 * @param {boolean} [args.prfHint] - force the simulated PRF-support outcome (for deterministic
 *   tests). Omit to get a randomized-but-weighted outcome mimicking real-world PRF adoption.
 */
export async function simulateRegister({ name, prfHint } = {}) {
  const keypair = await globalThis.crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  const publicKeyJwk = await globalThis.crypto.subtle.exportKey('jwk', keypair.publicKey);

  const credentialId = base64url(globalThis.crypto.getRandomValues(new Uint8Array(32)));

  // Real-world PRF/hmac-secret support varies by authenticator; weight it optimistically (~70%)
  // since most current-generation platform authenticators and FIDO2.1 security keys support it.
  const prfSupported = typeof prfHint === 'boolean' ? prfHint : Math.random() < 0.7;

  let derivedPublicKeyHex = null;
  let debugPrfSeed = null;
  if (prfSupported) {
    // Real registration flow this stands in for: create() the credential, then immediately do one
    // get() assertion with the PRF extension (fixed salt) to learn the device's derived public
    // key — the private half never leaves the authenticator, simulated here by never returning
    // `debugPrfSeed` itself, only what's derived from it.
    debugPrfSeed = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const prfOutput = await simulateGetPrfOutput({ _debugPrfSeed: debugPrfSeed }, PRF_SALT);
    derivedPublicKeyHex = deriveKeypairFromPrfOutput(prfOutput).publicKeyHex;
  }

  return {
    credentialId,
    publicKeyJwk,
    prfSupported,
    derivedPublicKeyHex,
    transports: ['internal', 'hybrid'],
    attestationFormat: 'simulated-none',
    simulated: true,
    _debugLabel: name,
    _debugPrivateKeyHandle: keypair.privateKey, // in-memory only, for simulateAssert(); never persisted
    _debugPrfSeed: debugPrfSeed, // in-memory only, for simulateGetPrfOutput() later this session; never persisted
  };
}

/**
 * Simulates a WebAuthn assertion (`navigator.credentials.get()`) against a previously "registered"
 * simulated credential — signs the given challenge with the simulated authenticator's private key,
 * standing in for the real ceremony's `response.signature`.
 *
 * @param {object} credential - the object returned by `simulateRegister` (must still be in memory
 *   — this simulation can't persist private key material across sessions, which is realistic:
 *   real authenticators don't let you export their private keys either).
 * @param {string} challenge - the relying party's challenge for this assertion.
 */
export async function simulateAssert(credential, challenge) {
  if (!credential._debugPrivateKeyHandle) {
    throw new Error(
      'simulateAssert: no private key handle available — this simulated credential was not just registered in this session (expected: real authenticators keep their key in hardware and are always available; this in-memory simulation is only available for the lifetime of the registration call).'
    );
  }
  const signature = await globalThis.crypto.subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    credential._debugPrivateKeyHandle,
    new TextEncoder().encode(challenge)
  );
  return {
    credentialId: credential.credentialId,
    challenge,
    signatureHex: Array.from(new Uint8Array(signature), (b) => b.toString(16).padStart(2, '0')).join(''),
    simulated: true,
  };
}

export { randomHex, base64url, PRF_SALT };
