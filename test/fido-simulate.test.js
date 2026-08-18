import { describe, it, expect } from 'vitest';
import {
  simulateRegister,
  simulateAssert,
  simulateGetPrfOutput,
  deriveKeypairFromPrfOutput,
  PRF_SALT,
} from '../src/fido/simulate.js';

describe('Simulated FIDO2/WebAuthn ceremonies (Phase 1 scaffold, real ceremony deferred)', () => {
  it('simulateRegister produces a credential shaped like a real WebAuthn registration result', async () => {
    const credential = await simulateRegister({ name: 'Test device' });
    expect(typeof credential.credentialId).toBe('string');
    expect(credential.credentialId.length).toBeGreaterThan(0);
    expect(credential.publicKeyJwk).toMatchObject({ kty: 'EC', crv: 'P-256' });
    expect(typeof credential.prfSupported).toBe('boolean');
    expect(credential.simulated).toBe(true);
  });

  it('prfHint deterministically controls the simulated PRF outcome (for reproducible tests)', async () => {
    const withPrf = await simulateRegister({ name: 'a', prfHint: true });
    const withoutPrf = await simulateRegister({ name: 'b', prfHint: false });
    expect(withPrf.prfSupported).toBe(true);
    expect(withoutPrf.prfSupported).toBe(false);
  });

  it('simulateAssert signs a challenge with the credential\'s (in-memory-only) private key', async () => {
    const credential = await simulateRegister({ name: 'Assertion test' });
    const assertion = await simulateAssert(credential, 'session-challenge-xyz');
    expect(assertion.credentialId).toBe(credential.credentialId);
    expect(assertion.challenge).toBe('session-challenge-xyz');
    expect(assertion.signatureHex).toMatch(/^[0-9a-f]+$/);
  });

  it('never exposes a raw private key on the credential object handed to the registry', async () => {
    const credential = await simulateRegister({ name: 'No leak check' });
    // The private key handle is a non-exportable CryptoKey object, not raw bytes — but more to
    // the point, nothing named "privateKey" (without the _debug prefix) should exist, since that
    // field is what the schema/registry layer would accidentally persist if this leaked.
    expect(credential.privateKey).toBeUndefined();
    expect(credential.publicKeyJwk.d).toBeUndefined(); // JWK private exponent must not be present
  });

  describe('PRF-derived ECDH keypair (Phase 2: how a full-share device becomes wrap-able)', () => {
    it('a PRF-capable credential gets a derivedPublicKeyHex; a non-PRF one does not', async () => {
      const withPrf = await simulateRegister({ name: 'PRF key', prfHint: true });
      const withoutPrf = await simulateRegister({ name: 'No PRF key', prfHint: false });
      expect(typeof withPrf.derivedPublicKeyHex).toBe('string');
      expect(withPrf.derivedPublicKeyHex.length).toBeGreaterThan(0);
      expect(withoutPrf.derivedPublicKeyHex).toBeNull();
    });

    it('the same credential + salt always yields the same PRF output (deterministic, like real hardware)', async () => {
      const credential = await simulateRegister({ name: 'Deterministic check', prfHint: true });
      const first = await simulateGetPrfOutput(credential, PRF_SALT);
      const second = await simulateGetPrfOutput(credential, PRF_SALT);
      expect(Array.from(first)).toEqual(Array.from(second));
    });

    it('a different salt yields a different PRF output', async () => {
      const credential = await simulateRegister({ name: 'Salt sensitivity', prfHint: true });
      const a = await simulateGetPrfOutput(credential, PRF_SALT);
      const b = await simulateGetPrfOutput(credential, 'a different salt entirely');
      expect(Array.from(a)).not.toEqual(Array.from(b));
    });

    it('deriveKeypairFromPrfOutput is deterministic and re-derives the same keypair used at registration', async () => {
      const credential = await simulateRegister({ name: 'Re-derive check', prfHint: true });
      const prfOutput = await simulateGetPrfOutput(credential, PRF_SALT);
      const rederived = deriveKeypairFromPrfOutput(prfOutput);
      expect(rederived.publicKeyHex).toBe(credential.derivedPublicKeyHex);
    });
  });
});
