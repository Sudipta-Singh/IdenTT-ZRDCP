import { describe, it, expect } from 'vitest';
import { wrapShare, unwrapShare, ShareUnwrapError } from '../src/crypto/shareWrap.js';
import { generateIdentityKeypair } from '../src/crypto/curve.js';

describe('Share wrapping (dissertation §2.2 step 2, ECDH + AES-GCM)', () => {
  it('round-trips a share between two zrdcp-native-style identities', async () => {
    const sender = generateIdentityKeypair();
    const recipient = generateIdentityKeypair();
    const share = { x: 3, y: 123456789012345678901234567890n };

    const wrapped = await wrapShare({ share, senderIdentity: sender, recipientPublicKeyHex: recipient.publicKeyHex });
    const unwrapped = await unwrapShare({ wrapped, recipientPrivateKeyHex: recipient.privateKeyHex });

    expect(unwrapped).toEqual(share);
  });

  it('the recipient can recompute the same shared secret from either direction (ECDH symmetry)', async () => {
    const a = generateIdentityKeypair();
    const b = generateIdentityKeypair();
    const share = { x: 1, y: 42n };

    const wrapped = await wrapShare({ share, senderIdentity: a, recipientPublicKeyHex: b.publicKeyHex });
    // b decrypts using its own private key + a's public key (embedded in the wrapped payload)
    const unwrapped = await unwrapShare({ wrapped, recipientPrivateKeyHex: b.privateKeyHex });
    expect(unwrapped).toEqual(share);
  });

  it('rejects unwrapping with the wrong private key', async () => {
    const sender = generateIdentityKeypair();
    const rightRecipient = generateIdentityKeypair();
    const wrongRecipient = generateIdentityKeypair();
    const share = { x: 2, y: 999n };

    const wrapped = await wrapShare({ share, senderIdentity: sender, recipientPublicKeyHex: rightRecipient.publicKeyHex });
    await expect(unwrapShare({ wrapped, recipientPrivateKeyHex: wrongRecipient.privateKeyHex })).rejects.toThrow(
      ShareUnwrapError
    );
  });

  it('rejects a tampered ciphertext (AES-GCM auth tag)', async () => {
    const sender = generateIdentityKeypair();
    const recipient = generateIdentityKeypair();
    const share = { x: 4, y: 7777n };

    const wrapped = await wrapShare({ share, senderIdentity: sender, recipientPublicKeyHex: recipient.publicKeyHex });
    const tampered = { ...wrapped, ciphertextHex: wrapped.ciphertextHex.slice(0, -4) + 'dead' };
    await expect(unwrapShare({ wrapped: tampered, recipientPrivateKeyHex: recipient.privateKeyHex })).rejects.toThrow(
      ShareUnwrapError
    );
  });

  it('the same share wrapped twice produces different ciphertext (fresh IV each time)', async () => {
    const sender = generateIdentityKeypair();
    const recipient = generateIdentityKeypair();
    const share = { x: 5, y: 555n };

    const a = await wrapShare({ share, senderIdentity: sender, recipientPublicKeyHex: recipient.publicKeyHex });
    const b = await wrapShare({ share, senderIdentity: sender, recipientPublicKeyHex: recipient.publicKeyHex });
    expect(a.ciphertextHex).not.toBe(b.ciphertextHex);
    expect(a.ivHex).not.toBe(b.ivHex);
  });
});
