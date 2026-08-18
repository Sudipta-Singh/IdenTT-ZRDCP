import { describe, it, expect } from 'vitest';
import { approveInboxEntry, ResponderError } from '../src/recovery/respond.js';
import { wrapShare, unwrapShare } from '../src/crypto/shareWrap.js';
import { generateIdentityKeypair } from '../src/crypto/curve.js';

describe('respond.js — approveInboxEntry (Responder Mode)', () => {
  it('an authentication-kind entry approves with no cryptography, just a marker', async () => {
    const responderLocalIdentity = generateIdentityKeypair();
    const result = await approveInboxEntry({
      entry: { id: 'req_1', kind: 'vault-unlock-authentication', fromVaultName: 'Alice', deviceId: 'dev_1' },
      responderLocalIdentity,
    });
    expect(result).toEqual({ kind: 'vault-unlock-authentication' });
  });

  it('a recovery-kind entry really unwraps the share using the responder\'s own private key', async () => {
    const senderIdentity = generateIdentityKeypair(); // stands in for Alice's localIdentity
    const responderLocalIdentity = generateIdentityKeypair(); // the responder vault's own identity
    const share = { x: 2, y: 999999999999999999n };
    const wrapped = await wrapShare({
      share,
      senderIdentity,
      recipientPublicKeyHex: responderLocalIdentity.publicKeyHex,
    });

    const result = await approveInboxEntry({
      entry: { id: 'req_2', kind: 'vault-unlock-recovery', fromVaultName: 'Alice', deviceId: 'dev_1', wrappedShare: wrapped },
      responderLocalIdentity,
    });
    expect(result).toEqual({ kind: 'vault-unlock-recovery', x: 2, y: '999999999999999999' });
  });

  it('a wrong-recipient private key fails to unwrap (would produce garbage / throw)', async () => {
    const senderIdentity = generateIdentityKeypair();
    const intendedRecipient = generateIdentityKeypair();
    const wrongResponder = generateIdentityKeypair();
    const wrapped = await wrapShare({
      share: { x: 1, y: 42n },
      senderIdentity,
      recipientPublicKeyHex: intendedRecipient.publicKeyHex,
    });
    await expect(
      approveInboxEntry({
        entry: { id: 'req_3', kind: 'vault-unlock-recovery', fromVaultName: 'Alice', deviceId: 'dev_1', wrappedShare: wrapped },
        responderLocalIdentity: wrongResponder,
      })
    ).rejects.toThrow();
  });

  it('a recovery-kind entry with no wrappedShare is rejected with a clear error', async () => {
    const responderLocalIdentity = generateIdentityKeypair();
    await expect(
      approveInboxEntry({
        entry: { id: 'req_4', kind: 'vault-unlock-recovery', fromVaultName: 'Alice', deviceId: 'dev_1', wrappedShare: null },
        responderLocalIdentity,
      })
    ).rejects.toThrow(ResponderError);
  });

  it('an unknown entry kind is rejected', async () => {
    const responderLocalIdentity = generateIdentityKeypair();
    await expect(
      approveInboxEntry({ entry: { id: 'req_5', kind: 'something-else' }, responderLocalIdentity })
    ).rejects.toThrow(ResponderError);
  });
});
