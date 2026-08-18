// IdenTT — Responder Mode (Phase 3): what happens when THIS vault is the one being asked to
// vouch for another local vault. Two inbox kinds (see `src/vault/crossVault.js`), two responses:
//   - 'vault-unlock-authentication' — no cryptography at all. Approving just means "yes, count me
//     toward that vault's kAuthentication quorum" — recorded as a plain approval flag.
//   - 'vault-unlock-recovery' — approving actually decrypts this responder's real Shamir share
//     (unwrapping it with THIS vault's own `localIdentity` private key, which is why the responder
//     has to be unlocked to respond at all) and hands back the genuine `{x, y}` point. This is
//     real reconstruction material, not a simulated outcome — see `src/recovery/evaluateOutcome.js`
//     for the (still-simulated, unchanged) equivalent used by the external-runtime-code challenge
//     flow from Phase 2, which this module does NOT replace.

import { unwrapShare } from '../crypto/shareWrap.js';

export class ResponderError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ResponderError';
  }
}

/**
 * @param {object} args
 * @param {import('../vault/crossVault.js').InboxEntry} args.entry
 * @param {{privateKeyHex: string, publicKeyHex: string}} args.responderLocalIdentity - the
 *   currently-open (responding) vault's own identity keypair.
 * @returns {Promise<
 *   { kind: 'vault-unlock-authentication' } |
 *   { kind: 'vault-unlock-recovery', x: number, y: string }
 * >} what to write back into the asking vault's scratch area (see `src/vault/crossVault.js`'s
 *   `pushAuthApproval`/`pushReconstructionShare`) — `y` is decimal-string-encoded since JSON has
 *   no BigInt type.
 */
export async function approveInboxEntry({ entry, responderLocalIdentity }) {
  if (entry.kind === 'vault-unlock-authentication') {
    return { kind: 'vault-unlock-authentication' };
  }
  if (entry.kind === 'vault-unlock-recovery') {
    if (!entry.wrappedShare) {
      throw new ResponderError(`inbox entry ${entry.id} is a recovery request but carries no wrapped share`);
    }
    const { x, y } = await unwrapShare({
      wrapped: entry.wrappedShare,
      recipientPrivateKeyHex: responderLocalIdentity.privateKeyHex,
    });
    return { kind: 'vault-unlock-recovery', x, y: y.toString() };
  }
  throw new ResponderError(`unknown inbox entry kind: ${entry.kind}`);
}
