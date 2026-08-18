import { describe, it, expect } from 'vitest';
import {
  seal,
  open,
  sealWithKey,
  openWithKey,
  WrongPassphraseOrCorruptVaultError,
} from '../src/vault/vault.js';

describe('Vault (passphrase-sealed local storage)', () => {
  it('round-trips arbitrary JSON data', async () => {
    const data = { devices: [{ name: 'laptop' }], threshold: { targetN: 6, k: 3 } };
    const sealed = await seal('correct horse battery staple', data);
    const opened = await open('correct horse battery staple', sealed);
    expect(opened).toEqual(data);
  });

  it('rejects the wrong passphrase', async () => {
    const sealed = await seal('right-passphrase', { secret: true });
    await expect(open('wrong-passphrase', sealed)).rejects.toThrow(WrongPassphraseOrCorruptVaultError);
  });

  it('rejects tampered ciphertext (AES-GCM auth tag catches it)', async () => {
    const sealed = await seal('some-passphrase', { secret: true });
    const tampered = { ...sealed, ciphertext: sealed.ciphertext.slice(0, -4) + 'AAAA' };
    await expect(open('some-passphrase', tampered)).rejects.toThrow(WrongPassphraseOrCorruptVaultError);
  });

  it('sealing the same data twice produces different ciphertext (fresh salt/IV each time)', async () => {
    const data = { x: 1 };
    const a = await seal('pw', data);
    const b = await seal('pw', data);
    expect(a.ciphertext).not.toBe(b.ciphertext);
    expect(a.salt).not.toBe(b.salt);
    expect(a.iv).not.toBe(b.iv);
  });
});

describe('Vault raw-key sealing (recovery-unlock-policy vaults, no passphrase)', () => {
  const keyHex = 'ab'.repeat(32);

  it('round-trips arbitrary JSON data under a raw 32-byte key', async () => {
    const data = { devices: [{ name: 'laptop' }] };
    const sealed = await sealWithKey(keyHex, data);
    const opened = await openWithKey(keyHex, sealed);
    expect(opened).toEqual(data);
  });

  it('rejects the wrong key', async () => {
    const sealed = await sealWithKey(keyHex, { secret: true });
    await expect(openWithKey('cd'.repeat(32), sealed)).rejects.toThrow(WrongPassphraseOrCorruptVaultError);
  });

  it('rejects tampered ciphertext', async () => {
    const sealed = await sealWithKey(keyHex, { secret: true });
    const tampered = { ...sealed, ciphertext: sealed.ciphertext.slice(0, -4) + 'AAAA' };
    await expect(openWithKey(keyHex, tampered)).rejects.toThrow(WrongPassphraseOrCorruptVaultError);
  });

  it('is a different KDF from passphrase sealing — a passphrase-opened blob does not open with a raw key', async () => {
    const data = { x: 1 };
    const sealedByPassphrase = await seal(keyHex, data); // same string, used as a passphrase this time
    await expect(openWithKey(keyHex, sealedByPassphrase)).rejects.toThrow();
  });
});
