import { describe, it, expect } from 'vitest';
import { createRegistry } from '../src/registry/registry.js';
import {
  setDuressPasscode,
  clearDuressPasscode,
  hasDuressPasscode,
  isDuressPasscode,
  setDefaultAuthCode,
  getDefaultAuthCode,
  DuressError,
} from '../src/vault/duress.js';

describe('duress.js', () => {
  it('a fresh registry has no duress passcode configured', async () => {
    const registry = createRegistry();
    expect(hasDuressPasscode(registry)).toBe(false);
    expect(await isDuressPasscode(registry, 'anything')).toBe(false);
  });

  it('setDuressPasscode stores only a salted hash, never the plaintext', async () => {
    const registry = createRegistry();
    const next = await setDuressPasscode(registry, 'my-duress-code');
    expect(hasDuressPasscode(next)).toBe(true);
    expect(next.duressPasscode.hash).not.toBe('my-duress-code');
    expect(JSON.stringify(next)).not.toContain('my-duress-code');
    // original registry is untouched (immutable convention)
    expect(hasDuressPasscode(registry)).toBe(false);
  });

  it('isDuressPasscode recognizes the correct code and rejects a wrong one', async () => {
    let registry = createRegistry();
    registry = await setDuressPasscode(registry, 'my-duress-code');
    expect(await isDuressPasscode(registry, 'my-duress-code')).toBe(true);
    expect(await isDuressPasscode(registry, 'wrong-code')).toBe(false);
    expect(await isDuressPasscode(registry, '')).toBe(false);
    expect(await isDuressPasscode(registry, undefined)).toBe(false);
  });

  it('rejects a too-short duress passcode', async () => {
    const registry = createRegistry();
    await expect(setDuressPasscode(registry, 'abc')).rejects.toThrow(DuressError);
    await expect(setDuressPasscode(registry, '')).rejects.toThrow(DuressError);
  });

  it('clearDuressPasscode removes it entirely', async () => {
    let registry = createRegistry();
    registry = await setDuressPasscode(registry, 'my-duress-code');
    registry = clearDuressPasscode(registry);
    expect(hasDuressPasscode(registry)).toBe(false);
    expect(await isDuressPasscode(registry, 'my-duress-code')).toBe(false);
    expect('duressPasscode' in registry).toBe(false);
  });

  it('two different registries hashing the same passcode get different salts/hashes', async () => {
    const a = await setDuressPasscode(createRegistry(), 'same-code-123');
    const b = await setDuressPasscode(createRegistry(), 'same-code-123');
    expect(a.duressPasscode.salt).not.toBe(b.duressPasscode.salt);
    expect(a.duressPasscode.hash).not.toBe(b.duressPasscode.hash);
  });

  it('default authentication code is stored in plain text and is fully optional', () => {
    let registry = createRegistry();
    expect(getDefaultAuthCode(registry)).toBeNull();
    registry = setDefaultAuthCode(registry, 'convenience-code');
    expect(getDefaultAuthCode(registry)).toBe('convenience-code');
    registry = setDefaultAuthCode(registry, '');
    expect(getDefaultAuthCode(registry)).toBeNull();
  });
});
