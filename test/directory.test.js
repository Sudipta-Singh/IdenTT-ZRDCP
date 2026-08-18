import { describe, it, expect } from 'vitest';
import { createMemoryStorageAdapter } from '../src/vault/storage.js';
import {
  listVaultNames,
  registerVaultName,
  unregisterVaultName,
  registerIdentity,
  unregisterIdentitiesForVault,
  findVaultNameForPublicKey,
} from '../src/vault/directory.js';

describe('directory.js (browser-wide vault + identity indexes)', () => {
  it('starts empty, lists registered vault names in order added', async () => {
    const storage = createMemoryStorageAdapter();
    expect(await listVaultNames(storage)).toEqual([]);
    await registerVaultName(storage, 'Alice');
    await registerVaultName(storage, 'Bob');
    const names = (await listVaultNames(storage)).map((v) => v.name);
    expect(names).toEqual(['Alice', 'Bob']);
  });

  it('refuses to register a duplicate vault name', async () => {
    const storage = createMemoryStorageAdapter();
    await registerVaultName(storage, 'Alice');
    await expect(registerVaultName(storage, 'Alice')).rejects.toThrow(/already exists/);
  });

  it('unregisterVaultName removes only the named entry', async () => {
    const storage = createMemoryStorageAdapter();
    await registerVaultName(storage, 'Alice');
    await registerVaultName(storage, 'Bob');
    await unregisterVaultName(storage, 'Alice');
    expect((await listVaultNames(storage)).map((v) => v.name)).toEqual(['Bob']);
  });

  it('resolves a registered identity public key to its owning local vault name', async () => {
    const storage = createMemoryStorageAdapter();
    await registerIdentity(storage, '02aa', 'Alice');
    expect(await findVaultNameForPublicKey(storage, '02aa')).toBe('Alice');
  });

  it('an unregistered public key resolves to null (the normal case — most trusted devices are external)', async () => {
    const storage = createMemoryStorageAdapter();
    expect(await findVaultNameForPublicKey(storage, '02aa')).toBeNull();
  });

  it('registering is idempotent and re-registering the same key just overwrites its owner', async () => {
    const storage = createMemoryStorageAdapter();
    await registerIdentity(storage, '02aa', 'Alice');
    await registerIdentity(storage, '02aa', 'Alice');
    await registerIdentity(storage, '02aa', 'Renamed-Alice');
    expect(await findVaultNameForPublicKey(storage, '02aa')).toBe('Renamed-Alice');
  });

  it('unregisterIdentitiesForVault removes every key owned by that vault, and only that vault', async () => {
    const storage = createMemoryStorageAdapter();
    await registerIdentity(storage, '02aa', 'Alice');
    await registerIdentity(storage, '02bb', 'Bob');
    await unregisterIdentitiesForVault(storage, 'Alice');
    expect(await findVaultNameForPublicKey(storage, '02aa')).toBeNull();
    expect(await findVaultNameForPublicKey(storage, '02bb')).toBe('Bob');
  });
});
