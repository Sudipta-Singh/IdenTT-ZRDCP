import { describe, it, expect } from 'vitest';
import { createMemoryStorageAdapter } from '../src/vault/storage.js';
import { getVaultMeta, setVaultMeta, deleteVaultMeta, UNLOCK_POLICIES } from '../src/vault/meta.js';

describe('meta.js (per-vault unencrypted metadata)', () => {
  it('defaults to passphrase policy with no recovery split for a vault with no stored meta', async () => {
    const storage = createMemoryStorageAdapter();
    expect(await getVaultMeta(storage, 'Alice')).toEqual({
      unlockPolicy: UNLOCK_POLICIES.PASSPHRASE,
      recoverySplit: null,
    });
  });

  it('round-trips a stored meta object', async () => {
    const storage = createMemoryStorageAdapter();
    const meta = { unlockPolicy: UNLOCK_POLICIES.RECOVERY, recoverySplit: { kRecovery: 3, shares: [] } };
    await setVaultMeta(storage, 'Alice', meta);
    expect(await getVaultMeta(storage, 'Alice')).toEqual(meta);
  });

  it('keeps different vault names fully isolated', async () => {
    const storage = createMemoryStorageAdapter();
    await setVaultMeta(storage, 'Alice', { unlockPolicy: UNLOCK_POLICIES.AUTHENTICATION, recoverySplit: null });
    expect(await getVaultMeta(storage, 'Bob')).toEqual({ unlockPolicy: UNLOCK_POLICIES.PASSPHRASE, recoverySplit: null });
  });

  it('deleteVaultMeta removes stored meta, reverting to defaults', async () => {
    const storage = createMemoryStorageAdapter();
    await setVaultMeta(storage, 'Alice', { unlockPolicy: UNLOCK_POLICIES.RECOVERY, recoverySplit: null });
    await deleteVaultMeta(storage, 'Alice');
    expect(await getVaultMeta(storage, 'Alice')).toEqual({ unlockPolicy: UNLOCK_POLICIES.PASSPHRASE, recoverySplit: null });
  });
});
