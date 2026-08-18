import { describe, it, expect } from 'vitest';
import { createMemoryStorageAdapter } from '../src/vault/storage.js';
import {
  pushInbox,
  listInbox,
  removeInboxEntry,
  pushReconstructionShare,
  listReconstructionShares,
  clearReconstructionShares,
  pushAuthApproval,
  listAuthApprovals,
  clearAuthApprovals,
} from '../src/vault/crossVault.js';

describe('crossVault.js — inbox (per recipient public key)', () => {
  it('is empty for a public key nothing was ever pushed to', async () => {
    const storage = createMemoryStorageAdapter();
    expect(await listInbox(storage, '02aa')).toEqual([]);
  });

  it('pushes and lists entries in order, scoped to one recipient key', async () => {
    const storage = createMemoryStorageAdapter();
    await pushInbox(storage, '02aa', { id: 'req_1', kind: 'vault-unlock-authentication' });
    await pushInbox(storage, '02aa', { id: 'req_2', kind: 'vault-unlock-recovery' });
    await pushInbox(storage, '02bb', { id: 'req_3', kind: 'vault-unlock-authentication' });
    expect((await listInbox(storage, '02aa')).map((e) => e.id)).toEqual(['req_1', 'req_2']);
    expect((await listInbox(storage, '02bb')).map((e) => e.id)).toEqual(['req_3']);
  });

  it('removeInboxEntry removes only the matching entry for that recipient', async () => {
    const storage = createMemoryStorageAdapter();
    await pushInbox(storage, '02aa', { id: 'req_1' });
    await pushInbox(storage, '02aa', { id: 'req_2' });
    await removeInboxEntry(storage, '02aa', 'req_1');
    expect((await listInbox(storage, '02aa')).map((e) => e.id)).toEqual(['req_2']);
  });
});

describe('crossVault.js — reconstruction shares (per asking vault)', () => {
  it('accumulates shares from distinct devices', async () => {
    const storage = createMemoryStorageAdapter();
    await pushReconstructionShare(storage, 'Alice', { deviceId: 'dev_1', x: 1, y: 123n });
    await pushReconstructionShare(storage, 'Alice', { deviceId: 'dev_2', x: 2, y: 456n });
    const shares = await listReconstructionShares(storage, 'Alice');
    expect(shares).toHaveLength(2);
    expect(shares[0]).toEqual({ deviceId: 'dev_1', x: 1, y: '123' }); // BigInt -> decimal string
  });

  it('re-pushing for the same device REPLACES its prior share rather than duplicating', async () => {
    const storage = createMemoryStorageAdapter();
    await pushReconstructionShare(storage, 'Alice', { deviceId: 'dev_1', x: 1, y: 111n });
    await pushReconstructionShare(storage, 'Alice', { deviceId: 'dev_1', x: 1, y: 222n });
    const shares = await listReconstructionShares(storage, 'Alice');
    expect(shares).toEqual([{ deviceId: 'dev_1', x: 1, y: '222' }]);
  });

  it('is isolated per vault name', async () => {
    const storage = createMemoryStorageAdapter();
    await pushReconstructionShare(storage, 'Alice', { deviceId: 'dev_1', x: 1, y: 1n });
    expect(await listReconstructionShares(storage, 'Bob')).toEqual([]);
  });

  it('clearReconstructionShares empties the list', async () => {
    const storage = createMemoryStorageAdapter();
    await pushReconstructionShare(storage, 'Alice', { deviceId: 'dev_1', x: 1, y: 1n });
    await clearReconstructionShares(storage, 'Alice');
    expect(await listReconstructionShares(storage, 'Alice')).toEqual([]);
  });
});

describe('crossVault.js — authentication approvals (per asking vault)', () => {
  it('accumulates distinct-device approvals', async () => {
    const storage = createMemoryStorageAdapter();
    await pushAuthApproval(storage, 'Alice', { deviceId: 'dev_1' });
    await pushAuthApproval(storage, 'Alice', { deviceId: 'dev_2' });
    expect((await listAuthApprovals(storage, 'Alice')).map((a) => a.deviceId)).toEqual(['dev_1', 'dev_2']);
  });

  it('does not duplicate an approval from the same device twice', async () => {
    const storage = createMemoryStorageAdapter();
    await pushAuthApproval(storage, 'Alice', { deviceId: 'dev_1' });
    await pushAuthApproval(storage, 'Alice', { deviceId: 'dev_1' });
    expect(await listAuthApprovals(storage, 'Alice')).toHaveLength(1);
  });

  it('clearAuthApprovals empties the list', async () => {
    const storage = createMemoryStorageAdapter();
    await pushAuthApproval(storage, 'Alice', { deviceId: 'dev_1' });
    await clearAuthApprovals(storage, 'Alice');
    expect(await listAuthApprovals(storage, 'Alice')).toEqual([]);
  });
});
