import { describe, it, expect } from 'vitest';
import { createVaultStore } from '../src/vault/store.js';
import { createMemoryStorageAdapter } from '../src/vault/storage.js';
import { addDevice } from '../src/registry/registry.js';
import { createZrdcpNativeDevice } from '../src/registry/schema.js';

describe('VaultStore (vault + storage + registry, wired together, one named vault)', () => {
  it('creates, saves, and reloads a registry across a fresh store instance (simulating app restart)', async () => {
    const backingStorage = createMemoryStorageAdapter(); // stands in for localStorage persisting across "sessions"
    const store1 = createVaultStore(backingStorage, 'Alice');

    expect(await store1.exists()).toBe(false);
    let registry = await store1.createNew('my-passphrase', { targetN: 6, kAuthentication: 2, kRecovery: 3 });
    registry = addDevice(
      registry,
      createZrdcpNativeDevice({
        name: 'Home laptop',
        contactChannels: [{ kind: 'email', address: 'me@example.com' }],
        publicKeyHex: '02' + 'ab'.repeat(32),
      })
    );
    await store1.save('my-passphrase', registry);

    // Fresh store instance over the SAME backing storage and vault name — simulates reopening the app.
    const store2 = createVaultStore(backingStorage, 'Alice');
    expect(await store2.exists()).toBe(true);
    const reloaded = await store2.load('my-passphrase');
    expect(reloaded.devices).toHaveLength(1);
    expect(reloaded.devices[0].name).toBe('Home laptop');
  });

  it('load() with the wrong passphrase fails', async () => {
    const backingStorage = createMemoryStorageAdapter();
    const store = createVaultStore(backingStorage, 'Alice');
    await store.createNew('correct-pw');
    await expect(store.load('incorrect-pw')).rejects.toThrow();
  });

  it('load() migrates a pre-authentication/recovery-split vault (old single threshold.k shape)', async () => {
    const backingStorage = createMemoryStorageAdapter();
    const store = createVaultStore(backingStorage, 'Alice');
    // Simulate an older vault on disk: threshold is the old { targetN, k } shape, no localIdentity.
    const { seal } = await import('../src/vault/vault.js');
    const oldRegistry = {
      version: 1,
      threshold: { targetN: 6, k: 5 },
      devices: [],
      updatedAt: new Date(0).toISOString(),
    };
    const sealed = await seal('legacy-pw', oldRegistry);
    await backingStorage.setItem('identt.vault.Alice.sealed.v1', JSON.stringify(sealed));

    const migrated = await store.load('legacy-pw');
    expect(migrated.threshold).toEqual({ targetN: 6, kAuthentication: 2, kRecovery: 5, minRemoteForRecovery: 1 });
    expect(migrated.localIdentity).toBeDefined();

    // And the migration was actually persisted, not just returned in-memory.
    const reloaded = await store.load('legacy-pw');
    expect(reloaded.threshold.kRecovery).toBe(5);
  });

  it('destroy() removes only the named vault it was created for', async () => {
    const backingStorage = createMemoryStorageAdapter();
    const alice = createVaultStore(backingStorage, 'Alice');
    const bob = createVaultStore(backingStorage, 'Bob');
    await alice.createNew('pw-a');
    await bob.createNew('pw-b');
    await alice.destroy();
    expect(await alice.exists()).toBe(false);
    expect(await bob.exists()).toBe(true);
  });

  it('two differently-named vaults over the same backing storage never collide', async () => {
    const backingStorage = createMemoryStorageAdapter();
    const alice = createVaultStore(backingStorage, 'Alice');
    const bob = createVaultStore(backingStorage, 'Bob');
    await alice.createNew('pw-a');
    await bob.createNew('pw-b');
    await expect(alice.load('pw-b')).rejects.toThrow(); // Bob's passphrase doesn't open Alice's vault
    const aliceRegistry = await alice.load('pw-a');
    const bobRegistry = await bob.load('pw-b');
    expect(aliceRegistry.localIdentity.publicKeyHex).not.toBe(bobRegistry.localIdentity.publicKeyHex);
  });

  it('saveWithKey/loadWithKey round-trip under a raw key instead of a passphrase', async () => {
    const backingStorage = createMemoryStorageAdapter();
    const store = createVaultStore(backingStorage, 'Alice');
    const registry = await store.createNew('bootstrap-pw'); // vault must exist first (passphrase-created)
    const keyHex = 'cc'.repeat(32);
    await store.saveWithKey(keyHex, registry);
    const reloaded = await store.loadWithKey(keyHex);
    expect(reloaded.localIdentity.publicKeyHex).toBe(registry.localIdentity.publicKeyHex);
    // The original passphrase no longer opens it — it's been re-sealed under the raw key.
    await expect(store.load('bootstrap-pw')).rejects.toThrow();
  });
});
