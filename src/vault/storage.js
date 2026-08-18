// IdenTT — storage adapters for the sealed vault blob.
//
// The vault itself (vault.js) doesn't know or care where its sealed bytes live; these adapters
// plug in a place to put them. `createMemoryStorageAdapter` is what tests use; the shipped app
// uses `createLocalStorageAdapter` (browser localStorage — simple and sufficient for a
// single-blob registry at MVP scale; revisit if/when the registry grows large enough that
// IndexedDB's async, larger-quota storage becomes worth the extra complexity).

export function createMemoryStorageAdapter() {
  const store = new Map();
  return {
    async getItem(key) {
      return store.has(key) ? store.get(key) : null;
    },
    async setItem(key, value) {
      store.set(key, value);
    },
    async removeItem(key) {
      store.delete(key);
    },
  };
}

export function createLocalStorageAdapter() {
  if (typeof globalThis.localStorage === 'undefined') {
    throw new Error('createLocalStorageAdapter: localStorage is not available in this environment');
  }
  return {
    async getItem(key) {
      return globalThis.localStorage.getItem(key);
    },
    async setItem(key, value) {
      globalThis.localStorage.setItem(key, value);
    },
    async removeItem(key) {
      globalThis.localStorage.removeItem(key);
    },
  };
}
