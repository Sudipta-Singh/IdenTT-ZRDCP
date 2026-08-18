// IdenTT — module-level app state shared across every screen: the storage adapter, the currently
// unlocked vault session (if any), and the one-shot "pending notice" pattern.
//
// Split out of the old monolithic main.js specifically so the new screen modules
// (src/app/screens/*.js) can all import the SAME `session` binding without going through main.js —
// ES module `export let` bindings are live, so every importer sees updates made here via
// `setSession`/`clearSession` immediately, the same way a single shared closure variable would
// behave in the old single-file version.

import { createLocalStorageAdapter } from '../vault/storage.js';
import { createVaultStore } from '../vault/store.js';

export const storage = createLocalStorageAdapter();

/** In-memory only for the life of this page load. Never written to storage directly.
 * `unlockSecret` is `{ kind: 'passphrase', value: string } | { kind: 'key', value: hexString }` —
 * which one depends on the open vault's unlock policy. */
export let session = { vaultName: null, registry: null, unlockSecret: null };

export function setSession(next) {
  session = next;
}

export function clearSession() {
  session = { vaultName: null, registry: null, unlockSecret: null };
}

/** A message to show once at the top of the next render. Needed because several actions want to
 * leave a confirmation behind after they finish, but they also trigger a re-render of the DOM —
 * and that re-render clears the container at the very start of its (synchronous-until-the-first-
 * await) body, which would otherwise wipe out a message set on the old, about-to-be-discarded DOM
 * before the browser ever paints it. */
let pendingNotice = null;
export function setPendingNotice(message) {
  pendingNotice = message;
}
export function consumePendingNotice() {
  const notice = pendingNotice;
  pendingNotice = null;
  return notice;
}

/** Re-seals `session.registry` under whatever secret currently protects `session.vaultName`, and
 * persists it. Every screen that mutates `session.registry` calls this immediately afterward. */
export async function persist() {
  const store = createVaultStore(storage, session.vaultName);
  if (session.unlockSecret.kind === 'passphrase') {
    await store.save(session.unlockSecret.value, session.registry);
  } else {
    await store.saveWithKey(session.unlockSecret.value, session.registry);
  }
}
