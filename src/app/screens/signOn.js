// IdenTT — Component 1: the Sign On screen. One cohesive screen (replacing the old two-step
// "pick a vault" -> "unlock" pair of screens) that:
//   - explains the two ways to sign in to a vault: Authentication mode (a passphrase, optionally
//     followed by a live step-up check-in) and Recovery mode (no passphrase — your trusted-device
//     mesh reconstructs the unlock key instead);
//   - has a single dropdown to pick which vault to act on, including a "+ Create a new vault"
//     option that reveals the create-vault form right there instead of a separate screen;
//   - shows whichever sign-in UI matches the selected vault's own unlock policy (see
//     src/vault/meta.js), and a "Delete this vault" action for when you want to remove one.
//
// This is the ONLY screen reachable before a vault is unlocked. On success it hands off to
// src/app/screens/shell.js's `renderShell`, which owns everything post-authentication (the
// Requests/Vaults/Devices/Help tabs).

import { el } from '../ui.js';
import { storage, setSession } from '../state.js';
import { createVaultStore, LEGACY_SINGLE_VAULT_STORAGE_KEY, storageKeyFor } from '../../vault/store.js';
import {
  listVaultNames,
  registerVaultName,
  unregisterVaultName,
  registerIdentity,
  unregisterIdentitiesForVault,
  findVaultNameForPublicKey,
} from '../../vault/directory.js';
import { getVaultMeta, setVaultMeta, deleteVaultMeta, UNLOCK_POLICIES } from '../../vault/meta.js';
import {
  pushInbox,
  listInbox,
  listReconstructionShares,
  clearReconstructionShares,
  listAuthApprovals,
  clearAuthApprovals,
} from '../../vault/crossVault.js';
import { attemptReconstruction } from '../../vault/unlockRecovery.js';
import { makeId } from '../../registry/schema.js';
import { renderShell } from './shell.js';

const CREATE_NEW_VALUE = '__create__';

/** One-time upgrade path: a vault created before multi-vault support existed lived under a fixed
 * storage key with no name and no entry in the vaults index. If we find one and the new index is
 * still empty, adopt it as a named vault ("My first vault") rather than stranding it. */
export async function migrateLegacyVaultIfPresent() {
  const legacyRaw = await storage.getItem(LEGACY_SINGLE_VAULT_STORAGE_KEY);
  if (legacyRaw === null) return;
  if ((await listVaultNames(storage)).length > 0) return; // multi-vault scheme already in use

  const legacyName = 'My first vault';
  await storage.setItem(storageKeyFor(legacyName), legacyRaw);
  await storage.removeItem(LEGACY_SINGLE_VAULT_STORAGE_KEY);
  await registerVaultName(storage, legacyName);
}

export async function renderSignOn(root, { preselect } = {}) {
  root.innerHTML = '';
  const vaults = await listVaultNames(storage);

  const heading = el('h1', { textContent: 'IdenTT' });
  const subheading = el('p', {
    className: 'subtitle',
    textContent: 'Sign in to a vault, or create a new one.',
  });

  const instructionsSection = el('section', { className: 'card' }, [
    el('h2', { textContent: 'How signing in works' }),
    el('p', {
      className: 'hint',
      textContent:
        'Authentication mode: enter the vault\'s passphrase. If that vault also requires a live authentication check-in (its own kAuthentication quorum), you\'ll be asked for that next, before it opens.',
    }),
    el('p', {
      className: 'hint',
      textContent:
        'Recovery mode: for a vault with no passphrase at all — its unlock key is protected by a real Shamir split across its trusted-device mesh, reconstructed once enough of those devices respond.',
    }),
    el('p', {
      className: 'hint',
      textContent: 'Pick a vault below to see the sign-in options that apply to it, or choose "Create a new vault."',
    }),
  ]);

  const options = [el('option', { value: '', textContent: `-- Select a vault (${vaults.length} available) --` })];
  for (const { name } of vaults) options.push(el('option', { value: name, textContent: name }));
  options.push(el('option', { value: CREATE_NEW_VALUE, textContent: '+ Create a new vault' }));
  const vaultSelect = el('select', {}, options);
  if (preselect) vaultSelect.value = preselect;

  const detailContainer = el('div', { className: 'signon-detail' });

  async function renderDetail() {
    detailContainer.innerHTML = '';
    const value = vaultSelect.value;
    if (!value) return;
    if (value === CREATE_NEW_VALUE) {
      detailContainer.append(renderCreateForm(root));
      return;
    }
    detailContainer.append(await renderVaultSignIn(root, value));
  }
  vaultSelect.addEventListener('change', renderDetail);

  const pickerSection = el('section', { className: 'card' }, [
    el('h2', { textContent: 'Vault' }),
    el('label', { textContent: 'Choose a vault to sign in to, or create a new one' }),
    vaultSelect,
    detailContainer,
  ]);

  root.append(el('div', { className: 'header' }, [heading]), subheading, instructionsSection, pickerSection);
  await renderDetail();
}

// ---------------------------------------------------------------------------------------------
// Create a new vault
// ---------------------------------------------------------------------------------------------

function renderCreateForm(root) {
  const nameInput = el('input', { type: 'text', placeholder: 'Vault name (e.g. "Personal", "Work")' });
  const passInput = el('input', { type: 'password', placeholder: 'Passphrase' });
  const confirmInput = el('input', { type: 'password', placeholder: 'Confirm passphrase' });
  const createError = el('p', { className: 'error' });
  const createBtn = el('button', {
    textContent: 'Create vault',
    onclick: async () => {
      createError.textContent = '';
      const name = nameInput.value.trim();
      if (!name) {
        createError.textContent = 'Vault name is required.';
        return;
      }
      if (!passInput.value) {
        createError.textContent = 'Passphrase is required.';
        return;
      }
      if (passInput.value !== confirmInput.value) {
        createError.textContent = 'Passphrases do not match.';
        return;
      }
      try {
        const store = createVaultStore(storage, name);
        if (await store.exists()) {
          createError.textContent = `A vault named "${name}" already exists.`;
          return;
        }
        // Every new vault starts on the 'passphrase' policy — there's no mesh yet to protect it
        // with anything else. Switch to 'authentication'/'recovery' later from the Vaults tab,
        // once you've enrolled trusted devices.
        const registry = await store.createNew(passInput.value);
        await registerVaultName(storage, name);
        await registerIdentity(storage, registry.localIdentity.publicKeyHex, name);
        setSession({ vaultName: name, registry, unlockSecret: { kind: 'passphrase', value: passInput.value } });
        renderShell(root, { tabId: 'requests' });
      } catch (e) {
        createError.textContent = e.message;
      }
    },
  });
  return el('div', { className: 'signon-subsection' }, [
    el('h3', { textContent: 'Create a new vault' }),
    nameInput,
    passInput,
    confirmInput,
    createBtn,
    createError,
  ]);
}

// ---------------------------------------------------------------------------------------------
// Sign in to an existing vault — branches on that vault's own unlock policy.
// ---------------------------------------------------------------------------------------------

async function renderVaultSignIn(root, vaultName) {
  const vaultMeta = await getVaultMeta(storage, vaultName);
  const store = createVaultStore(storage, vaultName);
  const container = el('div', { className: 'signon-subsection' });
  const error = el('p', { className: 'error' });

  const deleteArea = el('span', {});
  const deleteBtn = el('button', {
    className: 'danger',
    textContent: 'Delete this vault',
    onclick: () => {
      deleteArea.innerHTML = '';
      deleteArea.append(
        el('span', { className: 'hint', textContent: `Delete "${vaultName}"? This cannot be undone. ` }),
        el('button', {
          className: 'danger',
          textContent: 'Really delete',
          onclick: async () => {
            await createVaultStore(storage, vaultName).destroy();
            await deleteVaultMeta(storage, vaultName);
            await unregisterVaultName(storage, vaultName);
            await unregisterIdentitiesForVault(storage, vaultName);
            await clearReconstructionShares(storage, vaultName);
            await clearAuthApprovals(storage, vaultName);
            renderSignOn(root);
          },
        }),
        el('button', { className: 'secondary', textContent: 'Cancel', onclick: () => { deleteArea.innerHTML = ''; deleteArea.append(deleteBtn); } })
      );
    },
  });
  deleteArea.append(deleteBtn);

  if (vaultMeta.unlockPolicy === UNLOCK_POLICIES.RECOVERY) {
    container.append(await renderRecoveryUnlock(root, vaultName, vaultMeta, store, error));
    container.append(deleteArea);
    return container;
  }

  const policyHint =
    vaultMeta.unlockPolicy === UNLOCK_POLICIES.AUTHENTICATION
      ? 'Enter your passphrase. This vault also requires a live authentication check-in from your mesh afterward.'
      : 'Enter your passphrase to unlock this vault.';
  const passInput = el('input', { type: 'password', placeholder: 'Passphrase', autofocus: true });
  const unlockBtn = el('button', {
    textContent: 'Unlock',
    onclick: async () => {
      error.textContent = '';
      try {
        const registry = await store.load(passInput.value);
        await registerIdentity(storage, registry.localIdentity.publicKeyHex, vaultName);
        setSession({ vaultName, registry, unlockSecret: { kind: 'passphrase', value: passInput.value } });
        if (vaultMeta.unlockPolicy === UNLOCK_POLICIES.AUTHENTICATION) {
          renderAuthStepUp(root, vaultName, registry);
        } else {
          renderShell(root, { tabId: 'requests' });
        }
      } catch {
        error.textContent = 'Wrong passphrase.';
      }
    },
  });

  container.append(
    el('h3', { textContent: `Sign in to "${vaultName}"` }),
    el('p', { className: 'hint', textContent: policyHint }),
    passInput,
    unlockBtn,
    error,
    deleteArea
  );
  return container;
}

async function renderRecoveryUnlock(root, vaultName, vaultMeta, store, error) {
  const split = vaultMeta.recoverySplit;
  const wrapper = el('div', {});
  const statusArea = el('div', { className: 'recovery-results' });
  const initiateStatus = el('p', { className: 'hint' });
  const openBtn = el('button', { className: 'danger-action', textContent: 'Attempt to open', disabled: true });

  if (!split) {
    wrapper.append(
      el('h3', { textContent: `Sign in to "${vaultName}"` }),
      el('p', {
        className: 'error',
        textContent:
          'This vault is set to recovery-only unlock, but no recovery split was ever generated — this should not happen. It cannot be opened this way; delete it and start over, or contact support.',
      })
    );
    return wrapper;
  }

  async function refreshStatus() {
    statusArea.innerHTML = '';
    const collected = await listReconstructionShares(storage, vaultName);
    const validIds = new Set(split.shares.map((s) => s.deviceId));
    const usable = collected.filter((s) => validIds.has(s.deviceId));
    const remoteIds = new Set(split.shares.filter((s) => s.isRemote).map((s) => s.deviceId));
    const remoteCollected = usable.filter((s) => remoteIds.has(s.deviceId)).length;
    const ready = usable.length >= split.kRecovery && remoteCollected >= split.minRemoteForRecovery;
    openBtn.disabled = !ready;

    statusArea.append(
      el('p', {
        className: 'hint',
        textContent: `${usable.length}/${split.kRecovery} real responses collected · ${remoteCollected}/${split.minRemoteForRecovery} required remote responses collected`,
      }),
      el(
        'ul',
        { className: 'dispatch-list' },
        split.shares.map((s) =>
          el('li', { className: 'dispatch-row' }, [
            el('span', { className: 'device-name', textContent: `${s.deviceName}${s.isRemote ? ' · remote' : ' · local'}` }),
            el('span', {
              className: 'device-meta',
              textContent: usable.some((u) => u.deviceId === s.deviceId) ? '✓ real response received' : 'pending',
            }),
          ])
        )
      )
    );
  }

  const initiateBtn = el('button', {
    className: 'secondary',
    textContent: 'Initiate recovery (notify local responders)',
    onclick: async () => {
      let dispatchedToAnyLocal = false;
      for (const s of split.shares) {
        const localName = await findVaultNameForPublicKey(storage, s.devicePublicKeyHex);
        if (!localName) continue;
        const existing = await listInbox(storage, s.devicePublicKeyHex);
        const already = existing.some((e) => e.kind === 'vault-unlock-recovery' && e.fromVaultName === vaultName && e.deviceId === s.deviceId);
        if (!already) {
          await pushInbox(storage, s.devicePublicKeyHex, {
            id: makeId('req'),
            kind: 'vault-unlock-recovery',
            fromVaultName: vaultName,
            deviceId: s.deviceId,
            wrappedShare: s.wrapped,
            createdAt: new Date().toISOString(),
          });
        }
        dispatchedToAnyLocal = true;
      }
      initiateStatus.textContent = dispatchedToAnyLocal
        ? 'Notified local responder vault(s) — open them (choose a different vault above) and check the Requests tab\'s Responder Mode to approve, then come back and check for responses.'
        : "None of this recovery split's devices are other local vaults in this browser — recovery can't be completed here. In a real deployment, each would respond via its own IdenTT app.";
      await refreshStatus();
    },
  });
  const refreshBtn = el('button', { className: 'secondary', textContent: 'Check for responses', onclick: refreshStatus });

  openBtn.addEventListener('click', async () => {
    error.textContent = '';
    const collected = await listReconstructionShares(storage, vaultName);
    const result = attemptReconstruction({ recoverySplit: split, collectedShares: collected });
    if (!result.ok) {
      error.textContent = `Not enough real responses yet — ${result.reason}.`;
      return;
    }
    try {
      const registry = await store.loadWithKey(result.keyHex);
      await registerIdentity(storage, registry.localIdentity.publicKeyHex, vaultName);
      await clearReconstructionShares(storage, vaultName);
      setSession({ vaultName, registry, unlockSecret: { kind: 'key', value: result.keyHex } });
      renderShell(root, { tabId: 'requests' });
    } catch (e) {
      error.textContent = `The reconstructed key did not open the vault (${e.message}) — the split may be out of date; regenerate it from the Vaults tab next time you're in.`;
    }
  });

  const holderSummary = `Needs ${split.kRecovery} real share-holder responses (of ${split.holderCount} enrolled), including ${split.minRemoteForRecovery} remote.`;

  wrapper.append(
    el('h3', { textContent: `Sign in to "${vaultName}" — Recovery mode` }),
    el('p', {
      className: 'hint',
      textContent:
        'This vault unlocks via Recovery — there is no passphrase to enter. Ask your trusted-device mesh to respond (Responder Mode, on the Requests tab of any of them), then attempt to open once enough real responses are in.',
    }),
    el('p', { className: 'hint', textContent: holderSummary }),
    initiateBtn,
    initiateStatus,
    refreshBtn,
    statusArea,
    openBtn,
    error
  );
  await refreshStatus();
  return wrapper;
}

/** Step-up gate shown after a correct passphrase on an 'authentication'-policy vault, before the
 * main app opens. Uses THIS vault's own kAuthentication threshold. */
export async function renderAuthStepUp(root, vaultName, registry) {
  root.innerHTML = '';
  const heading = el('h1', { textContent: 'IdenTT' });
  const subheading = el('p', { className: 'subtitle', textContent: `Vault: "${vaultName}" — step-up authentication required` });
  const { kAuthentication } = registry.threshold;
  const statusArea = el('div', { className: 'recovery-results' });
  const dispatchStatus = el('p', { className: 'hint' });
  const continueBtn = el('button', { className: 'danger-action', textContent: 'Continue', disabled: true });

  async function refreshStatus() {
    const approvals = await listAuthApprovals(storage, vaultName);
    statusArea.innerHTML = '';
    statusArea.append(el('p', { className: 'hint', textContent: `${approvals.length}/${kAuthentication} real approvals collected.` }));
    continueBtn.disabled = approvals.length < kAuthentication;
  }

  const dispatchBtn = el('button', {
    className: 'secondary',
    textContent: 'Notify local responders',
    onclick: async () => {
      let any = false;
      for (const device of registry.devices) {
        if (device.type !== 'zrdcp-native') continue;
        const localName = await findVaultNameForPublicKey(storage, device.publicKeyHex);
        if (!localName) continue;
        const existing = await listInbox(storage, device.publicKeyHex);
        const already = existing.some((e) => e.kind === 'vault-unlock-authentication' && e.fromVaultName === vaultName && e.deviceId === device.id);
        if (!already) {
          await pushInbox(storage, device.publicKeyHex, {
            id: makeId('req'),
            kind: 'vault-unlock-authentication',
            fromVaultName: vaultName,
            deviceId: device.id,
            wrappedShare: null,
            createdAt: new Date().toISOString(),
          });
        }
        any = true;
      }
      dispatchStatus.textContent = any
        ? 'Notified local responder vault(s) — open them and check the Requests tab\'s Responder Mode to approve.'
        : 'None of your enrolled zrdcp-native devices are other local vaults in this browser — nothing to notify here.';
      await refreshStatus();
    },
  });
  const refreshBtn = el('button', { className: 'secondary', textContent: 'Check for responses', onclick: refreshStatus });

  continueBtn.addEventListener('click', async () => {
    await clearAuthApprovals(storage, vaultName);
    renderShell(root, { tabId: 'requests' });
  });

  root.append(
    el('div', { className: 'header' }, [heading]),
    subheading,
    el('div', { className: 'gate' }, [
      el('p', { className: 'hint', textContent: 'Your passphrase was correct. This vault also requires a live authentication check-in before it opens.' }),
      dispatchBtn,
      dispatchStatus,
      refreshBtn,
      statusArea,
      continueBtn,
    ])
  );
  await refreshStatus();
}
