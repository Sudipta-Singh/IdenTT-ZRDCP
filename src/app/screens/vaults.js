// IdenTT — Component 3: the Vaults tab. Everything about how THIS vault is configured and
// protected:
//   - Vault security: which unlock policy protects it (passphrase / passphrase + step-up
//     authentication / recovery-only) — unchanged behavior from the old single-screen app, just
//     relocated here.
//   - Mesh & threshold: target/max trusted-device count for this vault's mesh, and the
//     authentication/recovery quorum sizes.
//   - Duress & authentication passcodes (new this session): an optional default authentication
//     code that prefills the Requests tab's runtime-code field, and the duress passcode itself —
//     see src/vault/duress.js and src/recovery/decoy.js for what entering it does at challenge
//     time.

import { el } from '../ui.js';
import { session, storage, persist, setPendingNotice, consumePendingNotice } from '../state.js';
import { getVaultMeta, setVaultMeta, UNLOCK_POLICIES } from '../../vault/meta.js';
import { enableRecoveryUnlock } from '../../vault/unlockRecovery.js';
import { clearReconstructionShares } from '../../vault/crossVault.js';
import { createVaultStore } from '../../vault/store.js';
import { setThreshold, registryWarnings } from '../../registry/registry.js';
import { setDuressPasscode, clearDuressPasscode, hasDuressPasscode, setDefaultAuthCode, getDefaultAuthCode, DuressError } from '../../vault/duress.js';
import { appendHistory, HISTORY_KINDS } from '../../vault/history.js';
import { renderShell } from './shell.js';

export async function renderVaultsTab(container, root) {
  container.innerHTML = '';
  const registry = session.registry;
  const vaultName = session.vaultName;
  const vaultMeta = await getVaultMeta(storage, vaultName);

  container.append(
    renderSecuritySection(root, vaultName, vaultMeta),
    renderThresholdSection(root, registry),
    renderWarnings(registry),
    renderPasscodesSection(root, registry)
  );
}

// ---------------------------------------------------------------------------------------------
// Vault security (unlock policy)
// ---------------------------------------------------------------------------------------------

function renderSecuritySection(root, vaultName, vaultMeta) {
  const registry = session.registry;
  const policySelect = el(
    'select',
    {},
    [
      { value: UNLOCK_POLICIES.PASSPHRASE, textContent: 'Passphrase only' },
      {
        value: UNLOCK_POLICIES.AUTHENTICATION,
        textContent: `Passphrase + live authentication (needs ${registry.threshold.kAuthentication} approvals)`,
      },
      {
        value: UNLOCK_POLICIES.RECOVERY,
        textContent: `Recovery only, no passphrase (needs ${registry.threshold.kRecovery} shares, ${registry.threshold.minRemoteForRecovery} remote)`,
      },
    ].map((opt) => el('option', opt))
  );
  policySelect.value = vaultMeta.unlockPolicy;
  const newPassInput = el('input', { type: 'password', placeholder: 'New passphrase (only needed when leaving Recovery-only)' });
  const securityError = el('p', { className: 'error' });
  const securityStatus = el('p', { className: 'status', textContent: consumePendingNotice() ?? '' });

  const savePolicyBtn = el('button', {
    textContent: 'Update unlock policy',
    onclick: async () => {
      securityError.textContent = '';
      securityStatus.textContent = '';
      const targetPolicy = policySelect.value;
      const store = createVaultStore(storage, vaultName);
      try {
        if (targetPolicy === UNLOCK_POLICIES.RECOVERY) {
          const { keyHex, recoverySplit } = await enableRecoveryUnlock({ registry: session.registry });
          session.registry = appendHistory(session.registry, {
            kind: HISTORY_KINDS.UNLOCK_POLICY_CHANGED,
            detail: { policy: UNLOCK_POLICIES.RECOVERY },
          });
          await store.saveWithKey(keyHex, session.registry);
          await setVaultMeta(storage, vaultName, { unlockPolicy: UNLOCK_POLICIES.RECOVERY, recoverySplit });
          await clearReconstructionShares(storage, vaultName);
          session.unlockSecret = { kind: 'key', value: keyHex };
          setPendingNotice(
            'Recovery-based unlock enabled. Your passphrase no longer opens this vault — only your trusted-device mesh can, from now on.'
          );
        } else {
          if (session.unlockSecret.kind === 'key') {
            if (!newPassInput.value) {
              securityError.textContent = 'Set a new passphrase to leave Recovery-only unlock.';
              return;
            }
            session.registry = appendHistory(session.registry, {
              kind: HISTORY_KINDS.UNLOCK_POLICY_CHANGED,
              detail: { policy: targetPolicy },
            });
            await store.save(newPassInput.value, session.registry);
            session.unlockSecret = { kind: 'passphrase', value: newPassInput.value };
          } else {
            session.registry = appendHistory(session.registry, {
              kind: HISTORY_KINDS.UNLOCK_POLICY_CHANGED,
              detail: { policy: targetPolicy },
            });
            await persist();
          }
          await setVaultMeta(storage, vaultName, { unlockPolicy: targetPolicy, recoverySplit: vaultMeta.recoverySplit });
          setPendingNotice(`Unlock policy set to "${targetPolicy}".`);
        }
        renderShell(root, { tabId: 'vaults' });
      } catch (e) {
        securityError.textContent = e.message;
      }
    },
  });

  const children = [
    el('h2', { textContent: 'Vault security' }),
    el('p', {
      className: 'hint',
      textContent:
        'How this vault unlocks next time. "Recovery only" protects it with your trusted-device mesh instead of a passphrase — see the Help tab for the full mechanism.',
    }),
    policySelect,
    newPassInput,
    savePolicyBtn,
  ];
  if (vaultMeta.unlockPolicy === UNLOCK_POLICIES.RECOVERY) {
    children.push(
      el('button', {
        className: 'secondary',
        textContent: 'Regenerate recovery split (after mesh changes)',
        onclick: async () => {
          securityError.textContent = '';
          try {
            const { keyHex, recoverySplit } = await enableRecoveryUnlock({ registry: session.registry });
            const store = createVaultStore(storage, vaultName);
            await store.saveWithKey(keyHex, session.registry);
            await setVaultMeta(storage, vaultName, { unlockPolicy: UNLOCK_POLICIES.RECOVERY, recoverySplit });
            await clearReconstructionShares(storage, vaultName);
            session.unlockSecret = { kind: 'key', value: keyHex };
            renderShell(root, { tabId: 'vaults' });
          } catch (e) {
            securityError.textContent = e.message;
          }
        },
      })
    );
  }
  children.push(securityStatus, securityError);
  return el('section', { className: 'card' }, children);
}

// ---------------------------------------------------------------------------------------------
// Mesh & threshold — includes "max trusted devices" (mapped onto the existing targetN control,
// which is this vault's target/ceiling mesh size, 4-9; the hard cap of 9 enrolled devices is
// enforced separately wherever a device is added, on the Trusted Devices tab).
// ---------------------------------------------------------------------------------------------

function renderThresholdSection(root, registry) {
  const targetNInput = el('input', { type: 'number', min: 4, max: 9, value: registry.threshold.targetN });
  const kAuthInput = el('input', { type: 'number', min: 2, value: registry.threshold.kAuthentication });
  const kRecoveryInput = el('input', { type: 'number', min: 3, value: registry.threshold.kRecovery });
  const minRemoteInput = el('input', { type: 'number', min: 1, value: registry.threshold.minRemoteForRecovery });
  const thresholdError = el('p', { className: 'error' });
  const saveThresholdBtn = el('button', {
    textContent: 'Update threshold',
    onclick: async () => {
      thresholdError.textContent = '';
      try {
        session.registry = setThreshold(session.registry, {
          targetN: Number(targetNInput.value),
          kAuthentication: Number(kAuthInput.value),
          kRecovery: Number(kRecoveryInput.value),
          minRemoteForRecovery: Number(minRemoteInput.value),
        });
        session.registry = appendHistory(session.registry, { kind: HISTORY_KINDS.THRESHOLD_UPDATED });
        await persist();
        renderShell(root, { tabId: 'vaults' });
      } catch (e) {
        thresholdError.textContent = e.message;
      }
    },
  });
  return el('section', { className: 'card' }, [
    el('h2', { textContent: 'Mesh & threshold' }),
    el('label', { textContent: 'Max / target trusted devices for this mesh (n) — must be 4-9' }),
    targetNInput,
    el('label', { textContent: 'Devices required to authenticate (any type, no share math)' }),
    kAuthInput,
    el('label', { textContent: 'Devices required to recover (must hold real shares)' }),
    kRecoveryInput,
    el('label', { textContent: 'Of those, minimum flagged remote (not co-located with you)' }),
    minRemoteInput,
    saveThresholdBtn,
    thresholdError,
  ]);
}

function renderWarnings(registry) {
  const warnings = registryWarnings(registry);
  return warnings.length
    ? el(
        'div',
        { className: 'warnings' },
        warnings.map((w) => el('p', { textContent: `⚠ ${w}` }))
      )
    : el('div');
}

// ---------------------------------------------------------------------------------------------
// Duress & authentication passcodes
// ---------------------------------------------------------------------------------------------

function renderPasscodesSection(root, registry) {
  const defaultCodeInput = el('input', { type: 'text', placeholder: 'Default authentication code (optional)', value: getDefaultAuthCode(registry) ?? '' });
  const defaultCodeError = el('p', { className: 'error' });
  const defaultCodeStatus = el('p', { className: 'status' });
  const saveDefaultBtn = el('button', {
    className: 'secondary',
    textContent: 'Save default authentication code',
    onclick: async () => {
      defaultCodeError.textContent = '';
      session.registry = setDefaultAuthCode(session.registry, defaultCodeInput.value.trim());
      await persist();
      defaultCodeStatus.textContent = defaultCodeInput.value.trim() ? 'Saved.' : 'Cleared.';
    },
  });

  const duressInput = el('input', { type: 'password', placeholder: 'New duress passcode' });
  const duressConfirm = el('input', { type: 'password', placeholder: 'Confirm duress passcode' });
  const duressError = el('p', { className: 'error' });
  const duressStatus = el('p', { className: 'status', textContent: hasDuressPasscode(registry) ? 'A duress passcode is currently set.' : 'No duress passcode is set.' });
  const saveDuressBtn = el('button', {
    className: 'secondary',
    textContent: 'Set duress passcode',
    onclick: async () => {
      duressError.textContent = '';
      if (duressInput.value !== duressConfirm.value) {
        duressError.textContent = 'Passcodes do not match.';
        return;
      }
      try {
        session.registry = await setDuressPasscode(session.registry, duressInput.value);
        await persist();
        duressInput.value = '';
        duressConfirm.value = '';
        duressStatus.textContent = 'Duress passcode set.';
      } catch (e) {
        duressError.textContent = e instanceof DuressError ? e.message : `Unexpected error: ${e.message}`;
      }
    },
  });
  const clearDuressBtn = el('button', {
    className: 'danger',
    textContent: 'Clear duress passcode',
    onclick: async () => {
      session.registry = clearDuressPasscode(session.registry);
      await persist();
      duressStatus.textContent = 'Duress passcode cleared.';
    },
  });

  return el('section', { className: 'card' }, [
    el('h2', { textContent: 'Duress & authentication passcodes' }),
    el('p', {
      className: 'hint',
      textContent:
        'Default authentication code: optional convenience that prefills the Requests tab\'s runtime-code field. Fully overridable per attempt — leaving it blank changes nothing about how a challenge is computed.',
    }),
    defaultCodeInput,
    saveDefaultBtn,
    defaultCodeStatus,
    defaultCodeError,
    el('hr'),
    el('p', {
      className: 'hint',
      textContent:
        'Duress passcode: enter this instead of your real runtime code on the Requests tab under coercion, and IdenTT produces an indistinguishable fake success instead — nothing real is sent or reconstructed. The only record is a silent history entry, visible only here after you\'ve genuinely signed in.',
    }),
    duressStatus,
    duressInput,
    duressConfirm,
    saveDuressBtn,
    clearDuressBtn,
    duressError,
  ]);
}
