// IdenTT — Component 4: the Trusted Devices tab. Your own device identity (the ZRDCP keypair this
// vault was created with), the current trusted-device list, and the enroll/remove forms — all
// unchanged in behavior from the old single-screen app, just relocated here and now logging to
// this vault's history (src/vault/history.js) on add/remove.

import { el, deviceSummary } from '../ui.js';
import { session, persist } from '../state.js';
import { addDevice, removeDevice, shareHoldingDeviceCount } from '../../registry/registry.js';
import { createZrdcpNativeDevice, createFidoDevice, CONTACT_KINDS } from '../../registry/schema.js';
import { simulateRegister } from '../../fido/simulate.js';
import { G, randomScalar, pointToHex } from '../../crypto/curve.js';
import { appendHistory, HISTORY_KINDS } from '../../vault/history.js';

export async function renderDevicesTab(container, root) {
  container.innerHTML = '';
  container.append(
    renderIdentitySection(),
    renderDeviceList(root),
    renderAddNativeSection(root),
    renderAddFidoSection(root)
  );
}

function renderIdentitySection() {
  const registry = session.registry;
  const identityCopyStatus = el('p', { className: 'status' });
  return el('section', { className: 'card' }, [
    el('h2', { textContent: 'Your device identity' }),
    el('p', {
      className: 'hint',
      textContent:
        "This device's own ZRDCP public key — share it with people/devices enrolling YOU as one of their trusted devices. Generated once when this vault was created; every outgoing share is wrapped using its private half, which never leaves this vault.",
    }),
    el('input', { type: 'text', readOnly: true, value: registry.localIdentity.publicKeyHex }),
    el('button', {
      className: 'secondary',
      textContent: 'Copy public key',
      onclick: async () => {
        try {
          await navigator.clipboard.writeText(registry.localIdentity.publicKeyHex);
          identityCopyStatus.textContent = 'Copied.';
        } catch {
          identityCopyStatus.textContent = 'Could not copy — select and copy manually.';
        }
      },
    }),
    identityCopyStatus,
  ]);
}

function renderDeviceList(root) {
  const registry = session.registry;
  const deviceRows = registry.devices.map((device) =>
    el('li', { className: 'device-row' }, [
      el('span', { className: 'device-name', textContent: device.name }),
      el('span', { className: 'device-meta', textContent: deviceSummary(device) }),
      el('span', {
        className: 'device-contacts',
        textContent: device.contactChannels.map((c) => `${c.kind}:${c.address}`).join(', '),
      }),
      el('button', {
        className: 'danger',
        textContent: 'Remove',
        onclick: async () => {
          session.registry = removeDevice(session.registry, device.id);
          session.registry = appendHistory(session.registry, {
            kind: HISTORY_KINDS.DEVICE_REMOVED,
            detail: { deviceName: device.name },
          });
          await persist();
          const { renderShell } = await import('./shell.js');
          renderShell(root, { tabId: 'devices' });
        },
      }),
    ])
  );
  return el('section', { className: 'card' }, [
    el('h2', {
      textContent: `Trusted devices (${registry.devices.length} enrolled, ${shareHoldingDeviceCount(registry)} share-holding)`,
    }),
    el('ul', { className: 'device-list' }, deviceRows.length ? deviceRows : [el('li', { textContent: 'None yet.' })]),
  ]);
}

function renderAddNativeSection(root) {
  const nativeName = el('input', { type: 'text', placeholder: 'Device name (e.g. "Spouse\'s phone")' });
  const nativeContactKind = el(
    'select',
    {},
    Object.values(CONTACT_KINDS).map((k) => el('option', { value: k, textContent: k }))
  );
  const nativeContactAddr = el('input', { type: 'text', placeholder: 'Contact address (email/phone/URL)' });
  const nativePubkey = el('input', { type: 'text', placeholder: 'Public key (hex) — paste another local vault\'s identity key to test Responder Mode for real' });
  const nativeIsRemote = el('input', { type: 'checkbox' });
  const nativeRemoteLabel = el('label', { className: 'checkbox-label' }, [
    nativeIsRemote,
    document.createTextNode(' This device is remote (not physically co-located with me)'),
  ]);
  const generateDemoKeyBtn = el('button', {
    className: 'secondary',
    textContent: 'Generate demo keypair',
    title: 'For testing only — a real device should generate and keep its own private key locally.',
    onclick: () => {
      const priv = randomScalar();
      const pub = G.multiply(priv);
      nativePubkey.value = pointToHex(pub);
    },
  });
  const nativeError = el('p', { className: 'error' });
  const addNativeBtn = el('button', {
    textContent: 'Add zrdcp-native device',
    onclick: async () => {
      nativeError.textContent = '';
      try {
        const device = createZrdcpNativeDevice({
          name: nativeName.value,
          contactChannels: [{ kind: nativeContactKind.value, address: nativeContactAddr.value }],
          publicKeyHex: nativePubkey.value,
          isRemote: nativeIsRemote.checked,
        });
        session.registry = addDevice(session.registry, device);
        session.registry = appendHistory(session.registry, {
          kind: HISTORY_KINDS.DEVICE_ADDED,
          detail: { deviceName: device.name },
        });
        await persist();
        const { renderShell } = await import('./shell.js');
        renderShell(root, { tabId: 'devices' });
      } catch (e) {
        nativeError.textContent = e.message;
      }
    },
  });
  return el('section', { className: 'card' }, [
    el('h2', { textContent: 'Add a ZRDCP-native device' }),
    nativeName,
    nativeContactKind,
    nativeContactAddr,
    nativePubkey,
    generateDemoKeyBtn,
    nativeRemoteLabel,
    addNativeBtn,
    nativeError,
  ]);
}

function renderAddFidoSection(root) {
  const fidoName = el('input', { type: 'text', placeholder: 'Device name (e.g. "YubiKey 5C")' });
  const fidoContactKind = el(
    'select',
    {},
    Object.values(CONTACT_KINDS).map((k) => el('option', { value: k, textContent: k }))
  );
  const fidoContactAddr = el('input', { type: 'text', placeholder: 'Contact address (email/phone/URL)' });
  const fidoIsRemote = el('input', { type: 'checkbox' });
  const fidoRemoteLabel = el('label', { className: 'checkbox-label' }, [
    fidoIsRemote,
    document.createTextNode(' This device is remote (not physically co-located with me)'),
  ]);
  const fidoStatus = el('p', { className: 'status' });
  const fidoError = el('p', { className: 'error' });
  const registerFidoBtn = el('button', {
    textContent: 'Register FIDO2 device (simulated)',
    title: 'Real WebAuthn ceremonies need a local server + real hardware — deferred to a later phase.',
    onclick: async () => {
      fidoError.textContent = '';
      if (!fidoName.value.trim()) {
        fidoError.textContent = 'Device name is required.';
        return;
      }
      fidoStatus.textContent = 'Registering (simulated ceremony)…';
      try {
        const credential = await simulateRegister({ name: fidoName.value });
        const device = createFidoDevice({
          name: fidoName.value,
          contactChannels: [{ kind: fidoContactKind.value, address: fidoContactAddr.value }],
          credential,
          isRemote: fidoIsRemote.checked,
        });
        session.registry = addDevice(session.registry, device);
        session.registry = appendHistory(session.registry, {
          kind: HISTORY_KINDS.DEVICE_ADDED,
          detail: { deviceName: device.name },
        });
        await persist();
        const { renderShell } = await import('./shell.js');
        renderShell(root, { tabId: 'devices' });
      } catch (e) {
        fidoStatus.textContent = '';
        fidoError.textContent = e.message;
      }
    },
  });
  return el('section', { className: 'card' }, [
    el('h2', { textContent: 'Add a FIDO2/WebAuthn device' }),
    el('p', {
      className: 'hint',
      textContent:
        'Simulated for now — participation mode (full-share vs. approval-only) is decided by whether the simulated ceremony reports PRF/hmac-secret support, exactly as a real one would. FIDO2 devices can never be a local Responder Mode vault (they are not IdenTT vaults) — only zrdcp-native devices can.',
    }),
    fidoName,
    fidoContactKind,
    fidoContactAddr,
    fidoRemoteLabel,
    registerFidoBtn,
    fidoStatus,
    fidoError,
  ]);
}
