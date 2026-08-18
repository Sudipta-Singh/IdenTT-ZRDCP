// IdenTT — tiny DOM helpers shared by every screen module under src/app/screens/. Split out of the
// old monolithic main.js so each screen can `import { el } from '../ui.js'` without creating an
// import cycle back through main.js itself.

export const $ = (sel, root = document) => root.querySelector(sel);

export const el = (tag, props = {}, children = []) => {
  const node = document.createElement(tag);
  Object.assign(node, props);
  for (const child of children) node.append(child);
  return node;
};

/** Human-readable one-liner for a device row — used by both the Devices tab and the Requests tab's
 * dispatch history. */
export function deviceSummary(device) {
  const remoteTag = device.isRemote ? ' · remote' : ' · local';
  if (device.type === 'zrdcp-native') {
    return `zrdcp-native · pubkey ${device.publicKeyHex.slice(0, 12)}…${remoteTag}`;
  }
  return `fido2 · ${device.participationMode}${device.fido.simulated ? ' (simulated)' : ''}${remoteTag}`;
}

/** Short relative-ish timestamp for history rows — just a locale string; there's no need for a
 * fancy "3 minutes ago" formatter for a local single-user app. */
export function formatTimestamp(iso) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
