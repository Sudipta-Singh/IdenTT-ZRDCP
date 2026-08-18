// IdenTT — the post-sign-on shell: header (vault name, Lock, All vaults) + tab navigation across
// the four remaining components (Requests, Vault settings, Trusted devices, Help). Each tab module
// owns its own render function and gets a fresh container to draw into; switching tabs just swaps
// which one is called, so no tab's state survives a switch away from it (mirrors how the old
// single-screen app already reset everything on every renderApp() call).

import { el } from '../ui.js';
import { session } from '../state.js';
import { renderSignOn } from './signOn.js';
import { renderRequestsTab } from './requests.js';
import { renderVaultsTab } from './vaults.js';
import { renderDevicesTab } from './devices.js';
import { renderHelpTab } from './help.js';

const TABS = [
  { id: 'requests', label: 'Requests', render: renderRequestsTab },
  { id: 'vaults', label: 'Vault settings', render: renderVaultsTab },
  { id: 'devices', label: 'Trusted devices', render: renderDevicesTab },
  { id: 'help', label: 'Help', render: renderHelpTab },
];

let activeTabId = 'requests';

export async function renderShell(root, { tabId } = {}) {
  if (tabId) activeTabId = tabId;
  root.innerHTML = '';
  const vaultName = session.vaultName;

  const header = el('div', { className: 'header' }, [
    el('h1', { textContent: `IdenTT — "${vaultName}"` }),
    el('div', { className: 'header-actions' }, [
      el('button', { className: 'link-button', textContent: 'Lock', onclick: () => { activeTabId = 'requests'; renderSignOn(root, { preselect: vaultName }); } }),
      el('button', { className: 'link-button', textContent: 'All vaults', onclick: () => { activeTabId = 'requests'; renderSignOn(root); } }),
    ]),
  ]);

  const tabNav = el(
    'nav',
    { className: 'tab-nav' },
    TABS.map((tab) =>
      el('button', {
        className: `tab-button${tab.id === activeTabId ? ' active' : ''}`,
        textContent: tab.label,
        onclick: () => renderShell(root, { tabId: tab.id }),
      })
    )
  );

  const contentContainer = el('div', { className: 'tab-content' });
  root.append(header, tabNav, contentContainer);

  const activeTab = TABS.find((t) => t.id === activeTabId) ?? TABS[0];
  await activeTab.render(contentContainer, root);
}
