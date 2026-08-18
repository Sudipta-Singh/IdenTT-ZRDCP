// IdenTT — browser app entry point.
//
// As of this session, the app is split into five UI components instead of one long screen:
//   1. Sign On (src/app/screens/signOn.js)         — the only screen shown before a vault unlocks.
//   2. Requests tab (src/app/screens/requests.js)   — create challenges, respond to them
//      (Responder Mode), and a persisted history log.
//   3. Vaults tab (src/app/screens/vaults.js)       — unlock policy, mesh/threshold settings, and
//      duress/authentication passcodes.
//   4. Trusted Devices tab (src/app/screens/devices.js) — device identity, device list, enroll/
//      remove.
//   5. Help tab (src/app/screens/help.js)           — inline documentation.
// Tabs 2-5 all live inside the post-sign-on "shell" (src/app/screens/shell.js). Shared DOM helpers
// live in src/app/ui.js, and shared session/storage state lives in src/app/state.js — both exist
// specifically so the screen modules don't need to import each other for anything but navigation.
//
// This session also adds real (non-simulated) email/SMS dispatch via a local backend
// (src/dispatch/realDispatch.js + server/), and a duress-passcode/decoy mechanism
// (src/vault/duress.js + src/recovery/decoy.js) — see the Help tab for user-facing detail on both.

import { migrateLegacyVaultIfPresent, renderSignOn } from './screens/signOn.js';

const root = document.getElementById('app');
migrateLegacyVaultIfPresent().then(() => renderSignOn(root));
