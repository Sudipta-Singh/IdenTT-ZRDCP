// IdenTT — Component 2: the Requests/Challenge tab. Two sub-tabs plus a persistent history log:
//   1. "Create Challenge" — the (still Phase 2) authenticate/recover flow aimed at some OTHER
//      application that issued a challenge. The runtime code you enter is checked against this
//      vault's duress passcode FIRST (see src/vault/duress.js) — a match silently swaps in a fake
//      DECOY_EXEC session (src/recovery/decoy.js) that looks and behaves identically but touches
//      nothing real. Submitting switches you straight to the Responses sub-tab to track it.
//   2. "Responses" — new this session: EVERY response-type interaction lives here together —
//      requests from other devices awaiting your response (Responder Mode) AND the challenges you
//      yourself have initiated (moved out of "Create Challenge" so both directions of a response
//      are visible in one place, per the user's explicit request). Each of your own initiated
//      challenges shows its dispatch rows, a "Send for real" option for email/sms rows (via the
//      local backend, src/dispatch/realDispatch.js), and the runtime-challenge authentication step
//      described below.
//   3. "History" — a read-only log of everything above, persisted inside this vault's own
//      registry (src/vault/history.js) so it survives a lock/unlock cycle. Shown under both
//      sub-tabs.
//
// New this session — runtime-challenge response authentication: per the user's explicit
// requirement, a device RECEIVING a dispatched challenge must independently enter the exact same
// runtime challenge (C_r) the originator used before its response counts as a success. This is a
// manual, out-of-band authentication step (the originator would tell trusted responders the code
// directly, e.g. by phone) that sits ON TOP OF the existing Pedersen/NIZK cryptographic proof —
// it doesn't replace or weaken that proof, it adds a second, independent factor. Verified by
// reusing H() (src/crypto/hash.js) — the exact same hash-to-scalar function the protocol already
// uses to turn a runtime code into the committed value m — so "does what you typed match" is
// checked against the real m, not a parallel ad hoc hash. This only applies where a runtime
// challenge actually exists: the Create Challenge flow. The separate real cross-vault Responder
// Mode inbox (vault self-unlock, "Awaiting your response" below) has no typed runtime code in its
// story — recovery-policy self-unlock uses a randomly generated split key, and the
// authentication-policy step-up is a pure liveness check — so this extra step does not apply there.

import { el, formatTimestamp } from '../ui.js';
import { session, storage, persist } from '../state.js';
import { listInbox, removeInboxEntry, pushReconstructionShare, pushAuthApproval } from '../../vault/crossVault.js';
import { approveInboxEntry } from '../../recovery/respond.js';
import { initiateRecovery, RecoveryInitiationError } from '../../recovery/initiate.js';
import { evaluateChallengeOutcome } from '../../recovery/evaluateOutcome.js';
import { buildDecoySession, decoyOutcome } from '../../recovery/decoy.js';
import { isDuressPasscode, getDefaultAuthCode } from '../../vault/duress.js';
import { appendHistory, listHistory, HISTORY_KINDS } from '../../vault/history.js';
import { sendReal, checkBackendHealth, RealDispatchError } from '../../dispatch/realDispatch.js';
import { H } from '../../crypto/hash.js';

const SUB_TABS = [
  { id: 'create', label: 'Create Challenge' },
  { id: 'responses', label: 'Responses' },
];
let activeSubTabId = 'create';

/** Challenges initiated FROM this vault, this page session — vaultName -> session[] (newest
 * first). Deliberately in-memory only, never persisted to storage: in-flight session state is
 * ephemeral by design (see docs/PLAN.md §5), same as the dispatch/outcome data already was before
 * this session's Responses sub-tab made it visible outside the moment it was created. Keyed by
 * vault name so switching vaults never leaks one vault's initiated challenges into another's view. */
const outgoingChallengesByVault = new Map();
function getOutgoingChallenges() {
  return outgoingChallengesByVault.get(session.vaultName) ?? [];
}
function pushOutgoingChallenge(challengeSession) {
  const list = outgoingChallengesByVault.get(session.vaultName) ?? [];
  list.unshift(challengeSession);
  outgoingChallengesByVault.set(session.vaultName, list);
}

/** H() is the protocol's own hash-to-scalar function (src/crypto/hash.js) — reusing it means the
 * runtime-challenge authentication check below verifies against the SAME value (`m`) the Pedersen
 * commitment actually committed to, rather than an unrelated ad hoc hash. */
function runtimeChallengeDigest(code) {
  return H(code).toString(16);
}

export async function renderRequestsTab(container, root) {
  container.innerHTML = '';

  const subTabNav = el(
    'nav',
    { className: 'subtab-nav' },
    SUB_TABS.map((tab) =>
      el('button', {
        className: `subtab-button${tab.id === activeSubTabId ? ' active' : ''}`,
        textContent: tab.label,
        onclick: () => {
          activeSubTabId = tab.id;
          renderRequestsTab(container, root);
        },
      })
    )
  );
  const subTabContent = el('div', { className: 'subtab-content' });
  container.append(subTabNav, subTabContent);

  if (activeSubTabId === 'responses') {
    subTabContent.append(renderResponsesSubTab(container));
    await refreshAllResponderInboxes(container);
  } else {
    subTabContent.append(await renderCreateChallengeSection(container, root));
  }

  container.append(renderHistorySection());
}

// ---------------------------------------------------------------------------------------------
// Responses sub-tab — both directions: requests awaiting your response, and ones you've sent.
// ---------------------------------------------------------------------------------------------

function renderResponsesSubTab(tabContainer) {
  const responderContainer = el('div', { className: 'recovery-results', id: 'responder-inbox' });
  const incomingSection = el('section', { className: 'card' }, [
    el('h2', { textContent: 'Awaiting your response' }),
    el('p', {
      className: 'hint',
      textContent:
        "Authentication/recovery requests from other devices in your trusted mesh. Real live responses come from other local IdenTT (ZRDCP-native) vaults in this browser that have enrolled this vault as a trusted device — approving a recovery request really decrypts your share with your own private key here, nothing is simulated. FIDO2 devices are approval-only credentials you hold yourself; they don't independently send requests here.",
    }),
    responderContainer,
  ]);

  const outgoingSection = renderOutgoingChallengesSection(tabContainer);

  return el('div', {}, [incomingSection, outgoingSection]);
}

async function refreshAllResponderInboxes(container) {
  const responderContainer = container.querySelector('#responder-inbox');
  if (!responderContainer) return;
  const registry = session.registry;
  responderContainer.innerHTML = '';
  const entries = await listInbox(storage, registry.localIdentity.publicKeyHex);
  if (!entries.length) {
    responderContainer.append(el('p', { className: 'hint', textContent: 'No pending requests right now.' }));
    return;
  }
  responderContainer.append(
    el(
      'ul',
      { className: 'dispatch-list' },
      entries.map((entry) => {
        const rowError = el('p', { className: 'error' });
        const kindLabel =
          entry.kind === 'vault-unlock-recovery'
            ? 'wants your real share to help unlock its vault'
            : 'wants a live authentication approval to unlock its vault';
        const approveBtn = el('button', {
          textContent: 'Approve',
          onclick: async () => {
            rowError.textContent = '';
            try {
              const result = await approveInboxEntry({ entry, responderLocalIdentity: registry.localIdentity });
              if (result.kind === 'vault-unlock-recovery') {
                await pushReconstructionShare(storage, entry.fromVaultName, { deviceId: entry.deviceId, x: result.x, y: result.y });
              } else {
                await pushAuthApproval(storage, entry.fromVaultName, { deviceId: entry.deviceId });
              }
              await removeInboxEntry(storage, registry.localIdentity.publicKeyHex, entry.id);
              session.registry = appendHistory(registry, {
                kind: HISTORY_KINDS.RESPONDER_APPROVED,
                detail: { fromVaultName: entry.fromVaultName, requestKind: entry.kind },
              });
              await persist();
              refreshHistorySection(container);
              await refreshAllResponderInboxes(container);
            } catch (e) {
              rowError.textContent = e.message;
            }
          },
        });
        const denyBtn = el('button', {
          className: 'danger',
          textContent: 'Deny',
          onclick: async () => {
            await removeInboxEntry(storage, registry.localIdentity.publicKeyHex, entry.id);
            session.registry = appendHistory(registry, {
              kind: HISTORY_KINDS.RESPONDER_DENIED,
              detail: { fromVaultName: entry.fromVaultName, requestKind: entry.kind },
            });
            await persist();
            refreshHistorySection(container);
            await refreshAllResponderInboxes(container);
          },
        });
        return el('li', { className: 'dispatch-row' }, [
          el('span', { className: 'device-name', textContent: `"${entry.fromVaultName}" ${kindLabel}` }),
          el('span', { className: 'hint', textContent: `Request ${entry.id}` }),
          approveBtn,
          denyBtn,
          rowError,
        ]);
      })
    )
  );
}

function renderOutgoingChallengesSection(tabContainer) {
  const challenges = getOutgoingChallenges();
  const section = el('section', { className: 'card' }, [
    el('h2', { textContent: `Challenges you've initiated (${challenges.length})` }),
    el('p', {
      className: 'hint',
      textContent:
        "Recovery/authentication challenges you started from this vault this browser session — track dispatch and evaluate responses here, including the runtime-challenge authentication step below.",
    }),
  ]);
  if (!challenges.length) {
    section.append(el('p', { className: 'hint', textContent: 'None yet — start one from the Create Challenge sub-tab.' }));
    return section;
  }
  for (const challengeSession of challenges) {
    const wrapper = el('div', { className: 'recovery-results' });
    renderChallengeResults(wrapper, challengeSession, tabContainer);
    section.append(wrapper, el('hr'));
  }
  return section;
}

// ---------------------------------------------------------------------------------------------
// Create Challenge (authenticate/recover to another application)
// ---------------------------------------------------------------------------------------------

async function renderCreateChallengeSection(tabContainer, root) {
  const registry = session.registry;
  const backendStatus = el('p', { className: 'hint', textContent: 'Checking local backend for real email/SMS…' });
  checkBackendHealth().then((health) => {
    backendStatus.textContent = health.reachable
      ? `Local backend reachable — real send available for: ${[health.email && 'email', health.sms && 'SMS'].filter(Boolean).join(', ') || 'none configured yet'}.`
      : 'Local backend not reachable — "Send for real" will be unavailable until you run it (see server/README.md). Simulated dispatch below still works either way.';
  });

  const purposeSelect = el('select', {}, [
    el('option', { value: 'recovery', textContent: `Recovery (needs ${registry.threshold.kRecovery} shares, ${registry.threshold.minRemoteForRecovery} remote)` }),
    el('option', { value: 'authentication', textContent: `Authentication (needs ${registry.threshold.kAuthentication} approvals)` }),
  ]);
  const recoveryCodeInput = el('input', { type: 'password', placeholder: 'Runtime code (C_r)', value: getDefaultAuthCode(registry) ?? '' });
  const recoveryError = el('p', { className: 'error' });
  const recoveryStatus = el('p', { className: 'status' });

  const initiateBtn = el('button', {
    className: 'danger-action',
    textContent: 'Initiate challenge',
    onclick: async () => {
      recoveryError.textContent = '';
      if (!recoveryCodeInput.value) {
        recoveryError.textContent = 'Enter a runtime code first.';
        return;
      }
      recoveryStatus.textContent = 'Computing commitment, proof, and (for recovery) shares…';
      try {
        const enteredCode = recoveryCodeInput.value;
        const isDuress = await isDuressPasscode(session.registry, enteredCode);
        recoveryCodeInput.value = '';
        recoveryStatus.textContent = '';

        if (isDuress) {
          // DECOY_EXEC: build a fake session that looks identical to a real one, log it silently
          // (visible only inside this vault, only after genuine owner authentication), and never
          // touch real crypto or real/simulated dispatch.
          const decoySession = buildDecoySession({ registry: session.registry, purpose: purposeSelect.value });
          session.registry = appendHistory(session.registry, {
            kind: HISTORY_KINDS.DURESS_TRIGGERED,
            detail: { purpose: purposeSelect.value, sessionId: decoySession.sessionId },
          });
          await persist();
          pushOutgoingChallenge(decoySession);
          activeSubTabId = 'responses';
          await renderRequestsTab(tabContainer, root);
          return;
        }

        const challengeSession = await initiateRecovery({
          registry: session.registry,
          runtimeEntropy: enteredCode,
          purpose: purposeSelect.value,
        });
        // The runtime-challenge authentication step (see file header) checks a receiving device's
        // typed input against this digest — the same H() the Pedersen commitment itself used, so
        // "did you enter the exact code" is verified against the real committed value.
        challengeSession.runtimeChallengeHash = runtimeChallengeDigest(enteredCode);
        session.registry = appendHistory(session.registry, {
          kind: HISTORY_KINDS.CHALLENGE_INITIATED,
          detail: { purpose: challengeSession.purpose, sessionId: challengeSession.sessionId },
        });
        await persist();
        pushOutgoingChallenge(challengeSession);
        activeSubTabId = 'responses';
        await renderRequestsTab(tabContainer, root);
      } catch (e) {
        recoveryStatus.textContent = '';
        recoveryError.textContent = e instanceof RecoveryInitiationError ? e.message : `Unexpected error: ${e.message}`;
      }
    },
  });

  return el('section', { className: 'card' }, [
    el('h2', { textContent: 'Create a challenge' }),
    el('p', {
      className: 'hint',
      textContent:
        'For proving yourself to some OTHER application that issued a challenge — not for unlocking this vault (see the Vaults tab for that). Authentication is a lightweight quorum check; Recovery computes the Pedersen commitment + NIZK proof and splits it across your share-holding devices, requiring at least one remote device among the responders.',
    }),
    el('p', {
      className: 'hint',
      textContent:
        'Every device this gets dispatched to must independently enter the exact same runtime code you use below before its response counts — an authentication step confirming they\'re a trusted party in real time, on top of (not instead of) the cryptographic proof. Submitting takes you to the Responses sub-tab to track it.',
    }),
    backendStatus,
    el('label', { textContent: 'Purpose' }),
    purposeSelect,
    recoveryCodeInput,
    initiateBtn,
    recoveryStatus,
    recoveryError,
  ]);
}

function renderChallengeResults(resultsContainer, recoverySession, tabContainer) {
  resultsContainer.innerHTML = '';

  const challengeInputs = new Map(); // deviceId -> text input
  const outcomeResult = el('div', { className: 'outcome-result' });
  if (recoverySession._lastOutcome) {
    renderOutcome(outcomeResult, recoverySession._lastOutcome);
  }

  const dispatchRows = recoverySession.dispatches.map((d) => {
    const challengeInput = el('input', {
      type: 'text',
      className: 'outcome-select',
      placeholder: 'Enter the exact runtime challenge',
      'data-device-id': d.deviceId,
    });
    challengeInputs.set(d.deviceId, challengeInput);

    const rowChildren = [
      el('span', { className: 'device-name', textContent: `${d.deviceName} (${d.deviceType})` }),
      el('span', { className: 'device-meta', textContent: `${d.channelKind} → ${d.address}` }),
      el('span', {
        className: 'device-meta',
        textContent: d.hasShare ? 'share sent' : 'notification only (no share)',
      }),
      el('span', { className: 'device-meta', textContent: d.isRemote ? 'remote' : 'local' }),
    ];
    if (!recoverySession.decoy) {
      rowChildren.push(
        el('span', { className: 'hint', textContent: d.payloadPreview }),
        el('span', { className: 'hint', textContent: `Responder link: ${d.responderLink}` })
      );
    }

    if (!recoverySession.decoy && (d.channelKind === 'email' || d.channelKind === 'sms')) {
      const realStatus = el('span', { className: 'hint' });
      const realBtn = el('button', {
        className: 'secondary',
        textContent: `Send for real (${d.channelKind})`,
        onclick: async () => {
          realStatus.textContent = 'Sending…';
          try {
            const message = `${d.payloadPreview} Responder link: ${d.responderLink}`;
            await sendReal({ channelKind: d.channelKind, address: d.address, subject: 'IdenTT request', message });
            realStatus.textContent = '✓ sent for real.';
            session.registry = appendHistory(session.registry, {
              kind: HISTORY_KINDS.REAL_DISPATCH_SENT,
              detail: { deviceName: d.deviceName, channelKind: d.channelKind, sessionId: recoverySession.sessionId },
            });
            await persist();
            refreshHistorySection(tabContainer);
          } catch (e) {
            realStatus.textContent = e instanceof RealDispatchError ? e.message : `Unexpected error: ${e.message}`;
          }
        },
      });
      rowChildren.push(realBtn, realStatus);
    }

    rowChildren.push(
      el('label', {
        className: 'outcome-label',
        textContent: "Receiving device's response — must enter the exact runtime challenge to authenticate:",
      }),
      challengeInput
    );
    return el('li', { className: 'dispatch-row' }, rowChildren);
  });

  const evaluateBtn = el('button', {
    className: 'secondary',
    textContent: 'Evaluate outcome',
    onclick: async () => {
      let outcome;
      if (recoverySession.decoy) {
        // The whole point of a decoy is that it can't be made to visibly fail — ignore whatever
        // was typed per-device and always report the same fake success a real session would show
        // once its real responders came through.
        outcome = decoyOutcome(recoverySession);
      } else {
        const responses = {};
        for (const [deviceId, input] of challengeInputs) {
          const typed = input.value.trim();
          if (!typed) continue; // nothing entered — treated as no response, same as before
          responses[deviceId] = runtimeChallengeDigest(typed) === recoverySession.runtimeChallengeHash ? 'success' : 'fail';
        }
        outcome = evaluateChallengeOutcome({ session: recoverySession, responses });
        session.registry = appendHistory(session.registry, {
          kind: HISTORY_KINDS.CHALLENGE_OUTCOME,
          detail: { sessionId: recoverySession.sessionId, granted: outcome.granted, purpose: outcome.purpose },
        });
        await persist();
        refreshHistorySection(tabContainer);
      }
      recoverySession._lastOutcome = outcome;
      renderOutcome(outcomeResult, outcome);
    },
  });

  resultsContainer.append(
    el('p', { className: 'status', textContent: `Session ${recoverySession.sessionId} initiated (${recoverySession.purpose}).` }),
    el('p', {
      className: 'hint',
      textContent: `Commitment: ${recoverySession.recoveryInit.pedersen_commitment.slice(0, 24)}…`,
    }),
    el('ul', { className: 'dispatch-list' }, dispatchRows),
    evaluateBtn,
    outcomeResult
  );
}

function renderOutcome(container, outcome) {
  container.innerHTML = '';
  const verdict = el('p', {
    className: outcome.granted ? 'status' : 'error',
    textContent: outcome.granted
      ? `✓ ${outcome.purpose === 'authentication' ? 'Authentication' : 'Recovery'} would succeed.`
      : `✗ ${outcome.purpose === 'authentication' ? 'Authentication' : 'Recovery'} would fail.`,
  });
  const detailParts = [`${outcome.successCount}/${outcome.requiredK} required responses succeeded`];
  if (outcome.purpose === 'recovery') {
    detailParts.push(
      `${outcome.remoteSuccessCount}/${outcome.minRemoteForRecovery} required remote share-holder responses succeeded`
    );
  }
  const detail = el('p', { className: 'hint', textContent: detailParts.join(' · ') });
  const reason = el('p', { className: 'hint', textContent: outcome.reason ?? '' });
  container.append(verdict, detail, reason);
}

// ---------------------------------------------------------------------------------------------
// History
// ---------------------------------------------------------------------------------------------

const HISTORY_LABELS = {
  [HISTORY_KINDS.CHALLENGE_INITIATED]: (d) => `Challenge initiated (${d.purpose}) — session ${d.sessionId}`,
  [HISTORY_KINDS.CHALLENGE_OUTCOME]: (d) => `Challenge outcome (${d.purpose}) — ${d.granted ? 'granted' : 'denied'} — session ${d.sessionId}`,
  [HISTORY_KINDS.DURESS_TRIGGERED]: (d) => `⚠ Duress passcode used (${d.purpose}) — session ${d.sessionId}`,
  [HISTORY_KINDS.DEVICE_ADDED]: (d) => `Device added: ${d.deviceName}`,
  [HISTORY_KINDS.DEVICE_REMOVED]: (d) => `Device removed: ${d.deviceName}`,
  [HISTORY_KINDS.UNLOCK_POLICY_CHANGED]: (d) => `Unlock policy changed to "${d.policy}"`,
  [HISTORY_KINDS.THRESHOLD_UPDATED]: () => `Mesh & threshold settings updated`,
  [HISTORY_KINDS.RESPONDER_APPROVED]: (d) => `Approved a ${d.requestKind} request from "${d.fromVaultName}"`,
  [HISTORY_KINDS.RESPONDER_DENIED]: (d) => `Denied a ${d.requestKind} request from "${d.fromVaultName}"`,
  [HISTORY_KINDS.REAL_DISPATCH_SENT]: (d) => `Real ${d.channelKind} sent to ${d.deviceName} — session ${d.sessionId}`,
};

function historyRows(entries) {
  return entries.map((entry) => {
    const labelFn = HISTORY_LABELS[entry.kind];
    const label = labelFn ? labelFn(entry.detail) : entry.kind;
    return el('li', { className: 'dispatch-row' }, [
      el('span', { className: 'device-name', textContent: label }),
      el('span', { className: 'hint', textContent: formatTimestamp(entry.at) }),
    ]);
  });
}

/** Renders the History card with stable ids (#history-heading, #history-list) so
 * `refreshHistorySection` can rebuild it in place after an action appends a new entry to
 * `session.registry` — without this, a history-appending action taken after the tab first mounted
 * (initiating a challenge, evaluating an outcome, responding to a request) would silently not show
 * up until the next full tab switch, since this card would otherwise only ever read the registry
 * snapshot captured when `renderRequestsTab` first ran. Shown under both sub-tabs. */
function renderHistorySection() {
  const entries = listHistory(session.registry);
  const rows = historyRows(entries);
  return el('section', { className: 'card' }, [
    el('h2', { id: 'history-heading', textContent: `History (${entries.length})` }),
    el('p', { className: 'hint', textContent: 'A record of challenges, responses, and security changes for this vault, newest first.' }),
    el('ul', { className: 'dispatch-list', id: 'history-list' }, rows.length ? rows : [el('li', { textContent: 'Nothing yet.' })]),
  ]);
}

/** Rebuilds the History card's heading/list in place from the CURRENT `session.registry` — called
 * after every action in this file that appends a history entry. `tabContainer` is the Requests
 * tab's own root container (passed down from `renderRequestsTab`), so this works no matter how
 * deep in the DOM the action that triggered it happened. */
function refreshHistorySection(tabContainer) {
  if (!tabContainer) return;
  const heading = tabContainer.querySelector('#history-heading');
  const list = tabContainer.querySelector('#history-list');
  if (!heading || !list) return;
  const entries = listHistory(session.registry);
  heading.textContent = `History (${entries.length})`;
  list.innerHTML = '';
  const rows = historyRows(entries);
  for (const row of rows.length ? rows : [el('li', { textContent: 'Nothing yet.' })]) {
    list.append(row);
  }
}
