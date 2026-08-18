// IdenTT — simulated dispatch layer (Phase 2 scope).
//
// Per the plan, real email/SMS/voice/WebAPI sending is deferred to Phase 6 (needs Twilio/SMTP
// credentials). This module produces the same SHAPE of output a real dispatcher would — one
// activity-log entry per trusted device, with a channel, an address, a payload summary, and a
// responder link — but "sending" is just returning that entry, not making a network call.
//
// The responder link points at this app's own Responder Mode, which doesn't exist yet (Phase 3) —
// the link format is fixed now so it doesn't need to change when that screen is built.

/** Builds the link a trusted device holder would open to respond to a session. Uses a
 * custom-scheme-shaped URL for now since there's no real hosted responder site yet (§2 of the
 * plan: "Same local app, 'Responder Mode'" for the MVP) — swap the base for a real URL once
 * Responder Mode exists (Phase 3) or a hosted site exists (Phase 6). */
export function buildResponderLink({ sessionId, deviceId }, base = 'identt://responder') {
  const params = new URLSearchParams({ session: sessionId, device: deviceId });
  return `${base}?${params.toString()}`;
}

/**
 * Simulates dispatching one challenge session to one trusted device over its first configured
 * contact channel.
 *
 * @param {object} args
 * @param {object} args.device - a registry device (zrdcp-native or fido2).
 * @param {string} args.sessionId
 * @param {'authentication'|'recovery'} args.purpose
 * @param {object} args.recoveryInitMessage - from `buildRecoveryInit`, sent to every device.
 * @param {object|null} args.shareDeliveryMessage - from `buildShareDelivery`, or null for
 *   authentication (never carries a share) and for approval-only devices during a recovery.
 */
export function simulateDispatchToDevice({ device, sessionId, purpose, recoveryInitMessage, shareDeliveryMessage }) {
  const channel = device.contactChannels[0];
  const responderLink = buildResponderLink({ sessionId, deviceId: device.id });
  const hasShare = shareDeliveryMessage !== null && shareDeliveryMessage !== undefined;

  let payloadPreview;
  if (purpose === 'authentication') {
    payloadPreview = `AUTH_CHALLENGE (session ${sessionId.slice(0, 10)}…) — please approve or deny this authentication request. No share exchange is involved.`;
  } else if (hasShare) {
    payloadPreview = `RECOVERY_INIT (session ${sessionId.slice(0, 10)}…) + your encrypted share (node_index ${shareDeliveryMessage.node_index}). Open the responder link to review and approve.`;
  } else {
    payloadPreview = `RECOVERY_INIT (session ${sessionId.slice(0, 10)}…) — you're an approval-only participant on this mesh. Open the responder link to authenticate and approve; no share is sent to you.`;
  }

  return {
    deviceId: device.id,
    deviceName: device.name,
    deviceType: device.type,
    isRemote: device.isRemote ?? false,
    participationMode: device.type === 'fido2' ? device.participationMode : 'full-share',
    channelKind: channel?.kind ?? 'unknown',
    address: channel?.address ?? '(no contact channel configured)',
    hasShare,
    payloadPreview,
    // The actual wire messages this dispatch would carry — both are already public/ciphertext by
    // design (the whole point of NIZK + AES-GCM wrapping), so echoing them back here is exactly
    // what a real email/SMS/WebAPI payload would attach.
    recoveryInitMessage,
    shareDeliveryMessage: hasShare ? shareDeliveryMessage : null,
    responderLink,
    simulated: true,
    dispatchedAt: new Date().toISOString(),
  };
}
