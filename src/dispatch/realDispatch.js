// IdenTT — real (non-simulated) email/SMS dispatch, added this session alongside the small local
// Node/Express backend under server/. Browsers can't open raw SMTP sockets and can't safely hold a
// Twilio Auth Token client-side, so this module is a thin fetch() wrapper that hands the actual
// sending off to that backend, which holds the real credentials in its own .env (see
// server/.env.example) and is never bundled into the browser app.
//
// This is additive, not a replacement: src/dispatch/simulate.js (and the whole simulated-response
// evaluate-outcome flow it feeds) is unchanged and still the default way to exercise a challenge
// end-to-end without any real credentials configured. `sendReal` is wired in as a per-row "Send for
// real" action on the Requests tab (src/app/screens/requests.js) for email/sms rows specifically —
// see that file for how a dispatch row's existing `channelKind`/`address`/`payloadPreview` map onto
// this function's arguments.

export const DEFAULT_BASE_URL = 'http://localhost:4737';

export class RealDispatchError extends Error {
  constructor(message) {
    super(message);
    this.name = 'RealDispatchError';
  }
}

/**
 * @param {object} args
 * @param {'email'|'sms'} args.channelKind
 * @param {string} args.address - recipient email address or phone number.
 * @param {string} args.subject - used for email only.
 * @param {string} args.message - body text.
 * @param {string} [args.baseUrl]
 * @returns {Promise<{ok: true, id: string}>}
 */
export async function sendReal({ channelKind, address, subject, message, baseUrl = DEFAULT_BASE_URL }) {
  if (channelKind !== 'email' && channelKind !== 'sms') {
    throw new RealDispatchError(`real dispatch only supports 'email' and 'sms' channels, got '${channelKind}'`);
  }
  const path = channelKind === 'email' ? '/send-email' : '/send-sms';
  const body =
    channelKind === 'email'
      ? { to: address, subject: subject || 'IdenTT request', text: message }
      : { to: address, body: message };

  let response;
  try {
    response = await fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
  } catch (e) {
    throw new RealDispatchError(
      `could not reach the local IdenTT backend at ${baseUrl} — is it running? (cd server && npm install && npm start, after filling in server/.env). Original error: ${e.message}`
    );
  }

  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new RealDispatchError(payload.error || `backend responded with HTTP ${response.status}`);
  }
  return payload;
}

/** Best-effort backend reachability + configuration check, for a status indicator in the UI.
 * Never throws — a network failure just reads as "backend not reachable." */
export async function checkBackendHealth(baseUrl = DEFAULT_BASE_URL) {
  try {
    const response = await fetch(`${baseUrl}/health`, { method: 'GET' });
    if (!response.ok) return { reachable: false, email: false, sms: false };
    const body = await response.json();
    return { reachable: true, email: !!body.email, sms: !!body.sms };
  } catch {
    return { reachable: false, email: false, sms: false };
  }
}
