import { describe, it, expect, vi, afterEach } from 'vitest';
import { sendReal, checkBackendHealth, RealDispatchError } from '../src/dispatch/realDispatch.js';

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
});

describe('realDispatch.js (thin client for the local server/ backend)', () => {
  it('rejects an unsupported channel kind without ever calling fetch', async () => {
    globalThis.fetch = vi.fn();
    await expect(sendReal({ channelKind: 'webapi', address: 'x', message: 'm' })).rejects.toThrow(RealDispatchError);
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it('posts to /send-email with the expected body for an email dispatch', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true, id: 'msg-1' }) });
    const result = await sendReal({ channelKind: 'email', address: 'a@b.com', subject: 'Hi', message: 'body text' });
    expect(result).toEqual({ ok: true, id: 'msg-1' });
    const [url, opts] = globalThis.fetch.mock.calls[0];
    expect(url).toContain('/send-email');
    expect(JSON.parse(opts.body)).toEqual({ to: 'a@b.com', subject: 'Hi', text: 'body text' });
  });

  it('posts to /send-sms with the expected body for an sms dispatch', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true, id: 'sms-1' }) });
    const result = await sendReal({ channelKind: 'sms', address: '+15555555555', message: 'body text' });
    expect(result).toEqual({ ok: true, id: 'sms-1' });
    const [url, opts] = globalThis.fetch.mock.calls[0];
    expect(url).toContain('/send-sms');
    expect(JSON.parse(opts.body)).toEqual({ to: '+15555555555', body: 'body text' });
  });

  it('surfaces the backend error message when the backend responds with an error', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: false, status: 503, json: async () => ({ error: 'SMTP is not configured' }) });
    await expect(sendReal({ channelKind: 'email', address: 'a@b.com', message: 'm' })).rejects.toThrow('SMTP is not configured');
  });

  it('wraps a network failure (backend not running) in a clear RealDispatchError', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('connect ECONNREFUSED'));
    await expect(sendReal({ channelKind: 'email', address: 'a@b.com', message: 'm' })).rejects.toThrow(/could not reach the local IdenTT backend/);
  });

  it('checkBackendHealth never throws — reports unreachable on a network failure', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('connect ECONNREFUSED'));
    await expect(checkBackendHealth()).resolves.toEqual({ reachable: false, email: false, sms: false });
  });

  it('checkBackendHealth reports provider configuration when reachable', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ ok: true, email: true, sms: false }) });
    await expect(checkBackendHealth()).resolves.toEqual({ reachable: true, email: true, sms: false });
  });
});
