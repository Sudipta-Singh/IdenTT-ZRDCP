import { describe, it, expect } from 'vitest';
import { createRegistry } from '../src/registry/registry.js';
import { appendHistory, listHistory, clearHistory, HISTORY_KINDS } from '../src/vault/history.js';

describe('history.js (per-vault event log, stored inside the registry)', () => {
  it('starts empty for a freshly created registry', () => {
    const registry = createRegistry();
    expect(listHistory(registry)).toEqual([]);
  });

  it('appendHistory returns a NEW registry (immutable) with one more entry', () => {
    const registry = createRegistry();
    const next = appendHistory(registry, { kind: HISTORY_KINDS.DEVICE_ADDED, detail: { deviceName: 'Phone' } });
    expect(registry.history ?? []).toEqual([]); // original untouched
    expect(next.history).toHaveLength(1);
    expect(next.history[0]).toMatchObject({ kind: HISTORY_KINDS.DEVICE_ADDED, detail: { deviceName: 'Phone' } });
    expect(next.history[0].id).toMatch(/^hist_/);
    expect(next.history[0].at).toBeTypeOf('string');
  });

  it('listHistory returns newest-first', () => {
    let registry = createRegistry();
    registry = appendHistory(registry, { kind: HISTORY_KINDS.DEVICE_ADDED, detail: { deviceName: 'first' } });
    registry = appendHistory(registry, { kind: HISTORY_KINDS.DEVICE_ADDED, detail: { deviceName: 'second' } });
    const listed = listHistory(registry);
    expect(listed.map((e) => e.detail.deviceName)).toEqual(['second', 'first']);
  });

  it('caps stored entries so a long-lived vault does not grow the history unboundedly', () => {
    let registry = createRegistry();
    for (let i = 0; i < 550; i++) {
      registry = appendHistory(registry, { kind: HISTORY_KINDS.CHALLENGE_INITIATED, detail: { i } });
    }
    expect(registry.history.length).toBe(500);
    // Oldest entries fell off first — the newest one kept is the last one appended.
    expect(registry.history[registry.history.length - 1].detail.i).toBe(549);
  });

  it('clearHistory empties the log', () => {
    let registry = createRegistry();
    registry = appendHistory(registry, { kind: HISTORY_KINDS.DEVICE_ADDED, detail: {} });
    registry = clearHistory(registry);
    expect(listHistory(registry)).toEqual([]);
  });
});
