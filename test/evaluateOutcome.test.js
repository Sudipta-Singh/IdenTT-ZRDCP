import { describe, it, expect } from 'vitest';
import { evaluateChallengeOutcome } from '../src/recovery/evaluateOutcome.js';

/** Builds a fake-but-shaped-right session object without going through initiateRecovery, since
 * this module only reads {purpose, requiredK, minRemoteForRecovery, dispatches}. */
function fakeSession({ purpose, requiredK, minRemoteForRecovery = null, dispatches }) {
  return { sessionId: 'session-fake', purpose, requiredK, minRemoteForRecovery, dispatches };
}

describe('evaluateChallengeOutcome (local simulation harness, not real reconstruction)', () => {
  describe('authentication', () => {
    it('grants when enough devices (any type) respond success', () => {
      const session = fakeSession({
        purpose: 'authentication',
        requiredK: 2,
        dispatches: [
          { deviceId: 'a', hasShare: false, isRemote: false },
          { deviceId: 'b', hasShare: false, isRemote: false },
          { deviceId: 'c', hasShare: false, isRemote: false },
        ],
      });
      const outcome = evaluateChallengeOutcome({ session, responses: { a: 'success', b: 'success', c: 'fail' } });
      expect(outcome.granted).toBe(true);
      expect(outcome.successCount).toBe(2);
    });

    it('denies when too few respond success', () => {
      const session = fakeSession({
        purpose: 'authentication',
        requiredK: 2,
        dispatches: [
          { deviceId: 'a', hasShare: false, isRemote: false },
          { deviceId: 'b', hasShare: false, isRemote: false },
        ],
      });
      const outcome = evaluateChallengeOutcome({ session, responses: { a: 'success', b: 'fail' } });
      expect(outcome.granted).toBe(false);
    });

    it('treats a device with no recorded response as a non-response (not a success)', () => {
      const session = fakeSession({
        purpose: 'authentication',
        requiredK: 2,
        dispatches: [
          { deviceId: 'a', hasShare: false, isRemote: false },
          { deviceId: 'b', hasShare: false, isRemote: false },
        ],
      });
      const outcome = evaluateChallengeOutcome({ session, responses: { a: 'success' } }); // b never answered
      expect(outcome.granted).toBe(false);
      expect(outcome.successCount).toBe(1);
    });
  });

  describe('recovery', () => {
    it('grants when enough share-holders succeed AND the remote requirement is met', () => {
      const session = fakeSession({
        purpose: 'recovery',
        requiredK: 2,
        minRemoteForRecovery: 1,
        dispatches: [
          { deviceId: 'local', hasShare: true, isRemote: false },
          { deviceId: 'remote', hasShare: true, isRemote: true },
          { deviceId: 'approvalOnly', hasShare: false, isRemote: false },
        ],
      });
      const outcome = evaluateChallengeOutcome({
        session,
        responses: { local: 'success', remote: 'success', approvalOnly: 'success' },
      });
      expect(outcome.granted).toBe(true);
      expect(outcome.metCount).toBe(true);
      expect(outcome.metRemote).toBe(true);
      expect(outcome.remoteSuccessCount).toBe(1);
    });

    it('denies when count is met but no remote share-holder succeeded (the whole point of the rule)', () => {
      const session = fakeSession({
        purpose: 'recovery',
        requiredK: 2,
        minRemoteForRecovery: 1,
        dispatches: [
          { deviceId: 'local1', hasShare: true, isRemote: false },
          { deviceId: 'local2', hasShare: true, isRemote: false },
          { deviceId: 'remote', hasShare: true, isRemote: true },
        ],
      });
      const outcome = evaluateChallengeOutcome({
        session,
        responses: { local1: 'success', local2: 'success', remote: 'fail' },
      });
      expect(outcome.metCount).toBe(true);
      expect(outcome.metRemote).toBe(false);
      expect(outcome.granted).toBe(false);
    });

    it('denies when the remote requirement is met but count is not', () => {
      const session = fakeSession({
        purpose: 'recovery',
        requiredK: 2,
        minRemoteForRecovery: 1,
        dispatches: [
          { deviceId: 'remote', hasShare: true, isRemote: true },
          { deviceId: 'local', hasShare: true, isRemote: false },
        ],
      });
      const outcome = evaluateChallengeOutcome({ session, responses: { remote: 'success', local: 'fail' } });
      expect(outcome.metCount).toBe(false);
      expect(outcome.metRemote).toBe(true);
      expect(outcome.granted).toBe(false);
    });

    it('an approval-only device succeeding never counts toward the share-holder count', () => {
      const session = fakeSession({
        purpose: 'recovery',
        requiredK: 1,
        minRemoteForRecovery: 1,
        dispatches: [{ deviceId: 'approvalOnly', hasShare: false, isRemote: true }],
      });
      const outcome = evaluateChallengeOutcome({ session, responses: { approvalOnly: 'success' } });
      expect(outcome.successCount).toBe(0);
      expect(outcome.granted).toBe(false);
    });
  });
});
