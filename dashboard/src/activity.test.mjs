import test from 'node:test';
import assert from 'node:assert/strict';
import { activityLanes, activityStatus, mergeActivity } from './activity.mjs';

const now = Date.now();
const event = (id, overrides = {}) => ({ id, agent: 'agent', user: 'alice', session_id: 'same', timestamp: new Date(now).toISOString(), decision: 'ALLOW', execution_status: 'VERDICT_ONLY', ...overrides });

test('a verdict and external authorization do not claim execution', () => {
  assert.equal(activityStatus(event('a')).label, 'Decision recorded');
  assert.equal(activityStatus(event('a', { execution_status: 'AUTHORIZED_EXTERNAL' })).label, 'Awaiting tool result');
  assert.equal(activityStatus(event('a', { execution_status: 'EXECUTED_OUTPUT_BLOCKED' })).tone, 'blocked');
  assert.equal(activityStatus(event('a', { execution_status: 'RUNNING', timestamp: new Date(now - 121000).toISOString() }), now).label, 'Execution unconfirmed');
  assert.equal(activityStatus(event('a', { execution_status: 'EXECUTED', action: 'shell.exec' })).label, 'Emulated');
});

test('same session IDs owned by different users and missing IDs stay separate', () => {
  const lanes = activityLanes([event('1'), event('2', { user: 'bob' }), event('3', { session_id: '' }), event('4', { session_id: '' })], 'agent');
  assert.equal(lanes.length, 4);
  assert.equal(activityLanes([event('1', { agent: 'other' })], 'agent').length, 0);
});

test('replayed events update nodes in place and preserve chronological lanes', () => {
  const earlier = event('1', { timestamp: new Date(now - 2000).toISOString(), execution_status: 'RUNNING' });
  const merged = mergeActivity([earlier, event('2')], [{ ...earlier, execution_status: 'EXECUTED' }], now - 10000);
  assert.equal(merged.length, 2);
  assert.equal(activityLanes(merged, 'agent')[0].events[0].execution_status, 'EXECUTED');
  assert.deepEqual(activityLanes(merged, 'agent')[0].events.map(e => e.id), ['1', '2']);
  assert.equal(mergeActivity(merged, [], now + 1).length, 0);
});
