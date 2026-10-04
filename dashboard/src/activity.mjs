// Audit order is observable; task dependencies are not part of this API.
export function activityStatus(event, now = Date.now()) {
  const status = event.execution_status;
  if (status === 'RUNNING') return now - Date.parse(event.timestamp) > 120000
    ? { label: 'Execution unconfirmed', tone: 'neutral' }
    : { label: 'Running', tone: 'running' };
  if (status === 'EXECUTED_OUTPUT_BLOCKED') return { label: 'Output withheld', tone: 'blocked' };
  if (status === 'EXECUTED') return { label: event.decision === 'GHOST' || event.action === 'shell.exec' ? 'Emulated' : 'Completed', tone: event.decision === 'GHOST' || event.action === 'shell.exec' ? 'ghost' : 'done' };
  if (['BLOCK', 'THROTTLE', 'REJECTED', 'NOT_EXECUTED'].includes(status) || ['BLOCK', 'THROTTLE'].includes(event.decision)) return { label: event.decision === 'THROTTLE' ? 'Throttled' : 'Stopped', tone: 'blocked' };
  if (status === 'PENDING_APPROVAL') return { label: 'Awaiting approval', tone: 'waiting' };
  if (status === 'AUTHORIZED_EXTERNAL') return { label: 'Awaiting tool result', tone: 'waiting' };
  return { label: 'Decision recorded', tone: 'neutral' };
}

export function sessionKey(event) {
  // Session IDs are caller supplied: never join different users or missing IDs.
  return JSON.stringify([event.user, event.agent, event.session_id || event.id]);
}

export function activityLanes(events, agent, session = '') {
  const groups = new Map();
  const sorted = [...events].filter(e => e.agent === agent && (!session || sessionKey(e) === session))
    .sort((a, b) => Date.parse(a.timestamp) - Date.parse(b.timestamp) || a.id.localeCompare(b.id));
  for (const event of sorted) {
    const key = sessionKey(event);
    if (!groups.has(key)) groups.set(key, { key, user: event.user, session: event.session_id, events: [] });
    groups.get(key).events.push(event);
  }
  return [...groups.values()].sort((a, b) => Date.parse(b.events.at(-1).timestamp) - Date.parse(a.events.at(-1).timestamp));
}

export function mergeActivity(previous, incoming, cutoff) {
  const map = new Map(previous.map(e => [e.id, e]));
  for (const e of incoming) map.set(e.id, e);
  return [...map.values()].filter(e => Date.parse(e.timestamp) >= cutoff)
    .sort((a, b) => Date.parse(b.timestamp) - Date.parse(a.timestamp)).slice(0, 1000);
}
