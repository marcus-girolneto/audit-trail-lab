import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AuditLog, GENESIS, verify } from '../src/audit.ts';

function fixture(): AuditLog {
  const log = new AuditLog();
  log.append({ requestId: 'first', policy: 'policy-v1', decision: 'allow' });
  log.append({ requestId: 'second', policy: 'policy-v1', decision: 'deny' });
  return log;
}

test('empty chain requires an empty trusted checkpoint', () => {
  assert.deepEqual(verify([], { count: 0, headHash: GENESIS }), { ok: true, count: 0 });
  assert.equal(verify([], fixture().checkpoint()).ok, false);
});

test('valid records survive JSON serialization', () => {
  const log = fixture();
  assert.deepEqual(verify(JSON.parse(JSON.stringify(log.records())), log.checkpoint()), { ok: true, count: 2 });
});

test('modification, removal, reordering, duplication and insertion are rejected', () => {
  const log = fixture();
  const records = log.records();
  const changed = JSON.parse(JSON.stringify(records));
  changed[0].event.decision = 'deny';
  const attacks = [changed, records.slice(1), records.slice(0, 1), [...records].reverse(),
    [records[0], records[0]], [...records, records[1]]];
  for (const attack of attacks) assert.equal(verify(attack, log.checkpoint()).ok, false);
});

test('a fully recomputed chain cannot match the original trusted anchor', () => {
  const replacement = new AuditLog();
  replacement.append({ requestId: 'first', policy: 'policy-v1', decision: 'deny' });
  replacement.append({ requestId: 'second', policy: 'policy-v1', decision: 'deny' });
  assert.equal(verify(replacement.records(), fixture().checkpoint()).ok, false);
  assert.equal(verify(replacement.records(), replacement.checkpoint()).ok, true);
});

test('input property order does not affect digest', () => {
  const first = new AuditLog();
  const second = new AuditLog();
  first.append({ requestId: 'id', policy: 'v1', decision: 'allow' });
  second.append({ decision: 'allow', policy: 'v1', requestId: 'id' });
  assert.deepEqual(first.checkpoint(), second.checkpoint());
});

test('writer isolates caller mutations and protects record objects', () => {
  const log = new AuditLog();
  const event = { requestId: 'id', policy: 'v1', decision: 'allow' as const };
  const record = log.append(event);
  event.requestId = 'changed';
  assert.equal(record.event.requestId, 'id');
  assert.throws(() => Object.assign(record.event, { requestId: 'changed' }), TypeError);
  assert.throws(() => Object.assign(record, { hash: GENESIS }), TypeError);
  log.records().pop();
  assert.equal(log.checkpoint().count, 1);
});

test('malformed events, records and anchors fail closed', () => {
  const log = fixture();
  for (const input of [null, {}, 'not-json', [null], [{ version: 2 }]]) {
    assert.equal(verify(input, log.checkpoint()).ok, false);
  }
  for (const anchor of [null, {}, { count: -1, headHash: GENESIS },
    { count: 2, headHash: 'invalid' }, { count: 2.5, headHash: GENESIS }]) {
    assert.equal(verify(log.records(), anchor).ok, false);
  }
  const records = JSON.parse(JSON.stringify(log.records()));
  records[0].event.secret = 'unrecognized';
  assert.equal(verify(records, log.checkpoint()).ok, false);
  assert.throws(() => log.append({ requestId: '', policy: 'v1', decision: 'allow' }), TypeError);
});

test('unicode and delimiter-like data round trip without ambiguity', () => {
  const log = new AuditLog();
  log.append({ requestId: 'ação|"\\\n', policy: '政策-v1', decision: 'allow' });
  assert.equal(verify(log.records(), log.checkpoint()).ok, true);
});
