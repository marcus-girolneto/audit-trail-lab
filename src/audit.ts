import { createHash } from 'node:crypto';

export type AuditEvent = Readonly<{
  requestId: string;
  policy: string;
  decision: 'allow' | 'deny';
}>;

export type AuditRecord = Readonly<{
  version: 1;
  sequence: number;
  previousHash: string;
  event: AuditEvent;
  hash: string;
}>;

export type Checkpoint = Readonly<{ count: number; headHash: string }>;
export type Verification =
  | { ok: true; count: number }
  | { ok: false; reason: string; index?: number };

export const GENESIS = '0'.repeat(64);

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasKeys(value: Record<string, unknown>, keys: string[]): boolean {
  return Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}

function validEvent(value: unknown): value is AuditEvent {
  if (!isObject(value) || !hasKeys(value, ['requestId', 'policy', 'decision'])) return false;
  return typeof value.requestId === 'string' && value.requestId.length > 0 && value.requestId.length <= 128
    && typeof value.policy === 'string' && value.policy.length > 0 && value.policy.length <= 128
    && (value.decision === 'allow' || value.decision === 'deny');
}

function validHash(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

function digest(sequence: number, previousHash: string, event: AuditEvent): string {
  const payload = JSON.stringify([
    'audit-trail-lab/v1', sequence, previousHash,
    event.requestId, event.policy, event.decision,
  ]);
  return createHash('sha256').update(payload, 'utf8').digest('hex');
}

export function verify(records: unknown, checkpoint: unknown): Verification {
  if (!Array.isArray(records)) return { ok: false, reason: 'records must be an array' };
  if (!isObject(checkpoint) || !hasKeys(checkpoint, ['count', 'headHash'])
    || !Number.isSafeInteger(checkpoint.count) || (checkpoint.count as number) < 0
    || !validHash(checkpoint.headHash)) {
    return { ok: false, reason: 'invalid checkpoint' };
  }
  if (records.length !== checkpoint.count) return { ok: false, reason: 'checkpoint count mismatch' };
  let previousHash = GENESIS;
  for (const [index, record] of records.entries()) {
    if (!isObject(record) || !hasKeys(record, ['version', 'sequence', 'previousHash', 'event', 'hash'])
      || record.version !== 1 || record.sequence !== index || record.previousHash !== previousHash
      || !validEvent(record.event) || !validHash(record.hash)) {
      return { ok: false, reason: 'invalid record or chain link', index };
    }
    if (record.hash !== digest(index, previousHash, record.event)) {
      return { ok: false, reason: 'record hash mismatch', index };
    }
    previousHash = record.hash;
  }
  if (previousHash !== checkpoint.headHash) return { ok: false, reason: 'checkpoint head mismatch' };
  return { ok: true, count: records.length };
}

export class AuditLog {
  #records: AuditRecord[] = [];

  append(event: AuditEvent): AuditRecord {
    if (!validEvent(event)) throw new TypeError('Invalid audit event');
    const sequence = this.#records.length;
    const previousHash = this.#records.at(-1)?.hash ?? GENESIS;
    const storedEvent = Object.freeze({ ...event });
    const record: AuditRecord = Object.freeze({
      version: 1, sequence, previousHash, event: storedEvent,
      hash: digest(sequence, previousHash, storedEvent),
    });
    this.#records.push(record);
    return record;
  }

  records(): AuditRecord[] {
    return [...this.#records];
  }

  checkpoint(): Checkpoint {
    return Object.freeze({
      count: this.#records.length,
      headHash: this.#records.at(-1)?.hash ?? GENESIS,
    });
  }
}
