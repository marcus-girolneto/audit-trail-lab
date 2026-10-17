import { AuditLog, verify } from './audit.ts';

const log = new AuditLog();
log.append({ requestId: 'demo-001', policy: 'synthetic-policy-v1', decision: 'allow' });
log.append({ requestId: 'demo-002', policy: 'synthetic-policy-v1', decision: 'deny' });
const trustedCheckpoint = log.checkpoint();
const altered = JSON.parse(JSON.stringify(log.records()));
altered[0].event.decision = 'deny';

console.log(JSON.stringify({
  valid: verify(log.records(), trustedCheckpoint),
  modified: verify(altered, trustedCheckpoint),
  truncated: verify(log.records().slice(0, 1), trustedCheckpoint),
  checkpoint: trustedCheckpoint,
}, null, 2));
