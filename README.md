# Audit Trail Lab

An independent, executable TypeScript study of tamper-evident audit records. Built as portfolio work by Marcus Girolneto; not an extraction of employer code, not Constellation Gate, and not a production security product.

## Problem

An operator records decisions made by an application. Later, a reviewer needs to check whether an exported sequence still matches a previously trusted checkpoint, including whether records were modified, reordered, or removed.

## Run

Node.js 22.18+ is required. No external service, account, or API key is needed.

```sh
npm ci
npm run typecheck
npm test
npm run demo
```

The demo produces `ok: true` for the original records and `ok: false` for modified and truncated copies. All demo events are synthetic. The program records decisions supplied by the caller; it does **not** detect prompt injection or decide whether requests are safe.

## Design

Each SHA-256 digest covers a versioned domain separator, sequence number, previous digest, and three bounded event fields. A fixed-position JSON array provides unambiguous serialization for this deliberately narrow schema. Verification validates the entire chain against a supplied record count and head digest.

```text
Synthetic application decisions
             |
             v
     In-memory single writer ---> immutable record snapshots
             |                              |
             v                              v
       checkpoint                    exported records
             |                              |
   independently trusted store ------------> verifier
```

The trusted store is an architectural requirement, not implemented here. Keeping the checkpoint beside the log under the same attacker-controlled permissions defeats the trust model.

## Threat model and limits

- Detects changes to an exported sequence relative to an unchanged, trusted checkpoint.
- Detects suffix truncation through the checkpoint's count, not just linked hashes.
- A rewritten chain is rejected against the old checkpoint. A rewritten chain **and** replaced checkpoint can pass; a test explicitly demonstrates this limitation.
- Does not prove that the original events were truthful, complete, timely, or produced by a particular identity.
- Does not provide signatures, blockchain anchoring, persistence, atomic disk writes, multi-writer concurrency, retention controls, encryption, or access control.
- Audit fields must not contain prompts, credentials, or personal information. The schema rejects unknown fields but cannot detect sensitive information inside strings.
- Verification is O(n); the entire input is already in memory. This is unsuitable for unbounded, untrusted uploads without external size limits.

## Validation

Tests exercise valid and empty chains, JSON round trips, modified records, missing records, reordering, duplication, insertion, full-chain rewrites, malformed input, input mutation, deterministic serialization, and Unicode values. CI runs type checking and the same tests.

## Trade-offs

A hash chain is easy to inspect and adequate for this small demonstration. A Merkle structure would support more efficient inclusion proofs but adds complexity that this example does not need. Durable storage and authenticated external checkpoints are prerequisites for evolving this into a real system.

## Authorship and scope

Created with AI assistance. The initial implementation includes automated tests and explicit limitations. It is a new portfolio demonstration, not evidence of historical production deployment. Review the code and reproduce the checks before relying on it.
