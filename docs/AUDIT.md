# Recce Audit Log

Recce's investigations workspace records audit events in the local SQLite
database at `~/.local/share/recce/investigations.sqlite3`.

## Chain Format

Each audit event stores:

- `created_at`: UTC ISO-8601 timestamp.
- `event_type`: internal event name such as `investigation.created`.
- `payload_json`: canonical JSON created with sorted keys.
- `previous_hash`: full hex hash of the previous audit event.
- `event_hash`: full hex hash for this audit event.

The hash is:

```text
SHA-256(previous_hash | created_at | event_type | payload_json)
```

Genesis events use an empty `previous_hash`. The `|` character is reserved as
the structural delimiter in the hash input. `payload_json` is canonicalised JSON
and treated as one opaque field, not flattened into delimiter-separated fields.

## Verification

The GUI Investigations dashboard verifies the full local audit chain and shows
the status in the "Audit events" expander. The verifier walks `audit_events` in
SQLite insertion order, checks each `previous_hash`, recalculates the event
hash, and reports the first mismatch.

## Threat Model

The hash chain detects edits to historical audit rows and insertion of forged
rows by anyone who does not also rewrite every following hash consistently.

It does not, by itself, prove that trailing events were not deleted. A sealed
export or external timestamping step is needed for that stronger guarantee.

Case exports include the selected case's audit events for review. Those exports
are case-filtered slices of the global audit chain, so they are useful for
reviewing what happened in that case but are not standalone proof that no
events were omitted before or after the exported slice. Full chain verification
is performed against the local store.
