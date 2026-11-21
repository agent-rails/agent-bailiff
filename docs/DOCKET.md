# Docket

The docket is one file of newline-terminated signed records. Each record names its writer and carries a per-writer `seq` (starting at 1) and `prev`, the hash of that writer's previous record. One `DocketSink` process owns the file; writers append through `DocketClient` over a Unix socket.

## Trust model

- The sink uid, and root, are trusted for the docket file. Either can truncate, delete or replace it. Signatures stop them from forging or altering a writer's records without that writer's key; they do not stop removal of records.
- Append-only is enforced by the application: the sink opens the docket with `O_APPEND` and only appends. The file system does not enforce it.
- A writer is identified by its pinned Ed25519 key ids. The sink also accepts a connection only from a peer uid in `allowed_uids`; the client accepts a sink only if its peer uid equals the configured `sink_uid`.
- An entry means the operation was attempted or decided. It is not proof the operation happened or of its outcome; the outcome must come from reconciliation against the target system.

## Sink guarantees

- One sink per docket and per socket: the sink holds an exclusive non-blocking `flock` on the docket and on `<socket>.lock` for its lifetime. A second sink fails with `DocketLocked`.
- At start, under the lock, the sink checks the docket's parent directory (not a symlink, owned by the sink uid, not writable by group or others), the docket file (regular, owned by the sink uid, mode 0600; with `reader_group` set, mode 0640 and that group instead) and fsyncs the parent directory, then loads each writer's head through the same descriptor it appends to: from the heads snapshot when there is one, else by verifying every record (see Heads snapshot). A failed directory fsync makes the sink refuse every append.
- An append is acknowledged only after the full line is written and fsynced. A failed write or fsync makes the sink refuse every later append until restart.
- On close the sink removes the socket path only if it is still the socket it bound.
- Connections: the peer uid is checked before a connection counts against `max_connections` (default 16). A connection past the limit gets the refusal `overloaded` and is closed; nothing is appended, so the writer knows the record was not written. Every allowed peer shares the limit: an allowed peer that holds 16 connections open makes the other writers' appends fail with `overloaded` until `idle_timeout` or `max_lifetime` closes them. The client does not retry: decide refuses the call as `docket_unavailable`, and the custodian does not release a credential. Only the uids in `allowed_uids` can do this. A connection is closed after `idle_timeout` without a frame, when a frame takes longer than `frame_timeout`, and at `max_lifetime`.
- On macOS, `os.fsync` does not issue `F_FULLFSYNC`, so the drive may still hold acknowledged data in its cache.

## Heads snapshot

`<docket>.snapshot` lets the sink start without verifying every record. It holds a byte offset that ends a verified line, the number of records before it, the SHA-256 of the bytes before it, each writer's anchor (the byte offset, `seq` and hash of the writer's last record before the offset) and the key ids of the records before it. It is canonical JSON of at most 4 MiB, owned by the sink uid with the docket's mode and group (0600, or 0640 and `reader_group`).

- Start with a snapshot: the sink reads it after taking the docket lock and checking the docket file. It refuses to start with `snapshot_mismatch` if the snapshot file is not a regular file with the right owner, mode and group or not a valid snapshot, the offset is past the end of the docket, a key id it lists is not pinned, the SHA-256 of the bytes before the offset differs, or an anchor is not a whole line before the offset that decodes to that writer's record at that `seq` and hash. It then verifies every record after the offset, seeded with the anchors as heads; any failure there refuses start as it does without a snapshot.
- Start without a snapshot: the sink verifies every record, fsyncs the docket and writes a snapshot. Deleting the snapshot is always safe; the next start verifies every record again and gives the same heads.
- `snapshot_every` (required in the docket config; `agent-bailiff init docket` writes 10000) is the number of acknowledged appends between snapshot writes. After that many, the sink writes a snapshot once the current reply is sent. `close()` writes one after the last connection ends. Each write first fsyncs the docket, so a snapshot never covers bytes that are not on disk; if that fsync fails, or the sink refuses appends after a failed write, no snapshot is written. The offset is the end of the last acknowledged record, never the file size. A snapshot is written to a temporary file (0600, fsynced), renamed over the old one and the directory fsynced. A failed write logs an error and keeps the old snapshot; any other error logs and stops snapshot writes until restart. A stale snapshot only makes the next start verify more records.
- Measured on one host: start with 10k records and a 2k-record tail took 0.34 s against 1.67 s for a full verify; a snapshot write took 0.20 ms (median).

### What start no longer checks

Start trusts the bytes before the snapshot offset if their SHA-256 matches. The sink uid, or root, can rewrite both the docket and the snapshot, and then the sink starts:

- Deleting or rewriting a record before the offset and writing a snapshot that matches the result is not detected at start. `docket verify` fails on the broken chain.
- A snapshot that omits a writer's anchor, or holds an older one, lets that writer start again at `seq` 1 or fork from an older head when its client has no state file, for example a fresh state directory. The sink accepts the fork; `docket verify` and the exporter refuse the docket from the forked line on.
- Restoring an older docket together with its older snapshot is a rollback: start accepts it. Writer-side rollback detection reports it to a writer whose state file is newer.
- Anchors and key ids come only from records signed by pinned keys, so a snapshot holds at most one anchor per configured writer; the 4 MiB cap covers the largest writer set a config can hold.

These were caught at every restart before; they are now caught only by `docket verify`. Run `docket verify --snapshot <docket>.snapshot` on a schedule, as a reader group member or the sink uid, and alert when it exits 1. The longest time a doctored prefix goes unnoticed is the interval between runs plus one run; pick the interval as the longest window you accept. Neither the sink nor the exporter re-verifies records before its own resume point.

## Readers

A docket config with `reader_group` set lets members of that group read the docket without running as the sink uid. `agent-bailiff init docket --reader-group <gid>` gives the docket directory that group and mode 0750; the sink creates a new docket with that group and mode 0640 and refuses to start on any other mode or group. The sink uid must be a member of the group, or init and the first start fail. `config.json` stays 0600, so readers never read the sink config; they take writer pins from their own copies of the writers' public key records.

- Readers see every record: tools, resources, principals, tenants and argument digests, never the arguments themselves.
- Readers cannot append, truncate or replace the docket. `docket verify` detects forged, altered, reordered or deleted records within each writer's chain; it cannot detect the sink uid truncating the newest records of a writer. The sink's start checks less; see Heads snapshot.
- Without `reader_group` the docket stays 0600 and only the sink uid and root can read it.
- To add `reader_group` to an existing docket: stop the sink, give the directory the group and mode 0750 and the docket and `<docket>.snapshot` the group and mode 0640, set `reader_group` in `config.json`, then start the sink. Removing it is the reverse, back to 0700 and 0600; the sink refuses to start on any mix, and a snapshot left at the old mode refuses start with `snapshot_mismatch`.

## docket verify

```
agent-bailiff docket verify --docket PATH --pin decide.pub.json --pin custodian.pub.json [--trace ID] [--task ID] [--since UNIX_SECONDS] [--json] [--snapshot PATH]
```

Run it as a reader group member, the sink uid or root; it needs read access to the docket only, never the sink config. Each `--pin` is a writer's public key record; pass one per writer key, including retired keys whose records are still in the docket. Take pins from the writers' own key directories, not from a copy stored next to the docket, or whoever can replace the docket can replace the pins too.

- Every record is verified, from the first line to the last, whatever the filters. `--trace`, `--task` (the record's task root, or the `task` handle of a revocation) and `--since` (records at or after that Unix time, UTC) only choose which verified records are printed.
- Records print as tab-separated columns, with control and non-ASCII characters escaped; `--json` prints one JSON object per record, including the signed `token`, so a record can be passed on as written. The summary goes to stderr.
- A record with `performed` true is labelled `released, target outcome unknown`: the custodian released the credential, and the docket does not record what the target did with it.
- Exit 0 when every record verifies. Exit 1 when a line fails: the records before it are printed, and stderr names the line and reason. Exit 1 too for an unreadable docket or pin.
- `--snapshot PATH` also cross-checks a heads snapshot. The snapshot must be owned by the docket's owner with mode 0600, or 0640 and the docket's group when the docket is 0640. After every record verifies, the record count, the SHA-256 of the bytes before the snapshot offset, each writer's anchor and the key ids are rebuilt from the verified records and compared. Exit 1 if any differ, if the offset is not the end of a verified line, or if the snapshot is missing or invalid; stderr names the fields that differ. On a match, stderr also gives the number of records after the snapshot. Exit 0 does not mean the snapshot is recent: a snapshot that stopped being refreshed still matches. Alert on that count if it keeps growing past `snapshot_every`. The records printed are the same with and without it.
- Verifying a docket while the sink is appending can report `torn_tail` for a line still being written. Run it again; if `torn_tail` stays, follow Torn tail repair.

## docket export

```
pip install 'agent-bailiff[otel]'
agent-bailiff docket export --docket PATH --pin decide.pub.json --pin custodian.pub.json --checkpoint DIR/checkpoint.json --otlp http://collector:4318/v1/traces [--once] [--skip-line N]
```

Run it as a reader group member in its own process, with its own uid and a 0700 checkpoint directory. It reads the docket and pins the same way `docket verify` does, verifies every record, and sends each one as an OTLP/HTTP span. It is off the call path: decide and the custodian never wait for it, and a stopped or failing exporter changes no decision. Without `--once` it follows the docket until SIGTERM or SIGINT.

- Spans are a view, not evidence. The docket and `docket verify` are the record; a collector or trace backend can drop, alter or invent spans without a writer key.
- The span id is the first 8 bytes of sha256 over a fixed tag and the entry id, and the parent is derived the same way from `parent_entry`. Re-exporting a record sends the same ids. Two entry ids sharing an 8-byte prefix would collide; with random 128-bit entry ids this is negligible.
- Attributes are the record's fields under `bailiff.*`, the docket line, writer, seq, kid and record hash, and `gen_ai.tool.name`, `gen_ai.operation.name` and `error.type` from the [GenAI semantic conventions at 622b2b6](https://github.com/open-telemetry/semantic-conventions-genai/blob/622b2b6073b15e5ed886c3c12a65a892b9cd5c70/docs/gen-ai/mcp.md), whose status is Development and may change. A refusal is an error span with its reason. A release carries `bailiff.note` = `released, target outcome unknown`. Arguments are never exported; the docket holds only their digest.
- The span backend then holds what docket readers see: principals, tenants, tools and resources. Restrict access to it as you restrict the reader group.
- The resource `service.name` is `agent-bailiff-<writer>`. The span ends at the record's `at` (whole seconds) and starts `latency_ms` earlier.

### Trace ids

The trace id comes from the caller's `traceparent` and is not authenticated: an agent can choose any trace id, including one already used by another agent's calls, so grouping spans by trace says nothing about who made them. Use the signed `bailiff.principal`, `bailiff.tenant` and `bailiff.task_root` attributes, or `docket verify`, to attribute a call. The gateway adapter treats an all-zero trace or parent id as absent. A record whose trace id is not 32 lowercase hex characters, or is all zeros, gets a trace id derived from its entry id, `bailiff.trace_id_mapped` is set, and the raw value is not exported, so a caller cannot place text of its choosing in the trace id field.

### Delivery and checkpoint

- At least once. After each batch the backend accepts, the exporter writes the checkpoint (mode 0600, written to a temporary file, fsynced, renamed, directory fsynced). A crash between acceptance and the checkpoint write sends that batch again on restart. Backends that do not deduplicate by span id may keep both copies.
- The checkpoint holds the byte offset and count of exported records, each writer's head, the docket's device and inode, the hash of its first record and the hash and offset of the last exported one. On start the exporter refuses a docket that is another file, shorter than the offset, or whose first or last exported record differs, then verifies forward from the saved heads. It does not read the exported records between the first and last again, so a change to them by the sink uid or root is not detected on resume; `docket verify` checks every record. While following, it refuses a docket path that now names another file.
- One exporter per checkpoint: it holds an exclusive `flock` on `<checkpoint>.lock` while it runs, and a second exporter exits 1.
- Each pass reads only up to the size the docket had at its start. Reading stops while a batch is exported, so a slow backend slows the exporter and nothing is dropped.
- A failed batch is sent again. The SDK retries transient errors (429, 502, 503, 504 and connection errors) with backoff within `--timeout`; after `--max-failures` failed attempts of one batch the command exits 1 and the checkpoint stays at the last exported record.
- SIGTERM lets the batch in flight finish and write its checkpoint, then exits 0. If that batch fails, it is not sent again: the command exits 1 and the checkpoint stays at the last exported record.
- An incomplete last line is left for the next pass. If it stays for 30s the exporter logs a warning naming the line after the last exported record; see Torn tail repair.
- A line the sink wrote but could not fsync was refused to its writer but is still in the file; if it verifies, the exporter sends it.

### Resume runbook

- Exit 1 after failed exports: check the backend is reachable at `--otlp`, then start the exporter again. It resumes after the last exported record.
- Exit 1 because the backend refuses one record (the same batch keeps failing while the backend accepts others): run `--once --batch-size 1` to find the line; the error names it. Then run once with `--skip-line N`. N must be the next line to export, or the command exits 1 and sends nothing. That line is sent as a marker span named `docket export_skipped`, with error status, `bailiff.export_skipped` = true, and the entry id, docket line, writer, seq, kid, record hash and record time (`bailiff.entry_at`). It keeps the record's trace and span ids, but carries none of the record's other fields, and its span time is the time of export, so a backend that refuses old spans still accepts it. The exporter logs a warning and moves on. The record stays in the docket: `docket verify` still prints it. If the export stops before reaching line N (a `--skip-line` past the end of the docket, or a stop signal in follow mode), it exits 1 with nothing skipped. Alert on `bailiff.export_skipped` = true in the backend; find the skipped record with `docket verify --trace <the marker's trace id>`.
- Exit 1 because the backend rejected spans through an OTLP partial success (HTTP 200 with `rejected_spans` set): the error names the batch's lines and the backend's message. A partial rejection is not retried, as the OTLP spec requires, and the checkpoint stays before the batch. Rerunning sends the whole batch again; the accepted spans keep their span ids, so the backend gets duplicates with the same ids. Find the rejected record and skip it as above. A partial success with only an error message and no rejected spans is exported and logged as a warning.
- Exit 1 because the backend answered with a success status other than 200 (for example a redirect from an http endpoint to https; redirects are not followed): the export is not retried and the checkpoint stays before the batch. The OTLP spec requires 200 for success. Point `--otlp` at the collector's final URL.
- A reply body that is not an OTLP export response counts as a failed export and is retried like an error status.
- The backend's message is cut to 200 characters and escaped before it is logged or printed. The HTTP reason phrase of an error status is logged by the OpenTelemetry exporter unescaped.
- An incomplete last line is not an error: `--once` exports the records before it and exits 0, and following waits and warns. If the warning keeps repeating, follow Torn tail repair, then run a `--once` export again.
- Exit 1 with `DocketCorrupt`: run `docket verify` to find the line and reason. Records before it were exported. This is a docket integrity incident, not an exporter fault.
- Exit 1 with "not the file the checkpoint was written for", "replaced while following", "shorter than the checkpoint offset" or "differs from the checkpoint": the docket was replaced, truncated or rewritten after export. Treat it as a docket integrity incident and run `docket verify`. Once the docket is confirmed as the intended one, move the checkpoint aside and start the exporter; it exports every record again under the same span ids.
- Exit 1 with "held by another follower": another exporter uses this checkpoint. Stop one; two exporters on one checkpoint would send every record twice.
- Exit 1 on the checkpoint itself (mode, owner, fields): the checkpoint is 0600, owned by the exporter uid and version 1. Do not edit it; move it aside to export from the start.

## One client per writer

`DocketClient` takes an exclusive, non-blocking `flock` on `<state_dir>/<writer>.lock` (mode 0600, no symlinks) when it starts and holds it until `close()`. A second client for the same writer and state directory, in this or another process, fails at start with `writer_locked`; a closed client refuses appends with `closed`. The lock only covers one state directory. Two instances of one writer on separate state directories or hosts are not detected and race on `wrong_seq`, so run one instance per writer name and give each replica its own writer and key.

## Writer-side rollback detection

`DocketClient` stores its last acknowledged `seq` and hash in `<state_dir>/<writer>.head` (mode 0600, replaced atomically, fsynced). On every head fetch, and when the sink refuses an append with `wrong_seq` or `broken_prev`, the client raises `DocketRollback` if the sink's head `seq` is below the stored `seq`, or equals it with a different hash. Callers must treat it as a failed append.

It does not detect:

- removal of another writer's records, or of records this writer never saw acknowledged;
- a rollback that another instance of the same writer, using a different state directory, has already appended past the stored `seq`;
- anything after the state file is lost or rewritten. The client requires the state directory to be owned by its own uid and not writable by group or others; if the client runs as the sink uid, the sink uid can rewrite the state file too.

## Torn tail repair

A crash during a write can leave an incomplete final line. `verify_docket` reports it as `torn_tail`, and the sink refuses to start. That line was never acknowledged.

1. Stop the sink.
2. Run `verify_docket(docket_path, writers)` and confirm `reason == "torn_tail"`.
3. Run `repair(docket_path, side_path, writers)`, adding `reader_gid=<gid>` when the docket config sets `reader_group`. Under the docket lock it writes the incomplete line to `side_path` (created new, mode 0600), fsyncs it and its directory, truncates the docket to the last complete line, fsyncs the docket and its directory, and returns the verification of the result. It raises `DocketCorrupt` if any earlier line is invalid, and `DocketLocked` while a sink holds the docket.
4. Keep the side file for investigation and start the sink.

`repair` deletes the heads snapshot before it truncates, so the next start verifies every record and writes a new snapshot. It does not touch the snapshot when the docket verifies.

### snapshot_mismatch at start

The sink refuses to start with `snapshot_mismatch` when the docket and its snapshot disagree. With the sink stopped:

1. If the reason names the snapshot's mode, owner or group, check whether `reader_group` was just added or removed. If so, give the snapshot the docket's group and mode (see Readers) or move it aside, and start the sink.
2. Run `docket verify --snapshot <docket>.snapshot`. If a docket line fails, the docket itself is damaged: treat it as an integrity incident, and if the reason is `torn_tail` follow Torn tail repair, which also deletes the snapshot.
3. If every record verifies and the offset is past the end of the docket after a power loss, the disk lost bytes it had acknowledged (on macOS, see the `F_FULLFSYNC` note above). The records past the end were acknowledged to writers and are gone; treat it as an integrity incident.
4. If every record verifies and the snapshot differs anyway, the snapshot or the docket was rewritten. Treat it as an integrity incident.
5. Once the docket is confirmed as the intended one, move the snapshot aside, keep it for the investigation, and start the sink. It verifies every record and writes a new snapshot.
