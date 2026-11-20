# Docket

The docket is one file of newline-terminated signed records. Each record names its writer and carries a per-writer `seq` (starting at 1) and `prev`, the hash of that writer's previous record. One `DocketSink` process owns the file; writers append through `DocketClient` over a Unix socket.

## Trust model

- The sink uid, and root, are trusted for the docket file. Either can truncate, delete or replace it. Signatures stop them from forging or altering a writer's records without that writer's key; they do not stop removal of records.
- Append-only is enforced by the application: the sink opens the docket with `O_APPEND` and only appends. The file system does not enforce it.
- A writer is identified by its pinned Ed25519 key ids. The sink also accepts a connection only from a peer uid in `allowed_uids`; the client accepts a sink only if its peer uid equals the configured `sink_uid`.
- An entry means the operation was attempted or decided. It is not proof the operation happened or of its outcome; the outcome must come from reconciliation against the target system.

## Sink guarantees

- One sink per docket and per socket: the sink holds an exclusive non-blocking `flock` on the docket and on `<socket>.lock` for its lifetime. A second sink fails with `DocketLocked`.
- At start, under the lock, the sink checks the docket's parent directory (not a symlink, owned by the sink uid, not writable by group or others), the docket file (regular, owned by the sink uid, mode 0600; with `reader_group` set, mode 0640 and that group instead), verifies every record through the same descriptor it appends to, and fsyncs the parent directory. A failed directory fsync makes the sink refuse every append.
- An append is acknowledged only after the full line is written and fsynced. A failed write or fsync makes the sink refuse every later append until restart.
- On close the sink removes the socket path only if it is still the socket it bound.
- Connections: the peer uid is checked before a connection counts against `max_connections` (default 16). A connection past the limit gets the refusal `overloaded` and is closed; nothing is appended, so the writer knows the record was not written. Every allowed peer shares the limit: an allowed peer that holds 16 connections open makes the other writers' appends fail with `overloaded` until `idle_timeout` or `max_lifetime` closes them. The client does not retry: decide refuses the call as `docket_unavailable`, and the custodian does not release a credential. Only the uids in `allowed_uids` can do this. A connection is closed after `idle_timeout` without a frame, when a frame takes longer than `frame_timeout`, and at `max_lifetime`.
- On macOS, `os.fsync` does not issue `F_FULLFSYNC`, so the drive may still hold acknowledged data in its cache.

## Readers

A docket config with `reader_group` set lets members of that group read the docket without running as the sink uid. `agent-bailiff init docket --reader-group <gid>` gives the docket directory that group and mode 0750; the sink creates a new docket with that group and mode 0640 and refuses to start on any other mode or group. The sink uid must be a member of the group, or init and the first start fail. `config.json` stays 0600, so readers never read the sink config; they take writer pins from their own copies of the writers' public key records.

- Readers see every record: tools, resources, principals, tenants and argument digests, never the arguments themselves.
- Readers cannot append, truncate or replace the docket. Verification detects forged, altered, reordered or deleted records within each writer's chain; it cannot detect the sink uid truncating the newest records of a writer.
- Without `reader_group` the docket stays 0600 and only the sink uid and root can read it.
- To add `reader_group` to an existing docket: stop the sink, give the directory the group and mode 0750 and the docket the group and mode 0640, set `reader_group` in `config.json`, then start the sink. Removing it is the reverse, back to 0700 and 0600; the sink refuses to start on any mix.

## docket verify

```
agent-bailiff docket verify --docket PATH --pin decide.pub.json --pin custodian.pub.json [--trace ID] [--task ID] [--since UNIX_SECONDS] [--json]
```

Run it as a reader group member, the sink uid or root; it needs read access to the docket only, never the sink config. Each `--pin` is a writer's public key record; pass one per writer key, including retired keys whose records are still in the docket. Take pins from the writers' own key directories, not from a copy stored next to the docket, or whoever can replace the docket can replace the pins too.

- Every record is verified, from the first line to the last, whatever the filters. `--trace`, `--task` (the record's task root, or the `task` handle of a revocation) and `--since` (records at or after that Unix time, UTC) only choose which verified records are printed.
- Records print as tab-separated columns, with control and non-ASCII characters escaped; `--json` prints one JSON object per record, including the signed `token`, so a record can be passed on as written. The summary goes to stderr.
- A record with `performed` true is labelled `released, target outcome unknown`: the custodian released the credential, and the docket does not record what the target did with it.
- Exit 0 when every record verifies. Exit 1 when a line fails: the records before it are printed, and stderr names the line and reason. Exit 1 too for an unreadable docket or pin.
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
- A backend that rejects spans through an OTLP partial success (HTTP 200 with `rejected_spans` set) is not detected: the OpenTelemetry HTTP exporter reports success, the checkpoint moves past the rejected records, and no marker is sent. The skip path above covers only a backend that answers with an error status.
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
