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
- Connections: the peer uid is checked before a connection counts against `max_connections`. A connection is closed after `idle_timeout` without a frame, when a frame takes longer than `frame_timeout`, and at `max_lifetime`.
- On macOS, `os.fsync` does not issue `F_FULLFSYNC`, so the drive may still hold acknowledged data in its cache.

## Readers

A docket config with `reader_group` set lets members of that group read the docket without running as the sink uid. `agent-bailiff init docket --reader-group <gid>` gives the docket directory that group and mode 0750; the sink creates a new docket with that group and mode 0640 and refuses to start on any other mode or group. The sink uid must be a member of the group, or init and the first start fail. `config.json` stays 0600, so readers never read the sink config; they take writer pins from their own copies of the writers' public key records.

- Readers see every record: tools, resources, principals, tenants and argument digests, never the arguments themselves.
- Readers cannot append, truncate or replace the docket. Verification detects forged, altered, reordered or deleted records within each writer's chain; it cannot detect the sink uid truncating the newest records of a writer.
- Without `reader_group` the docket stays 0600 and only the sink uid and root can read it.

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
3. Run `repair(docket_path, side_path, writers)`. Under the docket lock it writes the incomplete line to `side_path` (created new, mode 0600), fsyncs it and its directory, truncates the docket to the last complete line, fsyncs the docket and its directory, and returns the verification of the result. It raises `DocketCorrupt` if any earlier line is invalid, and `DocketLocked` while a sink holds the docket.
4. Keep the side file for investigation and start the sink.
