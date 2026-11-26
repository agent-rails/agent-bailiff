# Docket

The docket is one file of newline-terminated signed records. Each record names its writer and carries a per-writer `seq` (starting at 1) and `prev`, the hash of that writer's previous record. One `DocketSink` process owns the file; writers append through `DocketClient` over a Unix socket.

## Trust model

- The sink uid, and root, are trusted for the docket file. Either can truncate, delete or replace it. Signatures stop them from forging or altering a writer's records without that writer's key; they do not stop removal of records.
- Append-only is enforced by the application: the sink opens the docket with `O_APPEND` and only appends. The file system does not enforce it.
- A writer is identified by its pinned Ed25519 key ids. The sink also accepts a connection only from a peer uid in `allowed_uids`; the client accepts a sink only if its peer uid equals the configured `sink_uid`.
- An entry means the operation was attempted or decided. It is not proof the operation happened or of its outcome; the outcome must come from reconciliation against the target system.

## Record types

A record is one of two types, named by its `typ`:

- `agent-bailiff/docket-entry/v1`: a decision, release, outcome or control action. Its fields do not change with grants.
- `agent-bailiff/docket-grant/v1`: a task root issued by `task issue`. Its body is `grant_id`, `at` and `root_token`, the issuer-signed task root as written to `task.json`, ASCII and 1 to 16,384 characters.

Both carry `writer`, `seq` and `prev` and share each writer's chain. A reader reads `typ` before verifying, only to choose the field set, then verifies the signature and decodes strictly for that type. Any other `typ` is refused as `wrong_typ`.

A writer is either an entry writer or a grant writer. The docket config's required `grant_writers` lists the grant writers by name, each also in `writers`; `[]` means none. Readers take a grant writer's public key record as `--grant-pin` (repeatable) on `docket verify`, `docket tasks`, `docket grants`, `docket export` and `docket archive`, and `init docket` and `init control` take it the same way. A writer pinned with both `--pin` and `--grant-pin` is refused ("writers pinned both as entry and grant writers"; in `docket tasks` and `docket grants`, "writer W is pinned as both --X and --grant-pin"). A grant writer appends only grants and an entry writer only entries: the sink refuses, and every reader rejects, a record of the other type as `wrong_record_type`. A reader without the grant writer's pin rejects its first grant as `unknown_kid`.

The issuer appends grants with its own docket-writer key, separate from its task root signing key. The writer key places the grant in the issuer's chain; the issuer's signature on `root_token` is what makes the grant authentic. The sink, the archiver, the exporter, the quickstart rule and `docket verify` without `--task` check only the shape of `root_token` and never decode it, so a change to the task root format does not change the docket format. `docket tasks`, `docket grants`, `docket verify --task` and control decode it. The exporter sends no span for a grant.

A grant is evidence, not enforcement: decide does not look for a grant before it allows a call. See THREAT_MODEL.md, Grants are evidence, not enforcement.

A release before grants refuses a grant. Upgrade every reader, and give each the issuer's docket-writer key as a grant pin, before the issuer writes its first grant; see [UPGRADE.md](UPGRADE.md), Docket grants.

### Grants from task issue

`task issue` appends one grant for each root it signs, so a task is in the docket before its agent makes a call. It takes the docket client settings as required flags: `--docket-socket`, `--docket-uid` (the sink's uid), `--docket-writer`, `--docket-key` and `--docket-state-dir` (the writer's own 0700 state directory). The docket key must not be the issuer key: `--docket-key must be the docket writer's own key, not the issuer key`.

The sink must be reachable: `task issue` runs on the sink host, as a uid in the sink's `allowed_uids`, with the docket socket. It holds an exclusive lock on the task directory; a second run fails with `another task issue is running in DIR; retry when it finishes`. Under the lock it:

1. if `task.json.pending` holds the task already in `task.json` (same root and decider id), an earlier run renamed it: for the same request (see Retrying task issue) it checks the pending root's signature, removes `task.json.pending`, fsyncs the directory and succeeds with that task and its `grant_id`, appending nothing; for another request it removes `task.json.pending` and goes on;
2. refuses an agent key that already has a task in `task.json`, without appending: `DIR/task.json already holds a task for this agent key; run proxy keygen for a new key and issue to that`;
3. writes `task.json.pending` (mode 0600, JSON with `version`, `grant_id`, `task_root` and `decider_id`) with a new `grant_id` to a temporary file, fsyncs it, renames it and fsyncs the directory, or reuses the one already there (see Retrying task issue);
4. writes the task file to a temporary file (mode 0644) and fsyncs it;
5. appends the grant and waits for the sink's acknowledgement;
6. renames the temporary file to `task.json`, fsyncs the directory, removes `task.json.pending` and fsyncs the directory again.

On success it prints `agent-bailiff task issue: wrote PATH, expires at EXPIRES_AT, grant_id GRANT_ID` to stderr and the task id to stdout. Every failure exits 1 with `agent-bailiff task issue refused: ` and one of:

- The sink refuses the append or cannot be reached: `docket refused the grant: <reason>; no grant recorded, no task file written`. `task.json.pending` is removed.
- No acknowledgement (`no_ack`, `bad_ack`, `write_failed`, `state_write_failed`): `docket did not acknowledge the grant (<reason>); grant may be recorded: grant_id <id>; check docket grants; revoke via control; or rerun the same command to finish from DIR/task.json.pending`. `task.json` is not written; `task.json.pending` is kept.
- A failure after the append was acknowledged: `<error>; grant recorded: grant_id <id>; task.json may be written; rerun the same command to finish from DIR/task.json.pending`.

### Retrying task issue

While `task.json.pending` exists, running the same command again (same decider id, issuer, tenant, principal, purpose, budget, max depth, scope, agent key and TTL) reuses its root and `grant_id`: the root signed by the new run is dropped, and the task expires when the pending root does. The retry appends the grant again, with a new `at`, so after a lost acknowledgement the docket can hold two grants of one root; `docket grants` shows the root once, with `grant_records` above 1. A refusal on a retry keeps `task.json.pending`: `docket refused the grant: <reason>; an earlier run may have recorded grant_id <id>; DIR/task.json.pending kept, rerun the same command to finish`.

A retry is refused when:

- the issuer key given to this run does not verify the pending root, as after a key rotation or with a file `task issue` did not write: `DIR/task.json.pending holds a root not signed by the current issuer key; grant may be recorded: grant_id <id>; check docket grants; remove it to issue`;
- the request differs: `DIR/task.json.pending holds an unfinished issue of grant_id <id> for another request; rerun that command to finish it, or check docket grants, revoke via control and remove it`;
- the pending root has expired: `DIR/task.json.pending holds an unfinished issue whose root expired at <expires_at>; grant may be recorded: grant_id <id>; check docket grants; remove it to issue`.

When `task.json.pending` holds the task already in `task.json` (step 1), the same request finishes even after the root has expired: the task is installed and its grant was appended before the rename, so finishing only removes `task.json.pending`. The `grant_id` it reports is the one in `task.json.pending`, not checked against the docket. If the issuer key given to this run does not verify that root, it refuses: `DIR/task.json already holds this root; DIR/task.json.pending is left over from an issue the current issuer key did not sign (grant_id <id>); check docket grants and remove it`. A `task.json.pending` with the root in `task.json` and another decider id is not finished; step 2 refuses it as a second task for the agent key.

A grant can still name a root that no agent holds: the operator gives up after a lost acknowledgement, or the process dies between the append and the rename. That root is valid until it expires. Find it with `docket grants`, where it shows every pair unused, and revoke it from its grant (see Revoking from a grant).

## Sink guarantees

- One sink per docket and per socket: the sink holds an exclusive non-blocking `flock` on `<docket>.lock` (mode 0600, no symlinks, beside the docket) and on `<socket>.lock` for its lifetime. A second sink, or `repair`, fails with `DocketLocked`. The lock is its own file so it does not move when the docket file is renamed.
- At start, under the lock, the sink checks the docket's parent directory (not a symlink, owned by the sink uid, not writable by group or others), the docket file (regular, owned by the sink uid, mode 0600; with `reader_group` set, mode 0640 and that group instead) and fsyncs the parent directory, then loads each writer's head through the same descriptor it appends to: from the heads snapshot when there is one, else by verifying every record (see Heads snapshot). A failed directory fsync makes the sink refuse every append.
- An append is acknowledged only after the full line is written and fsynced. A failed write or fsync makes the sink refuse every later append until restart.
- Free-space floor: before each write the sink reads the free space of the docket's file system (`fstatvfs`, blocks available to unprivileged users). If writing the record would leave less than `free_space_floor` bytes, the sink refuses it with `docket_full`. Nothing is written and the sink is not marked failed, so appends resume on their own once space returns. If the check itself fails, the append is refused with `space_check_failed`, also without marking the sink failed. Both are refusals of records that were not written, so decide refunds the refusal budget for them. While refusing for either reason, the sink logs at most one error per 60 s; the first append that passes the check again logs `docket appends resumed`. See Disk full.
- On close the sink removes the socket path only if it is still the socket it bound.
- Connections: the peer uid is checked before a connection counts against `max_connections` (default 16). A connection past the limit gets the refusal `overloaded` and is closed; nothing is appended, so the writer knows the record was not written. Every allowed peer shares the limit: an allowed peer that holds 16 connections open makes the other writers' appends fail with `overloaded` until `idle_timeout` or `max_lifetime` closes them. The client does not retry: decide refuses the call as `docket_unavailable`, and the custodian does not release a credential. Only the uids in `allowed_uids` can do this. A connection is closed after `idle_timeout` without a frame, when a frame takes longer than `frame_timeout`, and at `max_lifetime`.
- On macOS, `os.fsync` does not issue `F_FULLFSYNC`, so the drive may still hold acknowledged data in its cache.

## Heads snapshot

`<docket>.snapshot` lets the sink start without verifying every record. It is version 2 and holds the number of the docket segment it covers (1 for a docket that has never been cut), a byte offset that ends a verified line, the number of records before it, the SHA-256 of the bytes before it, each writer's anchor (the byte offset, `seq` and hash of the writer's last record before the offset) and the key ids of the records before it. It is canonical JSON of at most 4 MiB, owned by the sink uid with the docket's mode and group (0600, or 0640 and `reader_group`).

- Start with a snapshot: the sink reads it after taking the docket lock and checking the docket file. It refuses to start with `snapshot_mismatch` if the snapshot file is not a regular file with the right owner, mode and group or not a valid snapshot, the snapshot covers another segment than the active one, the offset is past the end of the docket, a key id it lists is not pinned, the SHA-256 of the bytes before the offset differs, or an anchor is not a whole line before the offset that decodes to that writer's record at that `seq` and hash. It then verifies every record after the offset, seeded with the anchors as heads; any failure there refuses start as it does without a snapshot.
- Start without a snapshot, or with a version 1 snapshot from an older release (logged as a warning): the sink verifies every record, fsyncs the docket and writes a version 2 snapshot. Neither the sink nor `repair` deletes the snapshot after that. An older release refuses a version 2 snapshot and does not start, so do not delete the snapshot by hand.
- `snapshot_every` (required in the docket config; `agent-bailiff init docket` writes 10000) is the number of acknowledged appends between snapshot writes. After that many, the sink writes a snapshot once the current reply is sent. `close()` writes one after the last connection ends. Each write first fsyncs the docket, so a snapshot never covers bytes that are not on disk; if that fsync fails, or the sink refuses appends after a failed write, no snapshot is written. The offset is the end of the last acknowledged record, never the file size. A snapshot is written to a temporary file (0600, fsynced), renamed over the old one and the directory fsynced. A failed write logs an error and keeps the old snapshot; any other error logs and stops snapshot writes until restart. A stale snapshot only makes the next start verify more records.
- Measured on one host: start with 10k records and a 2k-record tail took 0.34 s against 1.67 s for a full verify; a snapshot write took 0.20 ms (median).

### What start no longer checks

Start trusts the bytes before the snapshot offset if their SHA-256 matches. The sink uid, or root, can rewrite both the docket and the snapshot, and then the sink starts:

- Deleting or rewriting a record before the offset and writing a snapshot that matches the result is not detected at start. `docket verify` fails on the broken chain.
- A snapshot that omits a writer's anchor, or holds an older one, lets that writer start again at `seq` 1 or fork from an older head when its client has no state file, for example a fresh state directory. The sink accepts the fork; `docket verify` and the exporter refuse the docket from the forked line on.
- Restoring an older docket together with its older snapshot is a rollback: start accepts it. Writer-side rollback detection reports it to a writer whose state file is newer.
- Anchors and key ids come only from records signed by pinned keys, so a snapshot holds at most one anchor per configured writer; the 4 MiB cap covers the largest writer set a config can hold.

These were caught at every restart before; they are now caught only by `docket verify`. Run `docket verify --snapshot <docket>.snapshot` on a schedule, as a reader group member or the sink uid, and alert when it exits 1. The longest time a doctored prefix goes unnoticed is the interval between runs plus one run; pick the interval as the longest window you accept. Neither the sink nor the exporter re-verifies records before its own resume point.

## Segments

The sink appends to the active segment `<docket>`. Once an acknowledged append brings it to `segment_bytes` (required in the docket config; at least 64 MiB; `agent-bailiff init docket` writes 256 MiB), the sink seals it as `<docket>.seg-NNNNNNNNNNNN` after the current reply is sent. No append runs during a cut.

- Order: fsync the docket, write the snapshot of the next segment (offset 0), replace `<docket>.manifest` with one that lists the sealed segment (its size, SHA-256, first entry number, entry count, every writer's head and key ids), rename `<docket>` to the segment name, then create, fsync and rename `<docket>.new` to `<docket>`. Each rename is followed by a directory fsync. The manifest replace is the commit.
- A failure before the commit, including a manifest over its 4 MiB cap or `ENOSPC`, logs `aborted; the first append after 30 s retries it` and appends go on into the same segment. A failure at or after the commit, or a docket whose size is not what the sink wrote, makes the sink refuse every append until restart. Start finishes a committed cut and ignores the snapshot of one that did not commit.
- A sealed segment's heads are every writer's head, so a writer absent from a segment still resumes after its sealed `seq`.
- Segments are removed only after an archive receipt; see Removal. Once the manifest reaches its 4 MiB cap every cut aborts, and the sink retries the cut at most once every 30 s, each retry costing about three fsyncs more than an append that does not cut. The config refuses a `retained_bytes` whose manifest could exceed the cap.

### Removal

The docket config's `retained_bytes` (at least `2 * segment_bytes`; `agent-bailiff init docket` writes 16 GiB), `receipt_dir`, `archiver_uid` and `max_receipt_age` (3600 to 604800 s; init writes 86400) set retention, and `reader_group` is required. Every 60 s, and once at start, the sink removes the oldest sealed segment while the sealed segments plus the active one hold more than `retained_bytes`, up to 64 segments per pass. It removes a segment only when `<receipt_dir>/seg-NNNNNNNNNNNN.receipt` names this docket and matches the segment's manifest entry (size, SHA-256, end heads), and its `verified_at` is at most `max_receipt_age` old and at most 60 s in the future.

- Order: replace the manifest with one whose `base` records the removed segment (number, end entry, every writer's head), then unlink the segment file and fsync the directory. The manifest replace is the commit; `base` is the tombstone readers verify from.
- A receipt that is missing, unreadable, mismatched or too old keeps the segment and is logged. While the docket is over `retained_bytes`, each pass logs `over its ... byte cap; the oldest segment waits for a fresh archive receipt`. Alert on it: the archiver is behind or stopped, and the docket grows until the free-space floor.
- A failed manifest write keeps the segment and retries in 60 s. A failed directory fsync after the replace stops removals until restart. A failed unlink is retried before the next removal.
- Start finishes a committed removal: if the segment named by `base` is still present, the sink unlinks it only when its receipt names this docket and its size; otherwise it refuses to start with `segment_mismatch` ("left the manifest"). Any `<docket>.seg-*` not in the manifest refuses start too.
- The receipt directory is opened at start and must be owned by `archiver_uid` with group `reader_group` and mode 0750; the sink refuses to start otherwise. `agent-bailiff init docket --receipt-dir PATH --archiver-uid UID` writes both keys but does not create the directory; create it as the archiver uid before the first start.
- `archiver_uid` must not be the sink's own uid: the service refuses to start with "is the sink's own uid". A sink that could write receipts could vouch for its own removals. For the same reason the service refuses to start with euid 0 with "is running as root". It checks the euid only; also run the sink without a root real or saved uid and without `CAP_DAC_OVERRIDE`, `CAP_FOWNER` or `CAP_CHOWN`.
- Removal frees the segment on the host only. The records are then only in the archive; `docket verify` without `--archive` starts from `base`.
- Each removal rewrites and fsyncs the manifest on the sink's event loop, so appends wait for it. Measured on one host (`benchmarks/docket-removal-2026-11-22.json`, Apple silicon, APFS, one 64-removal pass each): from a 2064-entry manifest (502 KB) a manifest write took 11.3 ms p50 and 22.7 ms max, and the longest event-loop stall was 33.7 ms; from a 65-entry manifest, writes took 0.6 ms p50 and 1.1 ms max, and the longest stall was 1.6 ms. The init defaults (16 GiB `retained_bytes`, 256 MiB `segment_bytes`) keep about 64 entries. Config refuses a `retained_bytes` whose worst-case manifest exceeds 4 MiB, so a real manifest stays smaller than that. Not measured: larger manifests, concurrent appends, or other storage. macOS `fsync` does not flush the drive cache, so stalls on other disks can be longer. The writers' 5 s timeout applies to each socket operation.

### Archive

```
agent-bailiff docket archive --docket PATH --pin decide.pub.json --pin custodian.pub.json --grant-pin issuer-docket.pub.json --archive DIR --receipts RECEIPT_DIR --checkpoint DIR/checkpoint.json [--once] [--poll-interval 10] [--refresh-interval 900]
```

Run it as `archiver_uid`, a member of the reader group, in its own process with a 0700 checkpoint directory. For each sealed segment in order it reads the segment uncached, verifies every record from the previous segment's heads, writes `DIR/<docket_id>/seg-NNNNNNNNNNNN` (0640) and its canonical sidecar `.json` (0750 directory), fsyncs them, reads the copy back against the manifest entry, writes the receipt and then its checkpoint. Without `--once` it follows the manifest every `--poll-interval` seconds until SIGTERM or SIGINT.

- It refuses an archive directory on the docket's device (`is on the docket's device`). This means another file system, not another host: a second disk in the same machine passes. Put the archive on storage that a loss of the docket host does not take with it.
- Every `--refresh-interval` seconds (±10%) it rehashes each archived copy still in the manifest and rewrites its receipt with a new `verified_at`; a copy that is missing or differs has its receipt removed, so that segment is kept. Keep the interval well under `max_receipt_age`, or receipts expire between refreshes and removal stops. It also removes receipts of segments below `base`.
- Measured on one host (`benchmarks/docket-archiver-2026-11-21.json`, Apple silicon, APFS, 1 MiB segments): archiving ran at 5165 records/s against appends at 2833 records/s, both on one disk. The archiver bounds sustained ingest: if appends outrun it, removal stops and the docket grows to the floor. Alert on the cap log line above.
- One archiver per checkpoint: it holds `<checkpoint>.lock`, and a second exits 1.
- Any I/O error (a full or failing archive disk, an unreadable segment) exits 1; the archiver does not retry. Run it under a supervisor that restarts it and alerts on repeated exits. While it is down, receipts expire after `max_receipt_age` and removal stops.
- Neither archived copies nor their sidecars are ever pruned: the archive grows by every sealed segment. Size it for the retention you need and expire it with your own backup policy. Receipt files are pruned below `base`.
- Exit 1 with "is for docket": the checkpoint belongs to another docket. Exit 1 with `ArchiveMismatch` on a copy or sidecar: the archive was changed; treat it as an integrity incident. It also exits 1 with `ArchiveMismatch` ("is no longer the directory the archiver opened") before writing a receipt when the archive directory or `DIR/<docket_id>` was replaced at its path or removed since start, for example by a remount: check the mount, then restart it. Keep the archive directory's parent writable only by root or `archiver_uid`; that check runs just before the receipt write, not atomically with it.
- On Linux, uncached reads use `POSIX_FADV_DONTNEED`, which has no effect on NFS. Reading a docket on NFS fills the page cache.

### Archiver checkpoint loss

Without a checkpoint the archiver starts at segment 1. For segments already removed it re-derives each one's heads from its archived copy and checks it against the sidecar, then archives the retained segments again and rewrites their receipts. This needs the archive: if an archived copy below `base` is missing, it exits 1 with "was removed from the docket but has no archived copy", and nothing is removed until it runs again. If the archive is lost too, the removed records are gone; restore the archive from backup, or treat it as data loss.

### Upgrade and downgrade

1. Stop the sink and the archiver. Do not upgrade under a running sink.
2. Install the release and add `segment_bytes`, `reader_group`, `receipt_dir` and `archiver_uid` to the docket config, and create the receipt directory (see Removal): without them the config fails to load with `missing ...`. The quickstart bootstrap reports it with the same `docker compose down --volumes` hint as `free_space_floor`.
3. Start the sink. On a docket that has never been cut it reads a version 1 snapshot or none, verifies every record and writes a version 2 snapshot.

From then on `<docket>.snapshot` is always present and version 2. An older release refuses it with `snapshot_mismatch` and does not start, so there is no downgrade. An older release also refuses a docket config that sets `segment_bytes`, as an unknown key. Never delete or move the snapshot and remove the key to get an older release to start: it would read only the active segment and let every writer start again at `seq` 1. The current release then refuses to start on that fork with `wrong_seq`. Moving the snapshot aside (see snapshot_mismatch at start) is safe only when the current release starts next.

## Readers

A docket config with `reader_group` set lets members of that group read the docket without running as the sink uid. `agent-bailiff init docket --reader-group <gid>` gives the docket directory that group and mode 0750; the sink creates a new docket with that group and mode 0640 and refuses to start on any other mode or group. The sink uid must be a member of the group, or init and the first start fail. `config.json` stays 0600, so readers never read the sink config; they take writer pins from their own copies of the writers' public key records.

- Readers see every record: tools, resources, principals, tenants and argument digests, never the arguments themselves.
- Readers cannot append, truncate or replace the docket. `docket verify` detects forged, altered, reordered or deleted records within each writer's chain; it cannot detect the sink uid truncating the newest records of a writer. The sink's start checks less; see Heads snapshot.
- Without `reader_group` the docket stays 0600 and only the sink uid and root can read it.
- To add `reader_group` to an existing docket: stop the sink, give the directory the group and mode 0750 and the docket, `<docket>.snapshot`, `<docket>.manifest` and every `<docket>.seg-*` the group and mode 0640, set `reader_group` in `config.json`, then start the sink. Removing it is the reverse, back to 0700 and 0600; the sink refuses to start on any mix, and a snapshot left at the old mode refuses start with `snapshot_mismatch`.

## docket verify

```
agent-bailiff docket verify --docket PATH --pin decide.pub.json --pin custodian.pub.json --grant-pin issuer-docket.pub.json [--trace ID] [--task ID] [--since UNIX_SECONDS] [--json] [--snapshot PATH] [--archive DIR] [--receipts RECEIPT_DIR]
```

Run it as a reader group member, the sink uid or root; it needs read access to the docket only, never the sink config. Each `--pin` is a writer's public key record; pass one per writer key, including retired keys whose records are still in the docket. Take pins from the writers' own key directories, not from a copy stored next to the docket, or whoever can replace the docket can replace the pins too.

- Every record on the host is verified, whatever the filters: each sealed segment `<docket>.seg-NNNNNNNNNNNN` in the manifest `<docket>.manifest`, in order, then the active segment `<docket>`. Line numbers count across segments. When earlier segments were removed, verification starts from the heads the manifest's `base` records. Each sealed segment must also match its manifest entry: size, SHA-256, record count, end heads and key ids; stderr names the fields that differ, with reason `segment_mismatch`. A segment that ends with an incomplete line is a `segment_mismatch`, not a `torn_tail`, and Torn tail repair does not apply to it. Verify reads the manifest before and after opening each segment and opens it again if a cut happened meanwhile.
- Exit 1 with "cannot be opened; start the sink to finish a cut": a cut committed its manifest but the sink stopped before renaming the segment. Starting the sink finishes the cut. `--trace`, `--task` (the record's task root, the `task` handle of a revocation, or a grant whose root has that task id or binding) and `--since` (records at or after that Unix time, UTC) only choose which verified records are printed. A grant has no trace id, so `--trace` never prints one; `--task` prints the task's grant with its calls.
- Records print as tab-separated columns, with control and non-ASCII characters escaped; `--json` prints one JSON object per record, including the signed `token`, so a record can be passed on as written. The summary goes to stderr. A grant prints `grant` as its decision and `task grant` as its note, with no tool, resource or reason. Each JSON object carries `typ`, and a grant's object carries `grant` (`grant_id`, `at`, `root_token`) where an entry's carries `entry`.
- Pass the issuer's docket-writer key with `--grant-pin`, not `--pin`. Without it the first grant fails with `unknown_kid`; passed as `--pin`, with `wrong_record_type`.
- A record with `performed` true is labelled `released, target outcome unknown`: the custodian released the credential, and the docket does not record what the target did with it.
- Exit 0 when every record verifies. Exit 1 when a line fails: the records before it are printed, and stderr names the line and reason. Exit 1 too for an unreadable docket or pin.
- `--snapshot PATH` also cross-checks a heads snapshot. The snapshot must be owned by the docket's owner with mode 0600, or 0640 and the docket's group when the docket is 0640. The snapshot covers the active segment only. After every record verifies, the record count, the SHA-256 of the bytes before the snapshot offset, each writer's anchor and the key ids are rebuilt from the verified records and compared. Exit 1 if any differ, if the snapshot names another segment than the active one, if the offset is not the end of a verified line, or if the snapshot is missing or invalid; stderr names the fields that differ. On a match, stderr also gives the number of records after the snapshot. Exit 0 does not mean the snapshot is recent: a snapshot that stopped being refreshed still matches. Alert on that count if it keeps growing past `snapshot_every`. The records printed are the same with and without it.
- `--archive DIR` verifies the removed segments from the archive first, from line 1, then the retained ones, and checks that the last archived segment ends at the manifest's `base`. Each archived copy must match its sidecar. Line numbers are those of the whole docket.
- `--receipts RECEIPT_DIR` also checks each retained segment against its receipt, if it has one, and the `base` against the receipt of the removed segment. stderr gives `N retained segments match their receipts` and `the base matches removed segment N`; any difference exits 1.
- Verifying a docket while the sink is appending can report `torn_tail` for a line still being written. Run it again; if `torn_tail` stays, follow Torn tail repair.

## docket tasks

```
agent-bailiff docket tasks --docket PATH --decide-pin decide.pub.json --custodian-pin custodian.pub.json \
  --control-pin control.pub.json --grant-pin issuer-docket.pub.json --issuers issuers.json \
  [--pin effector.pub.json] [--archive DIR] [--json]
```

Run it like `docket verify`. It verifies every record first and prints nothing if any line fails. Then it prints one row per tenant and task id, from records whose `handles` name both and from grants, keyed by the tenant and task id in the grant's root: ROOT, principal, first and last time, decide allows, custodian releases and their refusals.

A record's `hop` is a field its writer signs, not a property of its key, so each hop the report reads is bound to the writers pinned for it: a `decide` record counts only from a `--decide-pin` writer, a `custodian` record only from a `--custodian-pin` writer, and a `control` revocation only from a `--control-pin` writer. Each flag is required and repeatable; repeat it for each key of a writer during rotation, or for each writer of the role. A record whose writer is not pinned for its hop opens no row and changes no count, and stderr says `N records claim a hop their writer is not pinned for; they are not counted`; rows are still printed and the exit code is 3, so a reading during an incident stays usable and a script can tell it is incomplete. A rotated decide key pinned only with `--pin` gives the same result for every record it signed. `--pin` pins writers that are verified but feed no row, such as the effector: effector refusals are not counted. A writer name under two of `--pin`, `--decide-pin`, `--custodian-pin`, `--control-pin` and `--grant-pin` is refused, `writer W is pinned as both --X and --Y`, exit 1, and so is one public key pinned under two writer names, `writers A and B are pinned with the same public key`, since a record signed by that key would verify as either writer.

PRINCIPAL and `record` come from one record: the task's latest decide record whose tenant matches the row and that names a principal. A custodian record never sets either, nor adds a root. A grant never sets the principal; a task listed only from grants has PRINCIPAL `-` until decide records a call. `docket grants --issuers FILE` shows the issuer-verified principal of each root. A verified grant's `at` counts toward first and last. An invalid grant's `at` sets them only while no trusted record of the task has been read; the first decide or custodian record, or verified grant, replaces it. A task that never made a call is listed from its grant, with zero counts. A grant whose root does not decode gives no row; stderr then says `N grants hold a task root that does not decode; their tasks are not listed`. Refusals before verification are not docketed, so they are not counted; see THREAT_MODEL.md, Unrecorded refusals.

STATE is `revoked` when a revocation recorded in the verified docket names the task, one of its roots or its tenant. Only revocations signed by a `--control-pin` writer count, so another pinned writer cannot mark a task. STATE is what control recorded, not the ledger's state, and a `--control-pin` key can record a revocation the ledger never applied:

- A link revocation blocks every chain through that link but does not mark the task.
- If control revoked in the ledger but its docket append failed (`ControlUnrecorded`), the task shows `-`.
- After segment removal, records in removed segments are read only with `--archive`; without it the listing starts at the manifest base, so older tasks and revocations are missing.

A root is named by its binding, a hash of the signed root, which includes its tenant, so a root revocation marks tasks of one tenant only.

### ROOT

`--issuers` is required: a 0600 JSON file holding the `issuers` section of decide's config (issuer id to `public_key`, `tenants`, `max_budget` and `max_depth`), the same file `docket grants` takes. A file that cannot be read, is not 0600, is not valid JSON or names no issuer is refused, exit 1. Each grant's root is checked against it as control and `docket grants` check it: the issuer is known, its signature verifies, and its allowance covers the root's tenant, principal, budget and depth. Every grant is checked, not one per root. ROOT is:

- `verified`: at least one grant of the task holds a root that passes. A forged copy beside it does not change this, but is counted in `invalid_grants` and exits 4.
- `invalid`: the task has grants and none passes. `root_reason` is the first failure: `unknown_issuer`, `bad_signature` or `issuer_not_allowed`. Either a grant writer recorded a root no allowed issuer signed, or `--issuers` differs from decide's: a key rotated in place, a tenant removed. Rotate an issuer key by adding a new issuer id, not by replacing `public_key`, or every older root of that issuer reads `bad_signature`.
- `unverified`: the task has no grant among the records read. Tasks issued before the issuer recorded grants, tasks whose grant is in a removed segment read without `--archive`, and rows seen only in decide or custodian records are `unverified`.

ROOT says only who signed the task root. It does not verify the counts, PRINCIPAL or STATE, which come from the writers pinned for each hop: a `verified` row can still carry allows, releases or a principal that a compromised decide or custodian key wrote. An invalid grant sets neither `granted`, `expires_at`, `record` nor `roots`, so a grant writer cannot hand out a record for a task its issuer did not sign, and a revocation naming only its root's binding does not mark the task.

`--json` rows also carry `root_status`, ROOT; `root_reason`, the first invalid reason, `null` unless ROOT is `invalid`; `invalid_grants`, the number of the task's grants whose root fails; `granted`, true when the verified docket holds a grant for the task from a pinned grant writer whose root verifies; `expires_at`, the latest `expires_at` of the task's verified roots, `null` without one; `record`, the signed token of the record PRINCIPAL comes from, or of the task's first verified grant when it has no such decide record, with its `record_line`, both `null` when the task has neither; and `principal_conflict`, true when the task's decide records name different principals. A conflict is among the records read: without `--archive`, records in removed segments are not compared. The table shows none of `granted`, `expires_at`, `principal_conflict`, `root_reason` and `invalid_grants`. A `record` is not always revocable: control accepts a decide record only if decide is among control's writer pins, and a grant only if its writer is among control's `grant_writers` and its root passes control's `issuers`; a task seen only in custodian records has no `record`. To revoke a task from it:

```
set -o pipefail
agent-bailiff docket tasks ... --issuers issuers.json --json \
  | jq -r 'select(.tenant == "acme" and .task == "TASK" and .root_status == "verified").record' > record
agent-bailiff control revoke --config CONTROL --actor NAME --level task --record record
```

Control verifies that record against its writer pins again, so a doctored row cannot revoke another task. `docket verify --task ID` shows the records of one task, its grant included.

`docket tasks` keeps one row per task, the roots and revocations it has seen and each row's `record` token. It counts them against a budget of 1 GiB: 1,024 bytes per row, 256 bytes per root and per revocation, plus the stored size of each kept string as `sys.getsizeof` reports it: 1, 2 or 4 bytes per character depending on the widest character, plus object overhead. Measured with tracemalloc on CPython 3.13, retained memory is 51 to 75% of the charge for short handles and up to 99% for 4,000-character strings of any width; a docket of one or two rows can exceed its charge by a few hundred bytes of fixed overhead. Printing adds a temporary copy of one row at a time, escaped: up to about 1.5 times the row's charge with `--json`, which writes the row in chunks, and about 3.8 times in the table. A signed line is at most 65,536 characters, so that copy stays within a few MB. A docket past the budget is refused, `agent-bailiff docket tasks refused: the report tracks at most 1073741824 bytes of task state and line N adds more`, exit 1, and no rows are printed. A pinned decide, custodian or grant writer key can fill the budget with rows of its own, so a compromised one can make the report refuse. Invalid grants are charged like verified ones.

Exit codes:

- 0: every `decide`, `custodian` and `control` record read came from a writer pinned for its hop. Records with any other hop, such as the effector's, are verified and not counted, and do not change the exit code.
- 1: a line fails verification, or an input is refused (`agent-bailiff docket tasks refused: ...`), such as a pin, the issuers file, an archive that does not match, or a docket past the budget. No rows are printed.
- 3: rows are printed, and N records claim a hop their writer is not pinned for. 3 is returned even when a grant is invalid, so 3 can hide 4; stderr still counts invalid grants.
- 4: rows are printed, and at least one grant is invalid or does not decode.

`unverified` rows alone exit 0. stderr lines come before the rows. The first is `N records verified, T tasks, V verified, U unverified, I invalid grants`, where I counts grants, not rows. When U is not 0 and `--archive` was not given, the next is `U tasks have no verified grant in the read segments; if segments were removed, pass --archive to read them`.

### Revoking from a grant

`control revoke` takes a grant at `--level task`, `root` or `tenant`; `--level link` is refused as `no_handle`, since a grant names no link. Control's config has two required keys for this: `grant_writers`, the writers in its `writers` that may only record grants, and `issuers`, in the format of decide's `issuers` (issuer id to `public_key`, `tenants`, `max_budget` and `max_depth`). `agent-bailiff init control` writes `"issuers": {}`, so every revoke from a grant is refused until the operator fills it in.

Control trusts a grant only after these checks, each refusing the revoke:

- the record verifies against control's writer pins, and its writer is a grant writer (`record_wrong_record_type` otherwise);
- the root in `root_token` decodes (`record_invalid_field`);
- its issuer is in `issuers` and has a key there (`root_unknown_issuer`);
- the issuer's signature on the root verifies (`root_bad_signature`);
- the issuer's allowance in `issuers` covers the root's tenant, principal, budget and depth (`root_not_allowed`).

So a grant writer cannot revoke a task of a tenant its issuer does not serve. The root's expiry is not checked: an expired root can be revoked. `task` revokes the root's tenant and task id, `root` its binding and `tenant` its tenant. The revocation entry's `trace_id` and `parent_entry` are both the grant's `grant_id`. `control suspend` refuses a grant as `record_not_suspendable`.

## docket grants

```
agent-bailiff docket grants --docket PATH --decide-pin decide.pub.json [--pin custodian.pub.json] \
  --grant-pin issuer-docket.pub.json --issuers ISSUERS.json [--archive DIR] [--json]
```

Only decide records from a `--decide-pin` writer count, as in `docket tasks`; `--decide-pin` is required and repeatable, and `--pin` pins writers that are verified but feed no root. A decide record from any other writer is not counted, and stderr says `N records claim a hop their writer is not pinned for; they are not counted` before the rows.

Run it like `docket verify`. It compares what each task root was granted with what decide allowed under it. `--issuers` is a JSON object in the format of decide's `issuers` section (issuer id to `public_key`, `tenants`, `max_budget` and `max_depth`), in a regular file with mode 0600 and one link, owned by the user running the command, in a directory that user owns and no group or other user can write. List every issuer whose roots are in the docket, including retired keys.

It prints one row per root, with a `status`:

- `granted`: a grant names the root and the root passes the checks below.
- `ungranted`: a decide record names the root in its handles, and no valid grant does. A root seen only in custodian records is not listed.
- `invalid_grant`: one row per grant whose root fails, with a `reason`: `malformed` (the root does not decode; tenant, task and root are then `null`), `unknown_issuer` (not in `--issuers`), `bad_signature`, or `issuer_not_allowed` (the issuer's allowance does not cover the root's tenant, principal, budget or depth). `detail` gives the text. If that root is used, it also gets an `ungranted` row.

A root is checked by signature and issuer allowance only, not expiry, so an expired root still reports.

The table has the columns TENANT, TASK, ROOT, STATUS, REASON, UNUSED (count), WILDCARDS (count), COST (`authorized_cost/budget`), TTL (`ttl_used/ttl`, `-` when unused) and FLAGS. `--json` prints one object per row with `status`, `reason`, `detail`, `tenant`, `task`, `root`, `issuer`, `grant_id`, `grant_line`, `grant_records`, `unused`, `wildcards`, `pairs_truncated`, `budget`, `authorized_cost`, `authorized_cost_exact`, `allows`, `ttl`, `ttl_used`, `ttl_flags`, `duplicate_roots` and `duplicate_roots_truncated`. Only decide's allows count as use. For a granted root:

- `unused`: per permission (`permission` is its index), the `tool` and `resource` pairs no allowed call used. A pair counts as used only within one permission.
- `wildcards`: for each tool or resource pattern ending in `*`, the names allowed calls used under it (`used`, at most 20 per pattern) and how many more there were (`truncated`).
- `authorized_cost`: the costs of decide's allows under the root, each `op_id` counted once, against the root's `budget`; `allows` counts them. It is what decide authorized, not what was spent: budget refunded later is not subtracted.
- `ttl` is `expires_at - issued_at`; `ttl_used` runs from `issued_at` to the last allowed call. `ttl_flags` holds `negative` when an allowed call came before `issued_at` and `after_expiry` when one came at or after `expires_at`; both mean the issuer's and decide's clocks disagree or the root was backdated.
- `grant_records`: the number of grants of the root; a retried `task issue` can record one root twice.
- `duplicate_roots`: the bindings of other granted roots with the same tenant and task id, the first 20 in sort order; `duplicate_roots_truncated` counts the rest. A task-level revoke covers all of them.

Per root it tracks at most 4,096 distinct pairs and 65,536 `op_id`s. Allows with a new pair past the first cap are counted in `pairs_truncated` and their pairs are not marked used, so `unused` can list a pair that was used. Past the second cap an `op_id` is no longer deduplicated, so `authorized_cost` and `allows` can count a repeated allow twice, and `authorized_cost_exact` is `false`. Across all roots it tracks at most 2,000,000 `op_id`s and pairs together; an allow past that exits 2 (below). An allow past a per-root cap does not count toward it. FLAGS in the table lists `negative`, `after_expiry`, `duplicate_roots`, `duplicate_roots_truncated`, `pairs_truncated` and `cost_inexact`.

stderr ends with `N records verified, R roots, I invalid grants`. Exit codes:

- 0: every record verifies, every `decide` record came from a `--decide-pin` writer, and no row is `invalid_grant`. Records with any other hop are verified and not counted.
- 1: every row is printed and at least one is `invalid_grant`.
- 3: every row is printed and N records claim a hop their writer is not pinned for. 3 is returned even when a row is `invalid_grant`.
- 2: a line fails verification (`agent-bailiff docket grants: line N fails verification: ...; no grants printed`), or an input is refused (`agent-bailiff docket grants refused: ...`), such as the issuers file, a pin, an archive that does not match, or a docket past the root cap or the `op_id` and pair budget. No rows are printed. Unlike `docket grants`, `docket verify` and `docket tasks` exit 1 on a line that fails, and `docket tasks` exits 4, not 1, on an invalid grant.

Limits:

- Advisory only. It sets no thresholds and revokes nothing.
- `ungranted` covers only roots that appear in a decide record. A root signed without a grant and never used is not seen.
- Without `--archive` it starts at the manifest base. After segment removal, a grant in a removed segment is then not read, and later calls under its root show as `ungranted`. Pass `--archive` to read removed segments too.
- It reads the docket once, in order, and keeps one bounded aggregate per root, not the records, so memory grows with the number of roots in the docket. It tracks at most 100,000 roots, counting granted, ungranted and `invalid_grant` rows; a docket with more exits 2 with `agent-bailiff docket grants refused: the report tracks at most 100000 roots and line N adds another`. A docket past the `op_id` and pair budget exits 2 with `agent-bailiff docket grants refused: the report tracks at most 2000000 op_ids and pairs and line N adds another`.
- Memory is bounded by those caps. Measured with tracemalloc on CPython 3.13: about 116 bytes per tracked `op_id` and about 225 bytes per pair whose tool and resource total about 50 characters (longer names cost more), so the budget holds about 0.5 GiB. Each granted root costs up to about 30 KiB for its aggregate with a 16 KiB root. Rows are built one at a time as they are printed, so at most one row is held at once, up to about 110 KiB for a scope with 1,024 tool and resource pairs. At 100,000 such roots the worst case is about 3.4 GiB.

## docket export

```
pip install 'agent-bailiff[otel]'
agent-bailiff docket export --docket PATH --pin decide.pub.json --pin custodian.pub.json --grant-pin issuer-docket.pub.json --checkpoint DIR/checkpoint.json --otlp http://collector:4318/v1/traces [--once] [--skip-line N] [--archive DIR]
```

Run it as a reader group member in its own process, with its own uid and a 0700 checkpoint directory. It reads the docket and pins the same way `docket verify` does, verifies every record, and sends each one as an OTLP/HTTP span. It is off the call path: decide and the custodian never wait for it, and a stopped or failing exporter changes no decision. Without `--once` it follows the docket until SIGTERM or SIGINT.

- Spans are a view, not evidence. The docket and `docket verify` are the record; a collector or trace backend can drop, alter or invent spans without a writer key.
- Grants are verified and not sent; the checkpoint moves past them like past an exported record.
- The span id is the first 8 bytes of sha256 over a fixed tag and the entry id, and the parent is derived the same way from `parent_entry`. Re-exporting a record sends the same ids. Two entry ids sharing an 8-byte prefix would collide; with random 128-bit entry ids this is negligible.
- Attributes are the record's fields under `bailiff.*`, the docket line, writer, seq, kid and record hash, and `gen_ai.tool.name`, `gen_ai.operation.name` and `error.type` from the [GenAI semantic conventions at 622b2b6](https://github.com/open-telemetry/semantic-conventions-genai/blob/622b2b6073b15e5ed886c3c12a65a892b9cd5c70/docs/gen-ai/mcp.md), whose status is Development and may change. A refusal is an error span with its reason. A release carries `bailiff.note` = `released, target outcome unknown`. Arguments are never exported; the docket holds only their digest.
- The span backend then holds what docket readers see: principals, tenants, tools and resources. Restrict access to it as you restrict the reader group.
- The resource `service.name` is `agent-bailiff-<writer>`. The span ends at the record's `at` (whole seconds) and starts `latency_ms` earlier.

### Trace ids

The trace id comes from the caller's `traceparent` and is not authenticated: an agent can choose any trace id, including one already used by another agent's calls, so grouping spans by trace says nothing about who made them. Use the signed `bailiff.principal`, `bailiff.tenant` and `bailiff.task_root` attributes, or `docket verify`, to attribute a call. The gateway adapter treats an all-zero trace or parent id as absent. A record whose trace id is not 32 lowercase hex characters, or is all zeros, gets a trace id derived from its entry id, `bailiff.trace_id_mapped` is set, and the raw value is not exported, so a caller cannot place text of its choosing in the trace id field.

### Delivery and checkpoint

- At least once. After each batch the backend accepts, the exporter writes the checkpoint (mode 0600, written to a temporary file, fsynced, renamed, directory fsynced). A crash between acceptance and the checkpoint write sends that batch again on restart. Backends that do not deduplicate by span id may keep both copies.
- The checkpoint holds the segment it last exported from, the byte offset in that segment, the count of exported records, each writer's head, the hash of the segment's first record and the hash and offset of the last exported one. Each pass the exporter reads the manifest, opens the segment, and starts again if the manifest generation changed meanwhile, so a cut never yields a gap or a duplicate. It refuses a segment shorter than the offset, or whose first or last exported record differs, then verifies forward from the saved heads. A sealed segment must end at the size and heads its manifest entry records. Sealed segment files are closed at the end of each pass. A version 1 checkpoint is migrated in place on first start: it must name the inode of `<docket>` or `<docket>.seg-000000000001`. It does not read the exported records between the first and last again, so a change to them by the sink uid or root is not detected on resume; `docket verify` checks every record. While following, it refuses a docket path that now names another file.
- `--archive DIR` reads a segment from the archive once it is removed from the host. Each copy must match its sidecar and size. Without a checkpoint it starts at line 1 of the archive; without `--archive` a new checkpoint starts at the first retained segment.
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
- Exit 1 with "was removed": the checkpoint names a segment no longer on the host; the exporter fell behind removal. Start it again with `--archive DIR` as a user that can read the archive; it resumes from the checkpoint. Exit 1 with `ArchiveMismatch`: the archived copy or sidecar differs; treat it as an integrity incident.
- Exit 1 with "not the file the checkpoint was written for", "replaced while following", "shorter than the checkpoint offset" or "differs from the checkpoint": the docket was replaced, truncated or rewritten after export. Treat it as a docket integrity incident and run `docket verify`. Once the docket is confirmed as the intended one, move the checkpoint aside and start the exporter; it exports every record again under the same span ids.
- Exit 1 with "held by another follower": another exporter uses this checkpoint. Stop one; two exporters on one checkpoint would send every record twice.
- Exit 1 on the checkpoint itself (mode, owner, fields): the checkpoint is 0600, owned by the exporter uid and version 2. Do not edit it; move it aside to export from the start.

## One client per writer

`DocketClient` takes an exclusive, non-blocking `flock` on `<state_dir>/<writer>.lock` (mode 0600, no symlinks) when it starts and holds it until `close()`. A second client for the same writer and state directory, in this or another process, fails at start with `writer_locked`; a closed client refuses appends with `closed`. The lock only covers one state directory. Two instances of one writer on separate state directories or hosts are not detected and race on `wrong_seq`, so run one instance per writer name and give each replica its own writer and key.

## Writer-side rollback detection

`DocketClient` stores its last acknowledged `seq` and hash in `<state_dir>/<writer>.head` (mode 0600, replaced atomically, fsynced). On every head fetch, and when the sink refuses an append with `wrong_seq` or `broken_prev`, the client raises `DocketRollback` if the sink's head `seq` is below the stored `seq`, or equals it with a different hash. Callers must treat it as a failed append.

It does not detect:

- removal of another writer's records, or of records this writer never saw acknowledged;
- a rollback that another instance of the same writer, using a different state directory, has already appended past the stored `seq`;
- anything after the state file is lost or rewritten. The client requires the state directory to be owned by its own uid and not writable by group or others; if the client runs as the sink uid, the sink uid can rewrite the state file too.

## Latency

Three different numbers exist. Each answers a different question, and each was measured on one host only.

- Per-hop `latency_ms` on a docket entry: milliseconds from the start of `Decider.check` or `Custodian.release` to the moment the entry is built, on a monotonic clock. Decide's allow entries and the refuse entries it records, and the custodian's release entries (both credential tiers) and the refuse entries it records, carry it. It is not the time at the gateway processor: the clock starts inside `check` or `release`, so request parsing before that call and transport after it are excluded. Each entry is stamped when it is built, before its own docket append, so that append is not included. Outcome, reconcile, canary-alert, credential-echo alert and the custodian's `response_*` refuse entries carry none (reconcile is timer-driven and has no request; a response check is not timed). The field is optional and non-negative in the signed format and the OTLP exporter uses it as the span start. It reveals how long a check took, so docket and OTLP readers must be audit operators only; no agent-callable tool returns docket records.
- `added_p50_ms` and `added_p99_ms` in `benchmarks/quickstart-<date>.json`: for each client level, the load benchmark's p50 and p99 through the gateway minus the same percentile for the same calls sent straight to the upstream (`baseline_*`). The baseline runs first, so the upstream is warmer for it than for the proxied run, and a gitea warm-up effect is not separated out. Each level has 20 calls per client, so the p99 of the small levels is close to the slowest call; the difference of two noisy p99 values can be negative.
- `benchmarks/proxy-<date>.json`: what an agent sees. A harness in the agent container plays an MCP host against `agent-bailiff proxy run` over stdio (initialize, tools/list, then `list_issues` calls, a scripted share out of scope) and times each request to its response line. `first_call_ms` is reported apart from `p50_ms` and `p99_ms`, which cover the remaining calls. `refusals_per_100_calls` counts proxy refusals in the run. `setup_retries` is read from the proxy's close log; tool calls are never retried, so `retries_per_call` is setup retries divided by calls and is not a count of retried tool calls.

Measured on one host (arm64 macOS, Docker 29.6.2, quickstart stack on gitea-mcp, 2026-11-24, one run each):

- Load benchmark, added p50 over direct upstream: 23.0 ms at 1 client, 36.1 ms at 4, 102.8 ms at 16, 144.7 ms at 32. Added p99: 80.4 ms, -45.3 ms, 551.2 ms, 747.9 ms. The negative value is the direct baseline's p99 (250.6 ms) exceeding the proxied p99 (205.3 ms) in that sample; it shows the noise, not a speedup. Throughput peaked at 60.0 calls/s at 4 clients.
- Perceived latency, 60 sequential calls, 20 percent out of scope: p50 25.6 ms and p99 152.4 ms over the 59 warm calls (p99 of 59 samples is near the slowest call), first call 45.0 ms, in-scope p50 26.5 ms, out-of-scope p50 6.9 ms, initialize 523.8 ms, tools/list 33.9 ms, 0 setup retries, 20.0 refusals per 100 calls.

Limits of these numbers:

- One run, one host, no repeats, so there is no variance estimate. Other hardware, a remote upstream or a loaded docket will differ.
- The perceived-latency run is sequential and short. A session is capped at 60 releases per minute by the custodian's `rate_limit`, so the harness refuses a schedule with more in-scope calls than that.
- A task records at most 16 refusals per 60 s window; later refusals are still refused but not docketed, which can make a refused call faster than one that is recorded.
- Not measured: concurrent agents through the proxy, other tools, a cold gateway, or credentials other than the quickstart's.

Re-run with `AGENT_BAILIFF_TEST_QUICKSTART=1 AGENT_BAILIFF_TEST_QUICKSTART_LOAD=1` for the load benchmark and `AGENT_BAILIFF_TEST_QUICKSTART=1 AGENT_BAILIFF_TEST_QUICKSTART_PROXY=1` for the proxy benchmark (`tests/test_quickstart_load.py`, `tests/test_quickstart_proxy.py`).

## Disk full

`free_space_floor` (required in the docket config; at least two frames, 131074 bytes; `agent-bailiff init docket` writes 256 MiB) keeps the sink from filling its file system. Below it, decide refuses calls as `docket_unavailable` and the custodian does not release credentials: without disk there is no record, so there is no call. When the floor is reached first, appends resume once space returns, with no restart.

- The floor is a threshold checked before each write, not a guarantee. A write can still fail with `ENOSPC` when another process takes the space between the check and the write, or when a quota or reserved blocks limit the sink below what `f_bavail` reports. That failure is `write_failed`, and the sink refuses appends with `sink_failed` until restart, as before.
- At start the sink refuses to start (exit 1) if the file system's total size is not larger than the floor plus one frame: such a sink could never accept an append. It checks total size, not free space, so a sink restarted while the disk is full still starts and resumes once space returns.
- Size the floor to cover what else writes to the same file system until an operator responds: the snapshot (at most 4 MiB), the manifest (at most 4 MiB), the temporary copy of each written beside it during a cut (up to 4 MiB more each), logs and anything sharing the volume. The floor is not a reserve for the docket; the sink stops writing at it.
- Alert on the `docket refusing appends` log line and on free space approaching the floor. Free space; no restart is needed, appends resume on the next request.
- Upgrade: a docket config without `free_space_floor` fails to load with `missing free_space_floor`; add the key. The quickstart bootstrap reports it with a hint to run `docker compose down --volumes`, which also deletes the quickstart docket.
- The floor does not remove records. Removal does, once segments are archived; a stopped archiver lets the docket grow until the floor (see Removal).
- Measured on one host (`benchmarks/docket-floor-2026-11-21.json`, Apple silicon, APFS): `fstatvfs` took 0.81 µs per call against an append p50 of about 1 ms. Append p50 with the check was 1.03 ms and 0.95 ms with a constant result; one run each cannot separate that gap from noise.

## Torn tail repair

A crash during a write can leave an incomplete final line of the active segment. `docket verify` reports it as `torn_tail`, and the sink refuses to start. That line was never acknowledged.

1. Stop the sink.
2. Run `docket verify --docket <docket> --pin ...` and confirm it fails with `torn_tail` on the last line.
3. Run `repair(docket_path, side_path, writers)`, adding `reader_gid=<gid>` when the docket config sets `reader_group`. Under the docket lock it writes the incomplete line to `side_path` (created new, mode 0600), fsyncs it and its directory, truncates the docket to the last complete line, fsyncs the docket and its directory, and returns the verification of the result. It raises `DocketCorrupt` if any earlier line is invalid, and `DocketLocked` while a sink holds the docket.
4. Keep the side file for investigation and start the sink.

`repair` does not finish a removal. If a removal committed and the sink stopped before unlinking, `repair` refuses with `segment_mismatch` ("left the manifest"). Start the sink first: it finishes the removal before it checks the active segment, then refuses with `torn_tail`, and `repair` runs.

Before it truncates, `repair` replaces the heads snapshot with one that ends at the last complete line, with the docket's mode and group. A crash between the two leaves that snapshot and the torn tail, and running `repair` again with a new side path finishes. It does not touch the snapshot when the docket verifies.

### snapshot_mismatch at start

The sink refuses to start with `snapshot_mismatch` when the docket and its snapshot disagree. With the sink stopped:

1. If the reason names the snapshot's mode, owner or group, check whether `reader_group` was just added or removed. If so, give the snapshot the docket's group and mode (see Readers) or move it aside, and start the sink.
2. Run `docket verify --snapshot <docket>.snapshot`. If a docket line fails, the docket itself is damaged: treat it as an integrity incident, and if the reason is `torn_tail` follow Torn tail repair, which also replaces the snapshot.
3. If every record verifies and the offset is past the end of the docket after a power loss, the disk lost bytes it had acknowledged (on macOS, see the `F_FULLFSYNC` note above). The records past the end were acknowledged to writers and are gone; treat it as an integrity incident.
4. If every record verifies and the snapshot differs anyway, the snapshot or the docket was rewritten. Treat it as an integrity incident.
5. Once the docket is confirmed as the intended one, move the snapshot aside, keep it for the investigation, and start the sink of the current release. It verifies every record and writes a new snapshot.
