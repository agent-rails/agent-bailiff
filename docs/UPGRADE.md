# Upgrading

- [Access log](#access-log)
- [Credential checks](#credential-checks)
- [Permission scopes](#permission-scopes)
- [Docket grants](#docket-grants)

## Access log

check-config now requires the gateway config to carry, at the top level:

```json
"frontendPolicies": {"accessLog": {"remove": ["mcp.error.message"]}}
```

agentgateway logs the text of an upstream JSON-RPC error as `mcp.error.message`, and that text can echo a released credential. A config without it, with any other `frontendPolicies` or access-log setting, with `config.logging` keys other than `level` and `format`, or with `fields` under `config.tracing` or `config.metrics`, fails check-config. Where startup runs check-config first, as the quickstart's `gateway-check` and `examples/live-run` do, the gateway then does not start; agentgateway itself starts without the block, so a deployment that skips check-config keeps logging the error text. Add the block to your `gateway.json` before upgrading; the quickstart template and `examples/live-run` already have it. To roll back, an earlier release refuses the unknown `frontendPolicies` key, so remove the block.

## Credential checks

The credential checks release checks each credential when it is stored and when it is released (D22 in [DECISIONS.md](DECISIONS.md)). `put-credential` refuses a value that is not printable ASCII without leading or trailing space or tab, with no override. It also refuses a valid header value that echo redaction cannot cover: a Basic token that is not base64 of a UTF-8 `user:password`, or a value with a form under 12 characters that echo redaction would match (D20). `--accept-unredactable` stores only such a valid header value, with an `unredactable` exception, and logs a warning.

### Stored credentials

The custodian and `put-credential` add a nullable `exception` column the first time they open an existing store; stored rows keep decrypting. A stored credential that fails the check has no exception, so the custodian now refuses it as `credential_unredactable`, the agent sees `release_refused`, and the custodian logs `stored credential '<id>' for target '<target>' cannot be redacted from results and has no accepted exception: <problem>`. The earlier release released it, with the warning `released credential, or its decoded basic password, is shorter than 12 characters and cannot be redacted from results` for a short form and no warning for a Basic token that does not decode. That warning does not name the credential. A stored value that is not a valid header value is refused as `credential_unavailable`, as the earlier release did, and `--accept-unredactable` does not cover it. Before restarting the custodian, run `check-credentials` as the custodian's uid. It reads every stored credential and prints one JSON line, with `tenant`, `credential_id`, `target` and `problem`, for each credential the custodian would refuse to release, never the credential itself, and exits 1 if there is any:

```console
$ agent-bailiff custodian check-credentials --config /var/lib/bailiff/custodian/config.json
{"credential_id": "notes-token", "problem": "credential cannot be redacted from results and has no accepted exception: ...", "target": "notes", "tenant": "quickstart"}
agent-bailiff check-credentials: 1 of 3 would be refused at release
```

Store each listed credential again with the new `put-credential`; the ones it refuses need a longer credential or `--accept-unredactable`. Run the check again until it exits 0.

### Rollback

An earlier release ignores the `exception` column. It cannot decrypt a credential stored with an exception, because the exception is part of its encryption context, and refuses it as `credential_unavailable`; store it again with the earlier `put-credential`. That leaves the column set, so after upgrading again the custodian refuses the credential as `credential_unavailable` until it is stored again with the new `put-credential`.

## Permission scopes

The permission scopes release moves task scopes to agent-warrant 0.4.0's permission list (D21 in [DECISIONS.md](DECISIONS.md)): a call is allowed only when one permission covers both its tool and its resource. A v1 scope, with `tools`, `resources` and `max_cost_per_call` at the top level, is read as one permission and accepted only on a root issued before `scope_v1_cutoff`.

### Choose the cutoff

`scope_v1_cutoff` is a Unix time in seconds, in both decide's and the custodian's `config.json`. A v1 root issued at or after it is refused as `chain_invalid`, with the log reason `task root: scope_v1_expired`. `init` writes 0, which accepts no v1 root.

- To keep tasks issued before the upgrade working, set the cutoff to the time you upgrade the issuers. Those tasks run to their expiry, at most 86,400 s later.
- To end every v1 task at once, leave it at 0. Every v1 task is then refused from the moment decide restarts, and its agent needs a new task.

Add the key to both files before restarting on the new release. Without it the service refuses to start with `decide: missing scope_v1_cutoff` or `custodian: missing scope_v1_cutoff`; the default in `init` applies only to new configs. Set the same value in both files. Each service logs its effective cutoff at startup:

```
decide <decider_id> effective scope_v1_cutoff=<n>
custodian <custodian_id> effective scope_v1_cutoff=<n>
```

The two are not checked against each other. If the custodian's cutoff is earlier than decide's, decide allows and reserves a v1 call that the custodian then refuses: the agent sees `release_refused`, the custodian logs `custodian refused the chain of a verified clearance: task root: scope_v1_expired` and records `chain_refused`. If decide's is earlier, decide refuses the call first. Compare the two startup lines after every restart.

### Rollout order

1. Docket sink, archiver, exporter and `docket verify` hosts. The docket entry format is unchanged, so these read records from either version and their order is not load-bearing; upgrading them first puts every reader on the new release before the writers.
2. Decide and the custodian together, with the same `scope_v1_cutoff`. Both now verify v1 and v2 chains.
3. Clients that delegate. `delegate` takes a v2 scope, and a 0.3.0 client cannot read a v2 root, so a delegating client must be upgraded before its holder receives a v2 task.
4. Issuers. From here `task issue` writes v2 scopes only, so nothing on the path may still run 0.3.0.

### Canary

After step 2, before step 4, run one v1 chain and one v2 chain through the gateway to both services. Issue the v1 task with an issuer still on the previous release, and the v2 task with `task issue` from the new release on one canary host, under an issuer key decide already trusts:

- A v1 task issued before the cutoff makes one allowed call. The docket shows decide's `allow` and the custodian's `release`, and decide logs `scope_v1_accepted` with the task's root binding.
- A v2 task with two permissions makes one call each permission covers and one that pairs the tool of one with the resource of the other. The first two are released; the third is refused as `out_of_scope`.

A `chain_refused` entry from the custodian on the v1 call means the custodian refused a chain decide accepted. Read the custodian's log for the reason: `task root: scope_v1_expired` means the cutoffs differ; revocation, expiry or a stale proof give other reasons.

### Draining v1

Decide logs each v1 root it accepts as a `scope_v1_accepted` warning with tenant, task, root binding, `issued_at` and cutoff. The docket does not record the scope version; entries before the cutoff plus 86,400 s are the only v1 candidates. After that time no v1 root is valid. Until then, an issuer key can still mint a v1 root, backdated before the cutoff, with free pairing; set the cutoff back to 0 once the drain ends to close that.

### Task file size

The task file holds at most 4,096 bytes. agent-warrant allows a scope of up to 16 permissions and 64 entries, which does not fit; `task issue` refuses a scope whose task file would be larger, before signing. Measured task files:

| Scope | Task file |
| --- | --- |
| One permission, one tool, one resource | 714 B |
| Two permissions, two tools each, 10 repositories each (20 in all) | 1,670 B |
| 16 permissions, one tool and one resource each | 2,738 B |

### Rollback

Once any v2 task is issued, going back to the previous release, on agent-warrant 0.3.0, is an outage for v2 tasks: 0.3.0 refuses to decode a v2 root, so the previous decide and custodian refuse every v2 call, the previous proxy cannot load a v2 `task.json`, its `task issue` refuses to write over one until it is removed, and its client cannot delegate from one. To roll back, revert every component in the reverse of the rollout order, remove `scope_v1_cutoff` from decide's and the custodian's `config.json` (the previous release refuses it as `unknown scope_v1_cutoff`), remove each v2 `task.json`, and reissue the tasks with v1 scopes. Tasks issued with v1 scopes before the upgrade keep working on 0.3.0.

## Docket report roles

`docket tasks` binds each hop it reads to role pins. It takes `--decide-pin`, `--custodian-pin` and `--control-pin`, all required; `--pin` is optional and pins writers that are verified but feed no row. Replace `--pin decide.pub.json --pin custodian.pub.json` with `--decide-pin decide.pub.json --custodian-pin custodian.pub.json`. An earlier command line fails with `the following arguments are required: --decide-pin, --custodian-pin`.

`docket grants` takes `--decide-pin`, required; replace `--pin decide.pub.json` with `--decide-pin decide.pub.json`, and `--pin` for other writers is optional. It counts allows only from a `--decide-pin` writer, a root seen only in custodian records is no longer listed as `ungranted`, and it exits 3 with rows printed when a record claims a hop its writer is not pinned for, ahead of 1 for an invalid grant.

`docket tasks` rows change: a grant no longer sets PRINCIPAL, so a task listed only from grants shows `-` until decide records a call; `record` is the latest decide record that names a principal; effector refusals are not counted; `--json` rows add `principal_conflict`. A record whose writer is not pinned for its hop is not counted, and the command exits 3 with rows printed. Scripts that treat any non-zero exit as no output must accept 3.

`docket tasks` also requires `--issuers FILE`, the 0600 `issuers` section of decide's config, as `docket grants` takes it; an earlier command line fails with `the following arguments are required: --issuers`. The table gains a ROOT column after TASK, and `--json` rows add `root_status`, `root_reason` and `invalid_grants`. A grant whose root fails the issuers no longer sets `granted`, `expires_at` or `record`. The command exits 4 with rows printed when a grant is invalid or does not decode (before, an undecodable grant exited 0); 3 still takes precedence. A revoke pipeline should select `root_status == "verified"` and run under `set -o pipefail`. In the quickstart, `docker compose up` adds `reader-init`, which writes the reader's copy to `/var/lib/bailiff/reader/issuers.json` in a new `reader-data` volume.

### Rollback

The docket format does not change, so an earlier release reads the same docket; the quickstart's `reader-data` volume is unused by it. Its `docket tasks` and `docket grants` count a record from any pinned writer under the hop the record claims, so a pinned custodian or effector key can again change a task's principal, counts and `record`, and a root's allows and `authorized_cost`. Its `docket tasks` refuses `--issuers` as an unrecognized argument, lists a task as `granted` with a root no allowed issuer signed, and has no ROOT column, so drop `--issuers` and the `root_status` filter from revoke pipelines before rolling back.

## Docket grants

The docket grants release adds the grant record, `agent-bailiff/docket-grant/v1` (see [DOCKET.md](DOCKET.md), Record types). `task issue` appends one for each root it signs, with a docket-writer key of its own. A reader on an earlier release refuses a grant, so every reader is upgraded before the issuer writes one.

### Precondition

`task issue` reaches the sink over its Unix socket. The issuer runs on the sink host, as a uid in the sink's `allowed_uids`, with the docket socket. On Kubernetes that means the issuer runs beside the sink with the socket volume mounted and its uid admitted; this repository ships no Kubernetes manifest for the sink, and that setup is untested. There is no remote transport to the sink: an issuer on another host cannot record grants, so it cannot issue from the docket grants release on.

### Config keys

The release adds required config keys. Without them a config fails to load:

- Docket config: `grant_writers`, a list of writer names, each also in `writers`. Add `"grant_writers": []` to an existing config; without it the sink refuses to start with `docket: missing grant_writers`.
- Control config: `grant_writers` in the same format, and `issuers`, in the format of decide's `issuers`. Add `"grant_writers": []` and `"issuers": {}` to an existing config; without them control refuses with `control: missing grant_writers, issuers`. With `"issuers": {}` every revoke from a grant is refused as `root_unknown_issuer`.

`init docket` and `init control` write both keys for a new config, taking grant writers from `--grant-pin`; `init control` writes `"issuers": {}`.

### Rollout order

1. Readers: the docket sink, the archiver, the exporter, the quickstart rule, control, and every host that runs `docket verify`, `docket tasks` or `docket grants`. As you upgrade each, add the issuer's docket-writer public key as a grant writer, never as an entry writer: to the sink's `writers` and `grant_writers`, as `--grant-pin` on every reader command, and to control's `writers` and `grant_writers`. Add the issuer's public key and allowance to control's `issuers`, copied from decide's.
2. Issuer: give it a docket-writer key, separate from its task root signing key, and a state directory owned by its uid with mode 0700, and add its uid to the sink's `allowed_uids`. Then upgrade `task issue` and pass `--docket-socket`, `--docket-uid`, `--docket-writer`, `--docket-key` and `--docket-state-dir`.

A reader that lacks the issuer's grant pin stops at the first grant with `unknown_kid`; one that pins it as an entry writer stops with `wrong_record_type`. `docket verify` and `docket tasks` exit 1, `docket grants` exits 2, and the archiver and the exporter exit 1. With the archiver stopped, receipts expire and removal stops. A sink restarted without the pin over a docket that holds a grant refuses to start.

If the issuer is upgraded before the sink, or the sink does not pin it as a grant writer, the sink refuses the grant and `task issue` exits with `docket refused the grant: <reason>; no grant recorded, no task file written`; no task is issued. Fix the sink and issue again. Tasks issued by an earlier issuer during the rollout have no grant and show as `ungranted` in `docket grants` once used.

### Canary

After step 2, issue one task on one issuer host and make no call with it. `docket grants --issuers FILE` shows its root as `granted` with every pair unused, and `docket tasks --json` lists the task with `granted` true. Revoke it from its grant with `control revoke --level task`; `docket tasks` then shows it `revoked`.

### Rollback

The issuer can go back: an earlier `task issue` writes no grant, readers keep reading the grants already written, and tasks it issues show as `ungranted` once used. Readers cannot go back below the docket grants release once the first grant is written. An earlier release refuses a grant, so its `docket verify`, `docket tasks`, archiver, exporter and rule stop at the first grant, and its sink refuses to start when a grant is among the records it verifies at start. Grants stay in sealed segments and the archive, so this holds for as long as the docket keeps them, not only while a grant is in the active segment.

Rolling the sink or control back also needs its config rolled back: an earlier release refuses `grant_writers` in the docket config (`docket: unknown grant_writers`) and `grant_writers` and `issuers` in control's (`control: unknown grant_writers, issuers`). Remove those keys when you revert the release.
