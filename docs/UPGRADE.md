# Upgrading to permission scopes

This release moves task scopes to agent-warrant 0.4.0's permission list (D21 in [DECISIONS.md](DECISIONS.md)): a call is allowed only when one permission covers both its tool and its resource. A v1 scope, with `tools`, `resources` and `max_cost_per_call` at the top level, is read as one permission and accepted only on a root issued before `scope_v1_cutoff`.

## Choose the cutoff

`scope_v1_cutoff` is a Unix time in seconds, in both decide's and the custodian's `config.json`. A v1 root issued at or after it is refused as `chain_invalid`, with the log reason `task root: scope_v1_expired`. `init` writes 0, which accepts no v1 root.

- To keep tasks issued before the upgrade working, set the cutoff to the time you upgrade the issuers. Those tasks run to their expiry, at most 86,400 s later.
- To end every v1 task at once, leave it at 0. Every v1 task is then refused from the moment decide restarts, and its agent needs a new task.

Set the same value in both files. Each service logs its effective cutoff at startup:

```
decide <decider_id> effective scope_v1_cutoff=<n>
custodian <custodian_id> effective scope_v1_cutoff=<n>
```

The two are not checked against each other. If the custodian's cutoff is earlier than decide's, decide allows and reserves a v1 call that the custodian then refuses: the agent sees `release_refused`, the custodian logs `custodian refused the chain of a verified clearance: task root: scope_v1_expired` and records `chain_refused`. If decide's is earlier, decide refuses the call first. Compare the two startup lines after every restart.

## Rollout order

1. Docket sink, archiver, exporter and `docket verify` hosts. The docket entry format is unchanged, so these read records from either version and their order is not load-bearing; upgrading them first puts every reader on the new release before the writers.
2. Decide and the custodian together, with the same `scope_v1_cutoff`. Both now verify v1 and v2 chains.
3. Clients that delegate. `delegate` takes a v2 scope, and a 0.3.0 client cannot read a v2 root, so a delegating client must be upgraded before its holder receives a v2 task.
4. Issuers. From here `task issue` writes v2 scopes only, so nothing on the path may still run 0.3.0.

## Canary

After step 2, before step 4, run one v1 chain and one v2 chain through the gateway to both services:

- A v1 task issued before the cutoff makes one allowed call. The docket shows decide's `allow` and the custodian's `release`, and decide logs `scope_v1_accepted` with the task's root binding.
- A v2 task with two permissions makes one call each permission covers and one that pairs the tool of one with the resource of the other. The first two are released; the third is refused as `out_of_scope`.

A `chain_refused` entry from the custodian on the v1 call means the cutoffs differ.

## Draining v1

Decide logs each v1 root it accepts as a `scope_v1_accepted` warning with tenant, task, root binding, `issued_at` and cutoff. The docket does not record the scope version; entries before the cutoff plus 86,400 s are the only v1 candidates. After that time no v1 root is valid. Until then, an issuer key can still mint a v1 root, backdated before the cutoff, with free pairing; set the cutoff back to 0 once the drain ends to close that.

## Task file size

The task file holds at most 4,096 bytes. agent-warrant allows a scope of up to 16 permissions and 64 entries, which does not fit; `task issue` refuses a scope whose task file would be larger, before signing. Measured task files:

| Scope | Task file |
| --- | --- |
| One permission, one tool, one resource | 714 B |
| Two permissions, two tools each, 10 repositories each (20 in all) | 1,670 B |
| 16 permissions, one tool and one resource each | 2,738 B |

## Rollback

Once any v2 task is issued, going back to the previous release, on agent-warrant 0.3.0, is an outage for v2 tasks: 0.3.0 refuses to decode a v2 root, so the previous decide and custodian refuse every v2 call, the previous proxy cannot load a v2 `task.json`, its `task issue` refuses to write over one until it is removed, and its client cannot delegate from one. To roll back, revert every component in the reverse of the rollout order, remove each v2 `task.json`, and reissue the tasks with v1 scopes. Tasks issued with v1 scopes before the upgrade keep working on 0.3.0.
