# Effector

The effector lets an agent change infrastructure without the agent, the gateway or any third-party MCP server holding a credential for it. For Kubernetes it is the gateway's upstream MCP server for catalog tools. It holds the only cluster credential and runs each approved operation itself, as an identity the cluster limits to that operation class.

## Operation catalog

`agent_bailiff/effector/catalogs/kubernetes.json` lists the operations. Each one names a call from a fixed allow-list (group, version, resource, subresource, verb), its arguments with types and ranges, and the response fields returned. The catalog's digest is signed into every release. The shipped catalog:

| Operation | Tool | Identity | Call |
|---|---|---|---|
| `list_pods` | `k8s.pods.list` | `read` | list `pods`, `limit` 1 to 200 |
| `read_pod_log` | `k8s.pods.log` | `read` | get `pods/log`, `tailLines` 1 to 500 |
| `get_deployment` | `k8s.deployments.get` | `read` | get `apps/deployments` |
| `scale_deployment` | `k8s.deployments.scale` | `scale` | patch `apps/deployments/scale`, `replicas` 1 to 10 |
| `restart_deployment` | `k8s.deployments.restart` | `restart` | server-side apply to `apps/deployments`, setting the pod template's `kubectl.kubernetes.io/restartedAt` and `bailiff.dev/restart-op` annotations |

The tool id, identity, resource (`k8s/<namespace>/<resource>[/<name>]`) and request body are derived from the call, not configured. A restart is a forced server-side apply, field manager `bailiff-effector`, of `restartedAt` (the release issue time) and `bailiff.dev/restart-op` (the release op-id). The op-id makes two distinct restarts in the same second produce distinct pod templates; retrying the same release changes nothing. Apply is used rather than a merge patch because the API server keeps at most 10 Update managers and merges older ones into `ancient-changes`, which the restart policy would read as a change to other managers' entries; Apply entries are not merged. A restart of a missing Deployment creates nothing (the guard admits only updates).

The same catalog produces the gateway routes and decide's resource for each call (`routes_from_catalog`), the tool schemas the effector lists, and the RBAC and admission objects. Routes outside the catalog cannot use the `k8s.` tool prefix.

## One call

1. decide and the custodian check the call as they do any other. For an effector binding, the custodian does not read a credential. It signs a release (`agent-bailiff/release/v1`, header `bailiff-release`, at most 10 s) after claiming the op_id. The release carries the op_id, tenant, task, tool, resource, argument digest, catalog digest and decide's clearance.
2. The gateway removes any `bailiff-release` the agent sent, and the custodian adds its own.
3. The effector refuses the call if any of these fails:
   - the suspension state is readable and not suspended;
   - the last clean RBAC check is at most 120 s old;
   - the release signature (pinned custodian keys), audience (this effector), issuer and lifetime are valid, and the release was issued after the second in which the effector started;
   - the catalog digest matches;
   - decide's clearance verifies (pinned decide keys) and agrees with the release on op_id, tenant, task, tool, resource and argument digest;
   - the operation's tool equals the release's, the arguments match the catalog schema exactly, and the derived resource and argument digest equal the release's;
   - the op_id has not been used within the release lifetime. This is effector-local; admission is stateless and accepts replay of the exact released change until expiry.
4. It records an `attempt` docket entry and makes no call until the entry is acknowledged. It checks suspension again.
5. It makes one Kubernetes request built only from the catalog's fields and the checked arguments. The request impersonates `bailiff:<tenant>:<identity>`, with the op_id and trace id as user extras. It uses the effector's own token, read from a 0600 file on each call, over HTTPS with a pinned CA, with no redirects or proxies, a 10 s timeout and a 1 MiB response cap.
6. It records the outcome and returns only the catalog's response fields, within the catalog's byte limit. A timeout, a 5xx, a client failure or an unacknowledged outcome entry returns `outcome_unknown`, never success.

The MCP server binds 127.0.0.1, answers `initialize`, `ping` and `tools/list` itself, refuses requests with an `Origin` header, caps bodies at 64 KiB and refuses JSON-RPC batches. `tools/call` needs exactly one `bailiff-release` header.

## Kubernetes identity

The effector uses Kubernetes constrained impersonation, beta in v1.36. Its service account holds:
- `impersonate:user-info` on exactly the synthetic users `bailiff:<tenant>:<identity>` and the `bailiff.dev/op-id` and `bailiff.dev/trace-id` extras;
- in each tenant namespace, `impersonate-on:user-info:<verb>` for exactly the catalog's calls.

Each synthetic user is bound, in its tenant's namespaces only, to a Role with only its identity's calls. A request succeeds only if both the effector's impersonate-on grant and the synthetic user's own RBAC allow it. The effector itself can do nothing else; it cannot list namespaces or delete.

Admission is load-bearing. Every policy fails closed and is bound cluster-wide in Deny mode:
- **the guard** denies a synthetic user any write except the catalog's write calls, any write outside its tenant's namespaces, and any request without exactly one well-formed op-id;
- **the range policy** limits `replicas` on `deployments/scale` to the catalog's range;
- **the restart policy** denies the restart identity any Deployment update except the two restart pod template annotations; `bailiff.dev/restart-op` must equal the request's single op-id extra. Every `DeploymentSpec` field, the pod spec, the pod template metadata and the Deployment's own metadata must be unchanged, except the server-owned `generation`, `resourceVersion` and `managedFields`. Other field managers' entries must be unchanged, except that an entry owning only `restartedAt` may lose it, and the `bailiff-effector` entry must be an Apply entry owning only the two restart annotations;
- **the binding policy** refuses creating or updating any RoleBinding or ClusterRoleBinding that names the effector, its audit account or a synthetic user, and creating or updating generated RBAC, unless the applier makes the change. Deleting generated RBAC is allowed, because it only removes access: deleting the effector's RoleBinding stops its next call.

Catalog writes also pass through the release-verifying webhook. See [RELEASE_WEBHOOK.md](RELEASE_WEBHOOK.md) for the Audit-to-Enforce rollout, structured denial events, operator response and deployment gates.

## Generated objects

```sh
agent-bailiff effector manifests \
  --namespace bailiff-system --service-account effector \
  --applier system:serviceaccount:argocd:argocd-application-controller \
  --webhook-namespace bailiff-webhook --tenant tenant-a=staging
```

This prints one kubectl `List`: the effector namespace, the effector and audit service accounts, the RBAC above, the release webhook audit grant, the four admission policies and their bindings. [deploy/kubernetes/effector.example.json](../deploy/kubernetes/effector.example.json) is this output. The effector's namespace must hold nothing but the effector. The generator refuses `default` and `kube-*` as the effector, webhook or a tenant namespace. The webhook namespace must differ from the effector's and from every tenant namespace, and must exist before the set is applied. The applier is the user that applies the generated set, normally a GitOps controller. Tenant namespaces must already exist.

## Drift check

At startup, and 60 s after each check ends, the effector checks the cluster's grants and admission objects against the generated set. It refuses calls with `rbac_unverified` unless the last clean check is at most 120 s old, and if the first check fails it does not start. The check covers the effector's and audit account's effective rules, the synthetic users' catalog calls, and the rules, role references, subjects and admission specs of the generated objects. It does not compare their metadata, or the generated Namespace and ServiceAccounts.
- A SelfSubjectRulesReview as the effector and as the audit account in every namespace must show only the generated grants, the default self-review rules and the default discovery and health URLs. An incomplete review counts as drift.
- A SubjectAccessReview with the implicit `system:authenticated` group, for every synthetic user, tenant namespace and catalog call, must be allowed exactly when the namespace is the tenant's and the call is the identity's.
- Every generated binding, role, policy and policy binding must be present and unchanged. No other binding may name the effector, the audit account or a synthetic user.
- When the catalog offers restart, the audit account reads `/openapi/v3/apis/apps/v1`. `Deployment`, `DeploymentSpec`, `PodTemplateSpec` and `ObjectMeta` must have exactly the fields the restart policy accounts for, and `Deployment.metadata`, `Deployment.spec`, `DeploymentSpec.template` and `PodTemplateSpec.metadata` must reference them. If the schema differs, or the document cannot be read within the 1 MiB response limit (711 KB on v1.36.5), the effector refuses restarts with `restart_unverified` and keeps serving the other operations. The restart policy stays in place either way.

The audit account may only list namespaces, RBAC objects and admission policies, create SubjectAccessReviews, get the generated release webhook objects and its two guard policies and bindings by name, and, in the webhook namespace only, get Pods and list EndpointSlices for the webhook audit's serving-endpoint check. Pod and EndpointSlice names are generated, so this grant cannot be limited by name; it is a namespaced Role, never cluster-wide, and the drift check compares it like every other generated grant.

## Running it

```sh
agent-bailiff init effector --dir /var/lib/bailiff-effector --name effector.homelab \
  --custodian-pin custodian.pub.json --decide-pin decide.pub.json \
  --ledger /var/lib/bailiff-decide/ledger.db --ledger-uid <decide uid> --ledger-group <ledger gid> \
  --port 18080 --kube-host <api server host> --kube-port 6443 --kube-ca ca.crt \
  --kube-token-file effector.token --kube-audit-token-file audit.token \
  --effector-namespace bailiff-system --service-account effector \
  --applier <applier user> --webhook-namespace bailiff-webhook --tenant tenant-a=staging \
  --docket-socket /run/bailiff-docket/docket.sock --docket-uid <docket uid>
agent-bailiff effector run --config /var/lib/bailiff-effector/config.json
```

- Decide's and the custodian's route tables name the catalog: `{"routes": [...], "catalogs": [{"service": "k8s", "name": "kubernetes"}]}`. Only shipped catalogs can be named.
- The custodian needs an effector binding per tool, with the effector's name as credential id and the catalog digest from `agent-bailiff effector digest`. Decide needs a matching target binding.
- Point the gateway's MCP target for the catalog service at `http://127.0.0.1:<port>/mcp`, and remove `bailiff-release` in its header modifier. check-config requires both: a catalog service must target http on 127.0.0.1, localhost or [::1]. It does not check the port or path against the effector's config; a release sent to another local server can at most run or drop the one approved operation it binds, or return a false result to the agent.
- Run one effector instance. Its single-use set is in memory.
- The effector and audit tokens must be service account tokens that live at most 600 s, for example `kubectl create token effector --duration=10m` or a TokenRequest with `expirationSeconds: 600`. The effector reads the effector token on every call and the audit token on every drift check, and refuses a token whose `exp` is more than 600 s after its `iat`, or that has no such claims; this catches legacy token secrets and projected tokens whose expiry the API server extended. It checks only those claims, not the token's identity, so installing the right service account's token is the operator's job. Replace them before they expire from outside the effector host: a minter on that host would give whoever takes the host the power to mint more.
- To stop the effector everywhere, delete the ClusterRoleBinding `bailiff-effector-impersonate`; on OrbStack v1.36.5 calls stopped 5 to 15 s later. Deleting `bailiff-effector-on` in a namespace stops calls there by the next call.

## Tests

- `tests/test_effector_gateway.py` runs the pinned agentgateway binary in front of a real effector. The effector receives exactly the custodian's `bailiff-release`. A tools/call answered with 503 returns a failure to the agent and reaches the upstream once, counted again after 3 s.
- `tests/test_effector_cluster.py` runs against a disposable cluster when `AGENT_BAILIFF_TEST_KUBE_CONTEXT` is set, and has been run on OrbStack v1.36.5. It covers a restart and its retry, a restart after `kubectl rollout restart`, a restart of a Deployment with 12 field managers, a restart of a missing Deployment, and nineteen changes the restart identity must not make, sent with the effector's own token as merge patches, JSON patches and forced applies.

## Limits

- Grants that reach the effector or a synthetic user through a group cannot be refused at admission; the next drift check finds them.
- Admission does not see reads. Reads are bounded by the impersonate-on grants and the catalog.
- `read_pod_log` returns the log text unchanged. A log line can carry instructions to the agent, and any secret an application logs reaches the agent, which may pass it to another tool. Decide still limits every action to the task's scope.
- The effector's admission objects are protected by the drift check, not by admission. The release webhook's separate registration, serving assets and workload are checked by its audit command; see [RELEASE_WEBHOOK.md](RELEASE_WEBHOOK.md).
- A direct RBAC or admission change is in effect until the next check finds it, up to 60 s plus the duration of a check, unless the binding policy refuses it.
- The synthetic users' own permissions outside the catalog are not enumerated. They are reachable only through the effector's impersonation, which impersonate-on limits to catalog calls.
- A credential issued by the cluster for a `bailiff:` user name would act with that user's grants. Issuing one needs control of the cluster CA or identity provider.
- The op-id is passed as an impersonation extra. Whether the API server's audit events record it has not been checked.
- The restart identity may restart any Deployment in its tenant's namespaces, as often as it is called. A stolen effector token can therefore roll every such Deployment repeatedly, as it can already scale them within the range.
- A restart is only as gentle as the Deployment's strategy. With `Recreate`, or `maxUnavailable` at least the replica count, it takes every pod down at once. Rollouts do not consult PodDisruptionBudgets.
- The schema check guards the effector's own calls, not the cluster. After an upgrade that adds a Deployment or ObjectMeta field, the restart policy does not compare that field, so a stolen effector token can change it through the restart identity until the policy is regenerated for the new version. Admission cannot see the server version, so this is not closed in the policy.
- A restart is refused if another field manager owns `restartedAt` together with other fields, because the policy cannot tell that handover from a change to those fields.
- One instance only.
- A stolen effector token can make any write the catalog's policies allow, in any tenant namespace, until it expires or is revoked. Admission checks only the op-id's format, and the token holder chooses its value. Admission also cannot tie a write to the effector: under impersonation the request's user is rebuilt from the impersonation headers, so the token's pod identity is not visible, and DOKS's control-plane firewall always admits the cluster's own workloads. Only an admission webhook that verifies the custodian-signed release closes this; it is required before the catalog adds writes or the effector is used in production.
- A stolen audit token can list namespaces, RBAC objects and admission policies cluster-wide, and create SubjectAccessReviews.
- Effector bindings have no canary. Credential bindings can mark a credential as a canary, so a release of it is refused, denies the task and writes an alert; an effector binding has no equivalent.
