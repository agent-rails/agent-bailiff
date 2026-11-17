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

The tool id, identity, resource (`k8s/<namespace>/<resource>[/<name>]`) and request body are derived from the call, not configured. Restart is not offered, because Kubernetes has no narrow restart API.

The same catalog produces the gateway routes and decide's resource for each call (`routes_from_catalog`), the tool schemas the effector lists, and the RBAC and admission objects. Routes outside the catalog cannot use the `k8s.` tool prefix.

## One call

1. decide and the custodian check the call as they do any other. For an effector binding, the custodian does not read a credential. It signs a release (`agent-bailiff/release/v1`, header `bailiff-release`, at most 30 s) after claiming the op_id. The release carries the op_id, tenant, task, tool, resource, argument digest, catalog digest and decide's clearance.
2. The gateway removes any `bailiff-release` the agent sent, and the custodian adds its own.
3. The effector refuses the call if any of these fails:
   - the suspension state is readable and not suspended;
   - the last clean RBAC check is at most 120 s old;
   - the release signature (pinned custodian keys), audience (this effector), issuer and lifetime are valid, and the release was issued after the second in which the effector started;
   - the catalog digest matches;
   - decide's clearance verifies (pinned decide keys) and agrees with the release on op_id, tenant, task, tool, resource and argument digest;
   - the operation's tool equals the release's, the arguments match the catalog schema exactly, and the derived resource and argument digest equal the release's;
   - the op_id has not been used within the release lifetime.
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
- **the binding policy** refuses creating or updating any RoleBinding or ClusterRoleBinding that names the effector, its audit account or a synthetic user, and creating or updating generated RBAC, unless the applier makes the change. Deleting generated RBAC is allowed, because it only removes access: deleting the effector's RoleBinding stops its next call.

## Generated objects

```sh
agent-bailiff effector manifests \
  --namespace bailiff-system --service-account effector \
  --applier system:serviceaccount:argocd:argocd-application-controller \
  --tenant tenant-a=staging
```

This prints one kubectl `List`: the effector namespace, the effector and audit service accounts, the RBAC above, the three admission policies and their bindings. [deploy/kubernetes/effector.example.json](../deploy/kubernetes/effector.example.json) is this output. The effector's namespace must hold nothing but the effector. The applier is the user that applies the generated set, normally a GitOps controller. Tenant namespaces must already exist.

## Drift check

At startup, and 60 s after each check ends, the effector checks the cluster's grants and admission objects against the generated set. It refuses calls with `rbac_unverified` unless the last clean check is at most 120 s old, and if the first check fails it does not start. The check covers the effector's and audit account's effective rules, the synthetic users' catalog calls, and the rules, role references, subjects and admission specs of the generated objects. It does not compare their metadata, or the generated Namespace and ServiceAccounts.
- A SelfSubjectRulesReview as the effector and as the audit account in every namespace must show only the generated grants, the default self-review rules and the default discovery and health URLs. An incomplete review counts as drift.
- A SubjectAccessReview with the implicit `system:authenticated` group, for every synthetic user, tenant namespace and catalog call, must be allowed exactly when the namespace is the tenant's and the call is the identity's.
- Every generated binding, role, policy and policy binding must be present and unchanged. No other binding may name the effector, the audit account or a synthetic user.

The audit account may only list namespaces, RBAC objects and admission policies, and create SubjectAccessReviews.

## Running it

```sh
agent-bailiff init effector --dir /var/lib/bailiff-effector --name effector.homelab \
  --custodian-pin custodian.pub.json --decide-pin decide.pub.json \
  --ledger /var/lib/bailiff-decide/ledger.db --ledger-uid <decide uid> --ledger-group <ledger gid> \
  --port 18080 --kube-host <api server host> --kube-port 6443 --kube-ca ca.crt \
  --kube-token-file effector.token --kube-audit-token-file audit.token \
  --effector-namespace bailiff-system --service-account effector \
  --applier <applier user> --tenant tenant-a=staging \
  --docket-socket /run/bailiff-docket/docket.sock --docket-uid <docket uid>
agent-bailiff effector run --config /var/lib/bailiff-effector/config.json
```

- Decide's and the custodian's route tables name the catalog: `{"routes": [...], "catalogs": [{"service": "k8s", "name": "kubernetes"}]}`. Only shipped catalogs can be named.
- The custodian needs an effector binding per tool, with the effector's name as credential id and the catalog digest from `agent-bailiff effector digest`. Decide needs a matching target binding.
- Point the gateway's MCP target for the catalog service at `http://127.0.0.1:<port>/mcp`, and remove `bailiff-release` in its header modifier. check-config requires both: a catalog service must target http on 127.0.0.1, localhost or [::1]. It does not check the port or path against the effector's config; a release sent to another local server can at most run or drop the one approved operation it binds, or return a false result to the agent.
- Run one effector instance. Its single-use set is in memory.

## Tests

- `tests/test_effector_gateway.py` runs the pinned agentgateway binary in front of a real effector. The effector receives exactly the custodian's `bailiff-release`. A tools/call answered with 503 returns a failure to the agent and reaches the upstream once, counted again after 3 s.
- `tests/test_effector_cluster.py` runs against a disposable cluster when `AGENT_BAILIFF_TEST_KUBE_CONTEXT` is set, and has been run on OrbStack v1.36.5.

## Limits

- Grants that reach the effector or a synthetic user through a group cannot be refused at admission; the next drift check finds them.
- Admission does not see reads. Reads are bounded by the impersonate-on grants and the catalog.
- The admission objects are protected by the drift check, not by admission.
- A direct RBAC or admission change is in effect until the next check finds it, up to 60 s plus the duration of a check, unless the binding policy refuses it.
- The synthetic users' own permissions outside the catalog are not enumerated. They are reachable only through the effector's impersonation, which impersonate-on limits to catalog calls.
- A credential issued by the cluster for a `bailiff:` user name would act with that user's grants. Issuing one needs control of the cluster CA or identity provider.
- The op-id is passed as an impersonation extra. Whether the API server's audit events record it has not been checked.
- One instance only.
- Effector bindings have no canary. Credential bindings can mark a credential as a canary, which denies the task when it is released; an effector binding has no equivalent.
