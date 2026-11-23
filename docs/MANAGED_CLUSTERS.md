# Managed clusters

How to run the effector against GKE or EKS. Managed clusters get reads only: the `kubernetes-read` catalog, no write grants in the generated RBAC, and nothing from bailiff running in the cluster. The cluster holds only the generated RBAC and admission policies. Writes on managed clusters need a separate design and are not supported.

## Status

| Platform | Effector status | Evidence |
|---|---|---|
| GKE Standard 1.36 | supported | Probe on 1.36.4-gke.2377000 (2026-11-22): constrained impersonation enabled, SelfSubjectRulesReview incomplete with the pinned error. The pin was reproduced on kind v1.36.4 with a webhook authorizer. Recorded read-only run on the same version (2026-11-23), see `examples/live-run/README.md`. |
| GKE Autopilot | not supported | not tested |
| EKS 1.36 | not supported | not probed. `platform: eks` accepts no incomplete rules review, so if EKS reports one the effector does not start. |

The effector refuses to start on a cluster whose `/version` `gitVersion` contains `-gke.` unless `platform` is `gke`, and refuses `platform: gke` on any other cluster. There is no EKS version check.

## What changes with `platform`

`agent-bailiff init effector --platform gke|eks` writes `"platform"` and the `kubernetes-read` catalog into the effector's config. The effector refuses to start on `gke` or `eks` with any catalog operation other than `get` or `list`.

On `gke` the drift check changes in two ways:
- An incomplete SelfSubjectRulesReview is accepted only when its `evaluationError` is exactly `webhook authorizer does not support user rule resolution`. The listed rules are still compared with the generated set. Any other error, or that error combined with another, is drift. The pin identifies the authorizer type, not its identity.
- Because the rules review no longer shows every grant, each account (the effector and the audit account) runs a SelfSubjectAccessReview with its own token for a fixed list of dangerous actions (`agent_bailiff/effector/platform.py` `DANGEROUS_ACTIONS`): secrets reads, pod creation, exec, attach, port-forward, ephemeral containers, token creation, workload and RBAC writes, bind, escalate, impersonation beyond the generated grants, node proxy and patch, namespace deletion, persistent volumes, certificate signing, admission configuration and CRDs, and `*` on `*`. Any allowed action is drift, and so is a denial that carries an `evaluationError` (an authorizer that could not decide). A review with no decision fails the check. The recorded GKE run predates the `evaluationError` rule; whether GKE sets that field on ordinary denials has not been checked, and if it does the effector does not start on GKE.

On `upstream` and `eks` neither applies: an incomplete rules review is drift.

## Endpoint and CA

The effector calls the API server over HTTPS with a pinned CA.

- GKE: use the control plane's IP endpoint and the cluster CA. Add the bailiff host's egress address to the control plane authorized networks.
  ```sh
  gcloud container clusters describe <cluster> --location <location> --format 'value(endpoint)'
  gcloud container clusters describe <cluster> --location <location> \
    --format 'value(masterAuth.clusterCaCertificate)' | base64 -d > ca.crt
  ```
  Pass `--kube-host <endpoint> --kube-port 443 --kube-ca ca.crt`. The DNS endpoint is not supported: it is expected to present a Google certificate rather than one from the cluster CA, which has not been checked.
- EKS (not supported yet): `aws eks describe-cluster --name <cluster> --query cluster.endpoint` and `cluster.certificateAuthority.data`. A private endpoint must be reachable from the bailiff host.

## Install

```sh
agent-bailiff init effector --platform gke ... # other flags as in EFFECTOR.md
CATALOG=$(jq -r .catalog /var/lib/bailiff-effector/config.json)
agent-bailiff effector manifests --catalog "$CATALOG" \
  --namespace bailiff-system --service-account effector \
  --applier <applier user> --webhook-namespace bailiff-webhook --tenant tenant-a=staging > effector.json
agent-bailiff effector digest --catalog "$CATALOG"
```

- The generated set still holds the release webhook audit Role and RoleBinding, so the webhook namespace must exist. Nothing is deployed in it, and the effector does not check the webhook when the catalog has no writes.
- Decide's and the custodian's route tables name `{"service": "k8s", "name": "kubernetes-read"}`, and the custodian's effector bindings carry the digest printed above.
- Apply `effector.json` as the applier.

## Tokens

The effector and audit tokens are service account tokens from a TokenRequest that live at most 600 s, as on any cluster (EFFECTOR.md). The effector refuses tokens without `iat` and `exp` claims or with a longer lifetime, so a GKE access token or an `aws eks get-token` token does not work.

Mint them off the bailiff host and deliver them into the two 0600 files before they expire. A minter on the host would give whoever takes the host the power to mint more. The minter needs only this, in the effector namespace:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: bailiff-token-minter
  namespace: bailiff-system
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    resourceNames: ["effector", "effector-audit"]
    verbs: ["create"]
```

Bind it to the minter's own identity. On GKE, bind it through RBAC; do not give the minter `roles/container.developer` or `roles/container.admin`, which can create tokens for any service account in any cluster in the project.

```sh
kubectl create token effector -n bailiff-system --duration=10m
kubectl create token effector-audit -n bailiff-system --duration=10m
```

Whether these return a token with `exp - iat` of 600 s on GKE has not been checked. If not, the effector refuses the token.

## Cloud IAM check

Access granted by cloud IAM does not appear in RBAC. The dangerous-action reviews catch a grant on that list. A grant outside the list is not seen by the drift check. Run this check after setup and on a schedule:

- GKE: `gcloud projects get-iam-policy <project> --format json`, and the same for the folders and organization above it. List every principal holding `roles/owner`, `roles/container.admin`, `roles/container.developer`, or a custom role with `container.serviceAccounts.createToken`: each can mint effector tokens (permission lists checked with `gcloud iam roles describe` on 2026-11-23). No binding may name the effector or audit service account (as a Workload Identity principal). On 1.36.4-gke.2377000 with Workload Identity Federation enabled (2026-11-23), a project `roles/container.developer` binding for a service account's `principal://` identifier did not authorize that account's own requests: its access reviews and real list requests stayed denied for 11 minutes. So a grant of that kind gives the drift check nothing to see. Other roles, custom roles, folder or organization bindings and longer propagation were not tested.
- EKS: `aws eks list-access-entries --cluster-name <cluster>` and, for each entry, `aws eks list-associated-access-policies`. Any principal with a cluster-admin access policy, or mapped to `system:masters`, can mint effector tokens.

## Alerts

Alert on these effector log lines:
- `effector RBAC drift:`: the effector refuses calls until the next clean check.
- `over half its ... s freshness window`: a check took more than 60 s. At more than 120 s every call is refused.
- `effector_refusal_unrecorded`: a refusal the docket did not acknowledge.

Each check logs its duration, request count and throttled count. Per account the dangerous-action reviews cost 86 cluster-scope reviews plus 37 per namespace (the effector namespace and every tenant namespace), whatever the cluster's namespace count. The rules reviews still run once per account per namespace in the cluster. Check durations on GKE have not been measured.

## Stop and roll back

Nothing from bailiff runs in the cluster, so stopping the effector stops every call. Releases live at most 10 s and tokens at most 600 s.

- Stop now: delete the ClusterRoleBinding `bailiff-effector-impersonate`. On OrbStack v1.36.5 calls stopped 5 to 15 s later; not measured on GKE. Then stop the minter; the last tokens expire within 600 s.
- Remove bailiff from a cluster: suspend through `agent-bailiff control suspend`, wait 10 s, stop the effector and the minter, and delete the applied set as the applier (`kubectl delete -f effector.json`). The binding policy allows deleting generated RBAC.
- Roll back the effector version: on GKE, stop the effector instead. A version from before `platform` refuses a config that has it, and treats the incomplete rules review as drift, so it does not start.
- Change catalog or platform (for example from `kubernetes` to `kubernetes-read`). The catalog digest is signed into every release and the drift check compares RBAC with the configured catalog, so switch these together:
  1. Suspend, wait 10 s, stop the effector.
  2. Set `catalog` and `platform` in the effector's config, the catalog name in decide's and the custodian's route tables, and the new digest in the custodian's effector bindings.
  3. Generate and apply the new set. Applying does not remove objects the new set lacks; from `kubernetes` to `kubernetes-read` delete the `bailiff-<tenant>-scale` and `bailiff-<tenant>-restart` Roles and RoleBindings in each tenant namespace, and the `bailiff-scale-deployment` and `bailiff-restart-deployment` policies and bindings. Leftover bindings naming a synthetic user are drift.
  4. Start the effector; it serves nothing until its first drift check passes. Resume.
