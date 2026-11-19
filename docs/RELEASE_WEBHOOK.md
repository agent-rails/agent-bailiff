# Release-verifying admission webhook

The release webhook adds cluster-side verification for Bailiff's catalog writes. Kubernetes admission receives `bailiff.dev/release` and `bailiff.dev/op-id` as impersonation extras. It checks the signed release and decide clearance with the same pure verifier used by the effector, binds the complete user/verb/resource/subresource/operation/kind and arguments to the release, and compares the old and new objects. A captured live release remains replayable until its 10 second lifetime plus the configured clock skew; suspension does not revoke a release already issued. A stolen effector token alone cannot create one.

## Actionable feedback

The webhook writes one-line JSON events to stdout for log collection:

- `bailiff_admission_would_deny`: a request that would fail verification while the webhook is in Audit mode. The request is allowed in this mode.
- `bailiff_admission_denied`: a request rejected in Enforce mode.
- `bailiff_admission_invalid_request` and `bailiff_admission_internal_error`: the webhook could not evaluate a valid request. The registration uses `failurePolicy: Fail`, so API writes fail closed.

Denial events include `reason_code`, `mode`, AdmissionReview `request_uid`, username, operation, resource, subresource, namespace and name. They never include the release, op-id, request object, or exception text. Route both denial event names to the Kubernetes security/on-call log alert path. In Audit mode, alert on `bailiff_admission_would_deny`; in Enforce mode, alert on `bailiff_admission_denied` and the two availability events. Retain Kubernetes API audit events long enough to investigate the request UID and impersonated identity. Kubernetes audit events can include the impersonated `UserInfo`, which has an `extra` map; verify whether the release extra is recorded by the target provider and restrict audit-log readers accordingly. Treat a recorded live release as a short-lived write capability. Do not treat webhook stdout as a durable audit ledger.

For an unexpected denial or would-deny:

1. Use `request_uid`, username and resource coordinates to find the matching Kubernetes API audit event and the authorized Bailiff operation/release record.
2. If the write was expected, identify the precise mismatch and correct the release, identity, object change or generated policy before enabling Enforce.
3. If it was not expected, suspend the task/tenant through Bailiff control, revoke the effector token, preserve webhook/API audit logs, and investigate the effector host and signing chain. Rotation of custodian and decide keys follows the documented key-rotation procedure.
4. If the webhook itself is unhealthy, keep `failurePolicy: Fail`; use the generated manifests with `--enforce` omitted to roll back to Audit mode, investigate, and rerun the audit. Do not delete the ValidatingWebhookConfiguration as a rollback: that silently removes the gate.

The `agent-bailiff-webhook audit` command checks generated webhook resources against live objects and runs SubjectAccessReviews for the Bailiff identities and effector account. Each finding names the drifted object or excessive permission and gives the immediate remediation. Run it during deployment and on a schedule; a nonzero exit is a deployment gate. This repository emits the structured events and actionable audit results, but paging, retention and scheduled audit execution must be connected to the cluster's log/alert and deployment systems.

## Rollout and operational gates

1. Generate and apply the full webhook in Audit mode. Route the `would_deny` event to the on-call path and observe legitimate writes through a representative workload window.
2. Require a clean `agent-bailiff-webhook audit`, a successful TLS load/abuse test, and a reviewed API audit-log sample proving release extras are not exposed to unauthorized readers.
3. Verify admission transport limits and audit visibility on the target managed Kubernetes provider. OrbStack's successful 16 KB probe does not establish DOKS behavior.
4. Use a dedicated, access-restricted namespace for the webhook. Verify by access review that Bailiff identities and the effector account cannot mutate the webhook registration/CA bundle, pins, TLS Secret, Deployment, or namespace. Also review every effective principal and group: untrusted principals must not be able to create Pods/workloads in the namespace, use `pods/exec`, `pods/attach` or ephemeral containers, or mutate Services, Endpoints, EndpointSlices, or the TLS Secret. A Pod creator in this namespace can mount its TLS Secret and match the Service selector. Confirm every live Service endpoint is owned by the expected Deployment ReplicaSet before Enforce and during scheduled audits. `agent-bailiff-webhook audit` runs these access reviews in the webhook's namespace, read from the manifest, for the effector and each synthetic user, and reports the webhook namespace if it is also a tenant namespace; the review of every other principal and group stays manual.
5. Switch to Enforce in two phases; never apply a full Enforce bundle in one `kubectl apply`:

   ```sh
   agent-bailiff-webhook manifests ... --enforce --phase prepare > enforce-prepare.json
   kubectl apply -f enforce-prepare.json
   kubectl rollout status deployment/bailiff-release-webhook -n bailiff-system
   agent-bailiff-webhook manifests ... --enforce --phase target > enforce-target.json
   agent-bailiff-webhook manifests ... --enforce --phase register > enforce-register.json
   kubectl apply -f enforce-register.json
   agent-bailiff-webhook audit --manifest enforce-target.json ...
   ```

   First require a clean Audit-mode audit and the external gates above. The prepare phase updates the pinned mode config and pod template, triggering a rollout; pods carry the label `bailiff.dev/webhook-mode`. The register phase switches the Service selector to `bailiff.dev/webhook-mode: enforce` together with `failurePolicy: Fail`, so an Audit-mode pod can never serve a review under Fail; if no Enforce pod is ready, bailiff writes are denied rather than allowed. Wait for rollout completion before registering. `--phase target` renders the full Enforce desired state as a `WebhookAuditTarget`, which `kubectl apply` refuses; use it only with `audit --manifest`.
6. Keep the alert route and recurring audit active. To roll back, first render/apply the Audit registration (`manifests ... --phase register`), which sets `failurePolicy: Ignore` and returns the Service to selecting every webhook pod, then render/apply the full Audit bundle and wait for the Audit-mode rollout. Never delete the registration as rollback.

The webhook uses TLS 1.2 or later, a concurrency limit, request-size limit, socket timeouts and an absolute 5 s deadline per connection, including the TLS handshake, so a slow client cannot hold a slot. A peer that keeps opening connections can still fill the slots: in Enforce that denies bailiff writes, and in Audit it admits them with no `would_deny` event. Restrict ingress to the webhook port to the API server with a NetworkPolicy or the provider's equivalent; how the API server and kubelet probes reach Pods depends on the CNI, so this is not generated and must be verified on the target cluster. Any other admission webhook, and anyone who reads API audit logs, can see the release extra; treat both as able to replay a released write within its lifetime. The serving private key is mounted from a Secret and is not embedded in generated manifests. The Service must keep `publishNotReadyAddresses` unset or false; the drift audit reports it if enabled because it bypasses mode-aware Pod readiness. Serving certificates expire after 90 days. Rotate before expiry with an overlapping CA bundle:

1. Generate a fresh certificate set in a new protected directory; keep `ca.key` offline.
2. Concatenate the old and new CA certificates into `ca-overlap.pem`. Render and apply only the registration, passing this bundle to `--ca` (and `--enforce` if Enforce is active). This keeps the current serving certificate trusted while adding trust for the replacement.
3. Update the TLS Secret and roll the pods:

   ```sh
   kubectl -n bailiff-system create secret tls bailiff-release-webhook-tls \
     --cert=/secure/next/tls.crt --key=/secure/next/tls.key --dry-run=client -o yaml \
     | kubectl apply -f -
   kubectl -n bailiff-system rollout restart deployment/bailiff-release-webhook
   kubectl -n bailiff-system rollout status deployment/bailiff-release-webhook
   ```

4. Render and apply the registration again with only the new CA certificate, then run the webhook audit.

Schedule this rotation well before 90 days and alert on the deadline; the binary does not renew certificates automatically. Pin the webhook image by digest. Confirm timeouts under TLS load on the target cluster before production use, and verify the two replicas occupy separate nodes before Enforce.
