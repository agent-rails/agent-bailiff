# Release-verifying admission webhook

The release webhook adds cluster-side verification for Bailiff's catalog writes. Kubernetes admission receives `bailiff.dev/release` and `bailiff.dev/op-id` as impersonation extras. It checks the signed release and decide clearance with the same pure verifier used by the effector, binds the complete user/verb/resource/subresource/operation/kind and arguments to the release, and compares the old and new objects. A captured live release remains replayable until its 10 second lifetime plus the configured clock skew; suspension does not revoke a release already issued. A stolen effector token alone cannot create one.

## Actionable feedback

The webhook writes one-line JSON events to stdout for log collection:

- `bailiff_admission_would_deny`: a request that would fail verification while the webhook is in Audit mode. The request is allowed in this mode.
- `bailiff_admission_denied`: a request rejected in Enforce mode.
- `bailiff_admission_invalid_request` and `bailiff_admission_internal_error`: the webhook could not evaluate a valid request. The registration uses `failurePolicy: Fail`, so API writes fail closed.

Denial events include `reason_code`, `mode`, AdmissionReview `request_uid`, username, operation, resource, subresource, namespace and name. They never include the release, op-id, request object, or exception text. Route both denial event names to the Kubernetes security/on-call log alert path. In Audit mode, alert on `bailiff_admission_would_deny`; in Enforce mode, alert on `bailiff_admission_denied` and the two availability events. Retain Kubernetes API audit events long enough to investigate the request UID and impersonated identity. Do not treat webhook stdout as a durable audit ledger.

For an unexpected denial or would-deny:

1. Use `request_uid`, username and resource coordinates to find the matching Kubernetes API audit event and the authorized Bailiff operation/release record.
2. If the write was expected, identify the precise mismatch and correct the release, identity, object change or generated policy before enabling Enforce.
3. If it was not expected, suspend the task/tenant through Bailiff control, revoke the effector token, preserve webhook/API audit logs, and investigate the effector host and signing chain. Rotation of custodian and decide keys follows the documented key-rotation procedure.
4. If the webhook itself is unhealthy, keep `failurePolicy: Fail`; use the generated manifests with `--enforce` omitted to roll back to Audit mode, investigate, and rerun the audit. Do not delete the ValidatingWebhookConfiguration as a rollback: that silently removes the gate.

The `agent-bailiff-webhook audit` command checks generated webhook resources against live objects and runs SubjectAccessReviews for the Bailiff identities and effector account. Each finding names the drifted object or excessive permission and gives the immediate remediation. Run it during deployment and on a schedule; a nonzero exit is a deployment gate. This repository emits the structured events and actionable audit results, but paging, retention and scheduled audit execution must be connected to the cluster's log/alert and deployment systems.

## Rollout and operational gates

1. Generate and apply the webhook in Audit mode. Route the `would_deny` event to the on-call path and observe legitimate writes through a representative workload window.
2. Require a clean `agent-bailiff-webhook audit`, a successful TLS load/abuse test, and a reviewed API audit-log sample proving release extras are not exposed to unauthorized readers.
3. Verify admission transport limits and audit visibility on the target managed Kubernetes provider. OrbStack's successful 16 KB probe does not establish DOKS behavior.
4. Verify by access review that Bailiff identities and the effector account cannot mutate the webhook registration/CA bundle, pins, TLS secret, Deployment, or namespace.
5. Only then generate/apply Enforce mode. Keep the alert route and recurring audit active. Roll back to Audit mode, never by deleting registration.

The webhook uses TLS 1.2 or later, a concurrency limit, request-size limit and socket timeouts. The serving private key is mounted from a Secret and is not embedded in generated manifests. Pin the webhook image by digest. Confirm timeouts under TLS load on the target cluster before production use.
