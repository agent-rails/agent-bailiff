# GKE quickstart

Run the effector read-only against a GKE Standard cluster, with its tokens minted off the bailiff host. Read `MANAGED_CLUSTERS.md` first for what `platform: gke` changes and the cloud IAM check; this page is only the setup order.

Tested on 2026-11-23 against 1.36.4-gke.2377000 in europe-west1-b, with a laptop as the bailiff host. Steps 2, 4 and 5 and the fetcher ran as written with the values filled in, except that the image was built from a directory holding only the two files the Dockerfile copies. Not run: the `services enable` list (the APIs were already on except Cloud Scheduler), and the host `secretAccessor` binding (the host ran as a project owner).

## Shape

```
Cloud Scheduler (every 5 min) --> Cloud Run job "bailiff-minter" --TokenRequest via DNS endpoint--> GKE
                                          |
                                          v
                              Secret Manager "bailiff-tokens" (one enabled version)
                                          |
                    bailiff host: fetch_tokens.py every 60 s --> effector.token, audit.token (0600)
                                          |
                    effector --IP endpoint, cluster CA--> GKE (reads only)
```

- The minter's Google service account can create tokens only for `effector` and `effector-audit` in `bailiff-system`. It cannot read the secret.
- The host can read the secret and nothing else. Whoever takes the host gets tokens that expire within 600 s and cannot mint more.
- If the minter or the fetcher stops, the tokens expire within 600 s and the effector refuses every call.

## 1. Variables

```sh
PROJECT=<project>
ZONE=<zone>
REGION=<region of the zone>
CLUSTER=<cluster>
MINTER=bailiff-minter@$PROJECT.iam.gserviceaccount.com
TRIGGER=bailiff-scheduler@$PROJECT.iam.gserviceaccount.com
gcloud services enable container.googleapis.com run.googleapis.com cloudscheduler.googleapis.com \
  secretmanager.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com --project $PROJECT
```

## 2. Cluster

The minter reaches the control plane through the DNS endpoint, authenticated by IAM, so it needs no authorized network. For an existing cluster use `gcloud container clusters update $CLUSTER --enable-dns-access`.

```sh
gcloud container clusters create $CLUSTER --zone $ZONE --release-channel regular --enable-dns-access --project $PROJECT
DNS_ENDPOINT=$(gcloud container clusters describe $CLUSTER --zone $ZONE --project $PROJECT \
  --format 'value(controlPlaneEndpointsConfig.dnsEndpointConfig.endpoint)')
```

## 3. Effector RBAC

Generate and apply the effector's RBAC as in `MANAGED_CLUSTERS.md` (Install), with `--namespace bailiff-system --service-account effector`. The applier must not be anonymous, a control-plane, node or `kube-system` identity, or a service account in the webhook namespace; the generated guard policies refuse it.

## 4. Minter identity, secret and RBAC

```sh
gcloud iam service-accounts create bailiff-minter --project $PROJECT
gcloud secrets create bailiff-tokens --replication-policy automatic --project $PROJECT
gcloud projects add-iam-policy-binding $PROJECT --member serviceAccount:$MINTER \
  --role roles/container.clusterViewer --condition None
gcloud secrets add-iam-policy-binding bailiff-tokens --member serviceAccount:$MINTER \
  --role roles/secretmanager.secretVersionManager --project $PROJECT
```

`roles/container.clusterViewer` lets the minter authenticate to every cluster in the project but grants no Kubernetes objects; RBAC grants the rest. `roles/secretmanager.secretVersionManager` adds and destroys versions without reading them.

Apply as the cluster admin, replacing `<MINTER>`:

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
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: bailiff-token-minter
  namespace: bailiff-system
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: bailiff-token-minter
subjects:
  - apiGroup: rbac.authorization.k8s.io
    kind: User
    name: <MINTER>
```

Check: `kubectl auth can-i create serviceaccounts/effector --subresource=token -n bailiff-system --as $MINTER` is `yes`, and the same for `serviceaccounts/default` is `no`.

## 5. Minter job and schedule

Build from the repo root; the image holds only `deploy/gke/mint_tokens.py` on a pinned Python base.

```sh
gcloud artifacts repositories create bailiff --repository-format docker --location $REGION --project $PROJECT
IMAGE=$REGION-docker.pkg.dev/$PROJECT/bailiff/minter:$(git rev-parse --short HEAD)
cat > /tmp/cloudbuild.yaml <<EOF
steps:
- name: gcr.io/cloud-builders/docker
  args: [build, -f, deploy/gke/Dockerfile.minter, -t, $IMAGE, .]
images: [$IMAGE]
EOF
gcloud builds submit . --config /tmp/cloudbuild.yaml --region $REGION --project $PROJECT

gcloud run jobs create bailiff-minter --image $IMAGE --region $REGION --service-account $MINTER \
  --max-retries 0 --task-timeout 120s --project $PROJECT \
  --set-env-vars BAILIFF_CLUSTER_HOST=$DNS_ENDPOINT,BAILIFF_NAMESPACE=bailiff-system,BAILIFF_EFFECTOR_ACCOUNT=effector,BAILIFF_AUDIT_ACCOUNT=effector-audit,BAILIFF_SECRET=projects/$PROJECT/secrets/bailiff-tokens
gcloud run jobs execute bailiff-minter --region $REGION --wait --project $PROJECT

gcloud iam service-accounts create bailiff-scheduler --project $PROJECT
gcloud run jobs add-iam-policy-binding bailiff-minter --region $REGION --member serviceAccount:$TRIGGER \
  --role roles/run.invoker --project $PROJECT
gcloud scheduler jobs create http bailiff-minter --location $REGION --schedule '*/5 * * * *' \
  --uri "https://run.googleapis.com/v2/projects/$PROJECT/locations/$REGION/jobs/bailiff-minter:run" \
  --http-method POST --oauth-service-account-email $TRIGGER --project $PROJECT
```

Each run checks that both tokens name the right account and live at most 600 s (GKE issued exactly 600 s), adds one version, and destroys every older one. A run that fails publishes nothing and destroys nothing. Every 5 minutes leaves at least 5 minutes on the current tokens; a single missed run is absorbed, two in a row stop the effector.

## 6. Host

Grant the host's Google identity read access to the one secret:

```sh
gcloud secrets add-iam-policy-binding bailiff-tokens --member <host principal> \
  --role roles/secretmanager.secretAccessor --project $PROJECT
```

As the effector's uid, every 60 s (systemd timer, launchd or cron), into a directory owned by that uid and not writable by group or others:

```sh
python deploy/gke/fetch_tokens.py --project $PROJECT --secret bailiff-tokens \
  --effector-token /var/lib/bailiff-effector/effector.token --audit-token /var/lib/bailiff-effector/audit.token
```

It refuses a secret whose tokens live longer than 600 s or expire within 60 s, refuses an existing token file that is not 0600, and replaces a file only when its token changed. Then initialize and run the effector with `--platform gke`, the IP endpoint and the cluster CA (`MANAGED_CLUSTERS.md`, Endpoint and CA), and those two files.

## Stop

- Stop minting: `gcloud scheduler jobs pause bailiff-minter --location $REGION --project $PROJECT`. The effector stops within 600 s.
- Cut the minter off: delete the `bailiff-token-minter` RoleBinding.

## Not tested

- The effector reading the tokens written by `fetch_tokens.py`; the 2026-11-23 run checked them with `kubectl auth whoami`, and the agent run used tokens minted by the live-run harness.
- The minter on a private cluster or with VPC Service Controls.
- A host principal other than a user account.
