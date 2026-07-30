<!-- markdownlint-disable MD013 -->

# openbao-config-operator

MTO OpenBao Extension

## Go module setup for private repos

This project depends on private modules under `github.com/stakater-ab`.

Before running `make build` or `go mod tidy`, configure Go to treat them as private:

```bash
# Tell Go to skip proxy/caching for private modules
export GOPRIVATE=github.com/stakater-ab/*

# If you use SSH for GitHub (recommended):
git config --global url."ssh://git@github.com/".insteadOf "https://github.com/"
```

## OpenBao authentication

The operator holds no stored OpenBao credential. It selects an auth mode from
`BAO_AUTH_METHOD`:

- **`kubernetes`** (deployment default): the operator exchanges its projected
  ServiceAccount token at `auth/k8s-operator/login` for a short-lived bao
  token, cached until near expiry and re-acquired automatically on expiry or
  revocation. Requires a one-time bootstrap (below).
- **`token`** (default when the env var is unset — used by `make run`): static
  token from `VAULT_TOKEN`/`BAO_TOKEN`, the legacy behavior. You are
  responsible for the token's lifetime.

### Bootstrap (once per OpenBao server)

The bootstrap creates the operator's auth mount and its config, the
`operator-manage` policy, the login role, and the token-reviewer identity bao
uses to call TokenReview. The operator cannot create these itself: it would
need to authenticate in order to build the thing it authenticates with, and a
CR that owned them could delete the operator's own way in.

You need:

- `bao`, `jq` and `kubectl` locally, pointed at the target cluster
- cluster-admin on the cluster (the script creates a ClusterRoleBinding)
- OpenBao reachable and unsealed
- a privileged OpenBao token, used only to mint a temporary one

**1. Mint a temporary bootstrap token.** Root's only job — it never touches
the script:

```bash
export VAULT_ADDR=https://<openbao>:8200
VAULT_TOKEN=<root> bao policy write obx-bootstrap hack/e2e/openbao/bootstrap-policy.hcl
BOOT_TOKEN=$(VAULT_TOKEN=<root> bao token create -field=token -policy=obx-bootstrap -ttl=20m)
```

Do not add `-use-limit`: `num_uses` counts every request including lookups, and
would kill the script midway.

**2. Run the bootstrap.**

```bash
VAULT_TOKEN=${BOOT_TOKEN} ./hack/e2e/openbao/bootstrap_operator_auth.sh
```

**3. Deploy or upgrade the operator** by whichever route you use (kustomize,
Helm, OLM bundle). The manifests already carry `BAO_AUTH_METHOD=kubernetes` and
the audience-bound projected token volume.

Steps 2 and 3 are order-independent. An operator running without the bootstrap
does not crash — it fails each reconcile and requeues, then starts working
within seconds of the bootstrap landing, with no restart needed. Running
bootstrap first simply avoids the window.

The script is idempotent — re-run it any time, for repair or when a release
notes a policy update. It ends by logging in as the operator's ServiceAccount
to prove the handshake works, reading the ServiceAccount, audience, mount and
role from the live Deployment rather than from its own inputs. If the operator
is not deployed yet, that check reports `SKIPPED` and you can re-run later.

On dev/kind, `make deploy` runs all of this for you with the dev-mode root
token. The temporary token expires on its own. Revoking the root token
afterwards is optional and reversible — a quorum of unseal keys can regenerate
one via `bao operator generate-root`.

### Verify

```bash
# the operator got in. --tail=-1 is required: with a selector, kubectl
# defaults to the last 10 lines and the login line scrolls out of range.
kubectl -n openbao-config-operator-system logs -l control-plane=controller-manager --tail=-1 \
  | grep "bao login"
# want: INFO bao-auth bao login succeeded {"reason": "expiry", "leaseSeconds": 3600}

# no stored credential in the pod spec
kubectl -n openbao-config-operator-system get deploy openbao-config-operator-controller-manager -o json \
  | jq '[.spec.template.spec.containers[0].env[].name | select(. == "VAULT_TOKEN" or . == "BAO_TOKEN")]'
# want: []
```

Skipping this is cheap to regret: the failure mode is a healthy-looking pod
whose every CR sits at `Ready=False`, which reads like a broken operator rather
than an incomplete bootstrap.

### Migrating an install that used a stored token

Earlier versions read a static bao token from the `mto-openbao-token` Secret.
To move an existing install off it:

1. **Bootstrap first** (steps 1–2 above). Doing this before the upgrade means
   there is no window where the operator cannot authenticate.
2. **Upgrade the operator.** The new manifests set
   `BAO_AUTH_METHOD=kubernetes`, mount the audience-bound projected token, and
   drop the `VAULT_TOKEN` env.
3. **Verify** (above) before touching the old credential.
4. **Revoke the old token, then delete the Secret:**

   ```bash
   OLD=$(kubectl -n openbao-config-operator-system get secret mto-openbao-token -o jsonpath='{.data.token}' | base64 -d)
   VAULT_TOKEN=${OLD} bao token revoke -self
   kubectl -n openbao-config-operator-system delete secret mto-openbao-token
   ```

   If that Secret holds the root token itself rather than a scoped one, `revoke
   -self` revokes root. That is recoverable via `bao operator generate-root`,
   but decide deliberately rather than by copy-paste.

Rolling back is the reverse: re-create the Secret, set
`BAO_AUTH_METHOD=token`, and roll the deployment. The bao-side bootstrap
objects are inert when unused, so nothing needs cleaning up.

### When a release changes the policy

`operator-manage` lives in OpenBao, not in the image, so **upgrading the
operator does not update it**. Any release whose notes flag a policy change
needs step 2 re-run against each OpenBao server. Until then the operator keeps
working with the old policy, and CRs touching newly granted paths return 403
with a `Forbidden` condition.

### Troubleshooting

Every value the bootstrap writes has a counterpart in the operator Deployment.
The login probe catches these at bootstrap time; if you hit them at runtime,
the message in the operator log or the CR's `Ready` condition names the cause:

| Message | Cause |
| --- | --- |
| `invalid audience (aud) claim` | the role's `audience` and the projected volume's `audience` differ |
| `service account name not authorized` | the role's bound ServiceAccount is not the Deployment's `serviceAccountName` |
| `invalid role name "..."` | `BAO_AUTH_ROLE` does not match the role the bootstrap created |
| `permission denied` on login | the mount does not exist, or bao's token-reviewer credential is stale — re-run the bootstrap |
| `permission denied` on a CR's path | the policy is missing that path; re-run the bootstrap after a policy-changing release |
| `read service account token: no such file` | `BAO_AUTH_JWT_PATH` does not match the projected volume's mount path |

## E2E

### Prerequisites

0. authenticated with GitHub CLI
1. install openbao and jq cli.
2. ensure openbao is running in the cluster at port 8200.
3. `export VAULT_ADDR="http://localhost:8200"`
4. run the bootstrap above (on dev-mode openbao, `make openbao-bootstrap-auth`)

### Setup

`./test/e2e/obx_e2e_setup.sh`

### Run test

`make test-e2e`
