# CRD reference

User-facing reference for the CRDs this operator installs. Appended to as each
story of the [VCO wrap roadmap](./plans/PLAN-vco-wrap-roadmap.md)
lands its primitive(s).

## Summary

| Kind | Group / Version | Scope | Purpose |
|---|---|---|---|
| `OpenBaoExtension` | `security.mto.stakater.com/v1alpha1` | Namespaced | Cluster-level connection + defaults for OpenBao integration. Reconciled by the `ClusterAuth` and `Tenant` controllers. |
| `OpenBaoPolicy` | `security.mto.stakater.com/v1alpha1` | Namespaced | Authors an OpenBao ACL policy at `sys/policies/acl/<name>`. Optionally scoped to an OpenBao namespace via `spec.openbaoNamespace` (X-Vault-Namespace). |
| `OpenBaoKubernetesAuthRole` | `security.mto.stakater.com/v1alpha1` | Namespaced | Authors an OpenBao Kubernetes-auth role at `auth/<spec.path>/role/<name>`. Binds service accounts in selected namespaces to bao policies. |
| `OpenBaoSecretEngine` | `security.mto.stakater.com/v1alpha1` | Namespaced | Manages a bao secret-engine mount lifecycle at `sys/mounts/<path>`. Discriminated-union spec selects engine kind: `kvV2`, `transit`, `pki`. Optionally scoped via `spec.openbaoNamespace`. Auth-method mounts are out of scope for this Kind. |
| `OpenBaoNamespace` | `security.mto.stakater.com/v1alpha1` | Namespaced | Owns a bao namespace at `sys/namespaces/<name>`. Nested via `spec.openbaoNamespace` as the parent. Delete is gracefully blocked until the bao namespace is empty. |
| `OpenBaoPKISecretEngineConfig` | `security.mto.stakater.com/v1alpha1` | Namespaced | Generates the root CA at `<path>/root/generate/internal` and writes URL config at `<path>/config/urls`. Pairs with an existing `OpenBaoSecretEngine` of kind=pki at the same path. **IsDeletable=false**: CR delete does not disable the bao mount (would destroy the private key). |
| `OpenBaoPKISecretEngineRole` | `security.mto.stakater.com/v1alpha1` | Namespaced | PKI issuance role at `<path>/roles/<name>`. Defines what certs may be issued from a PKI mount (allowed domains, key type/bits, EKU flags, TTL). Requires the mount to have a CA configured. |
| `OpenBaoGroup` | `security.mto.stakater.com/v1alpha1` | Namespaced | Identity group at `identity/group`. `type=internal` groups bundle policies plus member entities/groups directly; `type=external` groups receive members through `OpenBaoGroupAlias` entries that map auth-method aliases into the group. Optionally scoped via `spec.openbaoNamespace`. |
| `OpenBaoGroupAlias` | `security.mto.stakater.com/v1alpha1` | Namespaced | Identity group-alias at `identity/group-alias`. Maps a `(name, mountAccessor)` tuple from an external auth method (OIDC, JWT, LDAP, …) into a parent `type=external` `OpenBaoGroup`. Bao keys aliases by id; the controller stamps the bao-side id on `status.aliasId` for stable round-trips. |
| `OpenBaoIdentityTokenRole` | `security.mto.stakater.com/v1alpha1` | Namespaced | OIDC token role at `identity/oidc/role/<name>`. Mints OIDC ID tokens signed by a pre-existing identity OIDC key for federated auth (typical use: tenants pull AWS / GCP creds via OIDC trust). Optionally scoped via `spec.openbaoNamespace`. |
| `OpenBaoAuthMethod` | `security.mto.stakater.com/v1alpha1` | Namespaced | Bao auth-method mount lifecycle at `sys/auth/<path>`. Sibling of `OpenBaoSecretEngine` for auth mounts (cert / jwt / oidc / kubernetes / approle / userpass / ldap). Stamps the bao-side mount accessor on `status.mountAccessor` so downstream CRs (notably `OpenBaoGroupAlias`) can bind to it. |
| `OpenBaoCertAuthEngineConfig` | `security.mto.stakater.com/v1alpha1` | Namespaced | Cert auth mount-level configuration at `auth/<path>/config`. OCSP cache + identity-alias-metadata tunables. Pairs with an `OpenBaoAuthMethod` of `type=cert` at the same path. `IsDeletable=false` — bao has no DELETE on `/config`. |
| `OpenBaoCertAuthEngineRole` | `security.mto.stakater.com/v1alpha1` | Namespaced | Cert auth role at `auth/<path>/certs/<name>`. Owns the trusted CA bundle (sourced from a Kubernetes Secret) plus the per-cert allow-list (allowedNames, allowedDnsSans, etc.) and the policies bao grants on a successful login. The Secret watch re-enqueues the CR on rotation. |
| `OpenBaoJWTOIDCAuthEngineConfig` | `security.mto.stakater.com/v1alpha1` | Namespaced | JWT/OIDC auth mount-level configuration at `auth/<path>/config`. OIDC discovery URL or static JWKS, client id + client_secret (read from a Kubernetes Secret), bound issuer, default role. Pairs with an `OpenBaoAuthMethod` of `type=jwt` or `type=oidc`. `IsDeletable=false`. |
| `OpenBaoJWTOIDCAuthEngineRole` | `security.mto.stakater.com/v1alpha1` | Namespaced | JWT/OIDC role at `auth/<path>/role/<name>`. Maps inbound JWT/OIDC claims (sub, email, groups, etc.) to the bao identity entity and grants policies on successful login. `roleType=oidc` requires `allowedRedirectUris` for the OAuth2 callback URL set. |
| `OpenBaoKubernetesAuthEngineConfig` | `security.mto.stakater.com/v1alpha1` | Namespaced | Kubernetes auth mount-level configuration at `auth/<path>/config`. `kubernetesHost`, optional CA bundle (Secret-sourced), token-reviewer JWT (Secret-sourced), `pemKeys`, `issuer`, and bao tunables. Pairs with an `OpenBaoAuthMethod` of `type=kubernetes`. Secret-watch propagates token-reviewer JWT and CA rotations. `IsDeletable=false` — bao has no DELETE on `/config`. |
| `OpenBaoTransitKey` | `security.mto.stakater.com/v1alpha1` | Namespaced | Transit key at `<path>/keys/<name>`. Pairs with an `OpenBaoSecretEngine` of kind=transit at the same path. `spec.type` / `spec.derived` / `spec.convergentEncryption` / `spec.keySize` are immutable post-create — editing them surfaces `Ready=False reason=Invalid`. Bao's `deletion_allowed` flag is the canonical delete gate; CR delete with `spec.deletionAllowed` unset/false leaves the CR `Terminating` with `Ready=False reason=DeleteBlocked`. |

---

## `OpenBaoPolicy`

Reconciles a CR to an OpenBao ACL policy. CRUD plus drift correction on every reconcile (event-driven; see [memory/project_vco_drift_gap](../../.claude/projects) for the periodic-resync gap).

### Sample

See [config/samples/security_v1alpha1_openbaopolicy.yaml](../config/samples/security_v1alpha1_openbaopolicy.yaml) for a runnable example:

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoPolicy
metadata:
  name: secret-reader
  namespace: mto-extension-openbao-system
spec:
  policy: |
    path "secret/data/public/*" {
      capabilities = ["read", "list"]
    }
```

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.policy` | string (HCL) | yes | — | Policy body in OpenBao's HCL syntax. |
| `spec.name` | string | no | `metadata.name` | Name used on the bao side. Takes precedence over `metadata.name` when set; must match `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`. |
| `spec.openbaoNamespace` | string | no | `""` (root) | Targets an OpenBao namespace via `X-Vault-Namespace`. Accepts empty (root), single-segment (`acme`), nested (`acme/sub`), with optional trailing slash. |

VCO's `spec.authentication` and `spec.connection` fields are **not** present — our operator uses a single token from `OpenBaoExtension.spec.server.tokenSecretRef` for all primitives. The namespace selector that lived on `spec.authentication.namespace` upstream is now `spec.openbaoNamespace`.

### Status

One condition: `Ready`. Reason values the controller sets:

| Reason | Meaning |
|---|---|
| `Reconciled` | Bao-side policy matches `spec.policy`. |
| `Invalid` | CR validation failed (reserved; `Policy` has no runtime validation beyond CRD schema). |
| `Forbidden` | Operator token lacks capability on `sys/policies/acl/*`. Update the operator's policy. |
| `NotFound` | 404 seen during drift check; self-heals on next reconcile. |
| `BaoError` | Any other non-2xx from OpenBao. `message` carries the raw server response. |

### Operational notes

- **Accessor placeholder substitution unsupported.** A CR whose `spec.policy` contains `${auth/<mount>/@accessor}` is rejected with `Ready=False`; the condition message names the placeholder and shows how to find the literal UUID. Hardcode it for now:

  ```bash
  bao auth list -format=json | jq -r '.["kubernetes/"].accessor'
  ```

- **Drift correction.** The controller re-checks the bao-side body every 5 minutes. An out-of-band edit (`bao policy write`) is overwritten on the next tick.
- **Force-delete footgun.** `kubectl delete --grace-period=0 --force` bypasses the finalizer and leaves the bao-side policy orphaned. Clean up with a direct HTTP DELETE to `sys/policies/acl/<name>` via a port-forward, or with the `bao` CLI if installed.
- **Bao-name collision protection.** Bao policy names are global; the `Policy` CRD is namespace-scoped. Two `Policy` CRs in different k8s namespaces that target the same bao policy name (same `metadata.name` with no `spec.name`, or same `spec.name`) are detected at reconcile time. The older `CreationTimestamp` wins; on tie, lex order of `<namespace>/<name>` decides. The losing CR surfaces `Ready=False, Reason=NameCollision` with a message naming the winning CR; no overwrite happens.

### RBAC

- `security.mto.stakater.com/openbaopolicies`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaopolicies/status`: `get, update, patch`
- `security.mto.stakater.com/openbaopolicies/finalizers`: `update`

No cluster-scoped or cross-resource permissions.

### Watches

- `Policy` CRs, filtered by `predicate.GenerationChangedPredicate` — only spec changes trigger reconciles. Status writes from the controller itself do not.

---

## OpenBaoKubernetesAuthRole

Reconciles a CR to an OpenBao Kubernetes-auth role at `auth/<spec.path>/role/<name>`. The role binds Kubernetes service accounts in selected namespaces to a list of bao policies. CRUD plus periodic drift correction; namespace label changes re-resolve selector-bound roles within seconds.

### Samples

Two runnable samples ship under `config/samples/`:

- [security_v1alpha1_kubernetesauthenginerole.yaml](../config/samples/security_v1alpha1_kubernetesauthenginerole.yaml) — literal namespace list. Use when the bound namespace set is known at apply time and does not move.
- [security_v1alpha1_kubernetesauthenginerole_selector.yaml](../config/samples/security_v1alpha1_kubernetesauthenginerole_selector.yaml) — label selector. Use when the bound namespace set is driven by labels and may grow or shrink at runtime.

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoKubernetesAuthRole
metadata:
  name: team-a-readers
  namespace: mto-extension-openbao-system
spec:
  path: kubernetes
  policies:
    - team-a-secret-reader
  targetServiceAccounts:
    - default
  targetNamespaces:
    targetNamespaceSelector:
      matchLabels:
        stakater.com/tenant: team-a
  tokenTTL: 1h
  tokenMaxTTL: 24h
```

### Spec fields

Duration fields (`tokenTTL`, `tokenMaxTTL`, `tokenExplicitMaxTTL`, `tokenPeriod`) accept bao-format duration strings — e.g. `1h`, `3600s`, `30m`.

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.path` | string | yes | — | Auth mount path. Bao writes to `auth/<path>/role/<name>`. |
| `spec.name` | string | no | `metadata.name` | Bao-side role name. Must match `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`. |
| `spec.policies` | string[] | yes | — | Bao policy names this role binds. MinItems=1. |
| `spec.targetServiceAccounts` | string[] | no | `["default"]` | Service account names inside each matched namespace. |
| `spec.targetNamespaces.targetNamespaces` | string[] | one of two | — | Literal list of namespace names. |
| `spec.targetNamespaces.targetNamespaceSelector` | LabelSelector | one of two | — | Label selector resolved against `corev1.Namespace`. |
| `spec.audience` | string | no | — | JWT audience claim bao verifies on login. |
| `spec.aliasNameSource` | enum | no | `serviceaccount_uid` | One of `serviceaccount_uid`, `serviceaccount_name`. |
| `spec.tokenTTL` | duration | no | bao default | Incremental token lifetime, referenced at renewal. |
| `spec.tokenMaxTTL` | duration | no | bao default | Hard cap for renewals. |
| `spec.tokenBoundCIDRs` | string[] | no | — | Restrict token use to these CIDR blocks. |
| `spec.tokenExplicitMaxTTL` | duration | no | bao default | Hard token lifetime cap that ignores renewal. |
| `spec.tokenNoDefaultPolicy` | bool | no | bao default | Suppress bao's `default` policy on issued tokens. |
| `spec.tokenNumUses` | int | no | bao default | Cap on token uses; `0` means unlimited. |
| `spec.tokenPeriod` | duration | no | bao default | Periodic token renewal interval. |
| `spec.tokenType` | enum | no | `default` | One of `service`, `batch`, `default`, `default-service`, `default-batch`. |

VCO's `spec.authentication` and `spec.connection` fields are **not** present — our operator uses a single token from `OpenBaoExtension.spec.server.tokenSecretRef` for all primitives.

Exactly one of `spec.targetNamespaces.targetNamespaces` or `spec.targetNamespaces.targetNamespaceSelector` must be set. Setting both, or neither, is rejected with `Ready=False reason=Invalid` (no requeue — fix the spec).

### Status

One condition: `Ready`. Reason values the controller sets:

| Reason | Meaning |
|---|---|
| `Reconciled` | Bao-side role matches the desired payload. |
| `Invalid` | XOR violation on `targetNamespaces` / `targetNamespaceSelector`, or empty literal list. |
| `Forbidden` | Operator token lacks capability on `auth/<path>/role/*`. Update the operator's policy. |
| `NotFound` | 404 seen during drift check; self-heals on next reconcile. |
| `BaoError` | Any other non-2xx from OpenBao. `message` carries the raw server response. |
| `NameCollision` | Another `OpenBaoKubernetesAuthRole` CR (different UID) targets the same `(spec.path, name)`. The older `CreationTimestamp` wins. |
| `InternalError` | k8s apiserver lookup failed during selector resolution or the cross-CR collision check. The fault is the apiserver, not bao. |

Status field `baoWritten` (bool) is the durable cleanup signal: it flips true after a successful upsert and is never cleared. The controller uses it on the deletion path to decide whether to call `BaoDelete`, so a CR that flipped `Ready=True→False` after writing (e.g. token revoked mid-life) still cleans up its bao role on delete.

### Operational notes

- **Selector resolution.** The controller watches `corev1.Namespace` with a `LabelChangedPredicate`. Adding the matching label to a new namespace, removing it, creating, or deleting a namespace all re-trigger reconciles for any selector-bound CR within seconds.
- **Empty selector match.** When the selector matches zero namespaces, the controller writes `["__no_namespace__"]` as a sentinel because bao rejects an empty bound list. Once a matching namespace appears, the watch fires and the role rebinds.
- **Drift correction.** The controller re-checks the bao-side role every 5 minutes. The bound-namespace list comparison is order-insensitive; an out-of-band edit (`bao write auth/.../role/...`) is overwritten on the next tick.
- **Force-delete footgun.** `kubectl delete --grace-period=0 --force` bypasses the finalizer and leaves the bao-side role orphaned. Clean up with a direct HTTP DELETE to `auth/<path>/role/<name>` via a port-forward, or with the `bao` CLI.
- **Bao-name collision protection.** Bao role identity is the full `auth/<path>/role/<name>` — two CRs with the same `metadata.name` on **different** auth mounts (different `spec.path`) do not collide. Two CRs with the same `(spec.path, name)` across k8s namespaces are detected at reconcile; older `CreationTimestamp` wins, lex-tiebreak on `<namespace>/<name>`.

### RBAC

- `security.mto.stakater.com/openbaokubernetesauthroles`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaokubernetesauthroles/status`: `get, update, patch`
- `security.mto.stakater.com/openbaokubernetesauthroles/finalizers`: `update`
- **`""/namespaces`**: `get, list, watch` (cluster-scoped) — required for selector resolution and the namespace-label watch.

This is the first cluster-scoped permission added by the VCO-wrapped CRDs. Audit/compliance reviewers should expect this delta when upgrading.

### Watches

- `OpenBaoKubernetesAuthRole` CRs, filtered by `predicate.GenerationChangedPredicate`.
- `corev1.Namespace`, filtered by `predicate.LabelChangedPredicate`. Map function fans label changes out to every CR whose `targetNamespaceSelector` matches the changed namespace's labels.

---

## `OpenBaoSecretEngine`

Reconciles a CR to a bao-side secret-engine mount at `sys/mounts/<spec.path>`. The discriminated-union spec selects which secret-engine kind to enable: `kvV2`, `transit`, or `pki`. Auth-method mounts are out of scope for this Kind — the kubernetes auth mount is enabled by `clusterauth` at startup; cert and JWT auth mounts will be modeled by a separate Kind when those primitives land.

Exactly one engine slot must be set; CRD-level XValidation + `IsValid` enforce the XOR.

### Sample

See [config/samples/security_v1alpha1_openbaosecretengine.yaml](../config/samples/security_v1alpha1_openbaosecretengine.yaml) for a runnable example:

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoSecretEngine
metadata:
  name: secret-kv
  namespace: mto-extension-openbao-system
spec:
  path: secret
  description: cluster-shared kv-v2
  kvV2: {}
```

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.path` | string | yes | — | Bao-side mount path (e.g. `secret`, `pki`, `transit`). Trailing slashes stripped before the API call. Anchored Pattern allows nested paths (`kv/cluster-a`). |
| `spec.description` | string | no | `""` | Free-form mount description; mirrored verbatim into bao. |
| `spec.openbaoNamespace` | string | no | `""` (root) | Targets an OpenBao namespace via `X-Vault-Namespace`. |
| `spec.kvV2` | object | one of | — | Selects a KV-v2 secret engine. Empty object is sufficient (kv-v2 default config). |
| `spec.transit` | object | one of | — | Selects a Transit secret engine. Stub for now; per-engine fields land with the Transit story. |
| `spec.pki` | object | one of | — | Selects a PKI secret engine. Pairs with `OpenBaoPKISecretEngineConfig` and `OpenBaoPKISecretEngineRole` CRs targeting the same path. |

### Status

One condition: `Ready`. Reasons:

| Reason | Meaning |
|---|---|
| `Reconciled` | Bao-side mount matches spec. |
| `Invalid` | XOR violation, empty path, or other spec-level failure. |
| `NameCollision` | Another CR (different UID) targets the same `(openbaoNamespace, path)` tuple. |
| `Forbidden` | Operator token lacks capability on `sys/mounts/*`. |
| `BaoError` | Any other non-2xx from OpenBao. |

### Operational notes

- **Idempotent enable.** Bao returns `400 "path is already in use"` when re-enabling at the same path. The wrapper treats this as success so reconciles after the first one are no-ops.
- **Drift correction is event-driven.** Description and KV-v2 options are compared against the bao read shape; a CR-spec edit triggers re-upsert. Out-of-band edits to mount config are not corrected until the CR is patched, or until the next 5-minute periodic resync.
- **Namespace isolation.** Same path in different OpenBao namespaces is not a collision — bao isolates mounts via `X-Vault-Namespace`.
- **Rename cleanup.** Changing `spec.path` (or `spec.openbaoNamespace`) tears down the previous bao mount before recording the new identity. `status.lastWrittenBaoName` and `status.lastWrittenOpenBaoNamespace` track the last-written identity.
- **Force-delete footgun.** `kubectl delete --grace-period=0 --force` bypasses the finalizer; clean up with a direct DELETE to `sys/mounts/<path>` via port-forward.

### RBAC

- `security.mto.stakater.com/openbaosecretengines`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaosecretengines/status`: `get, update, patch`
- `security.mto.stakater.com/openbaosecretengines/finalizers`: `update`

No cluster-scoped or cross-resource permissions.

### Watches

- `OpenBaoSecretEngine` CRs, filtered by `predicate.GenerationChangedPredicate`.

---

## `OpenBaoPKISecretEngineConfig`

Generates a CA inside an existing PKI mount and publishes the URL distribution config (AIA / CRL / OCSP). Pairs with `OpenBaoSecretEngine` of kind=pki at the same path — this CR populates the mount, it does not enable it. The field set, names, and defaults match upstream redhat-cop/vault-config-operator, except `connection`/`authentication` are dropped (single operator token) and `openbaoNamespace` is added.

**`spec.type` selects root vs intermediate:**

- `root` — a self-signed root CA. The key never leaves bao.
- `intermediate` — a CA whose CSR is signed by another CA. Two signing models, mutually exclusive:
  - `internalSign` — `internalSign.name` is the signing CA's **mount path**; the operator generates the CSR, calls `root/sign-intermediate` on that mount, and `intermediate/set-signed` — fully automated in one reconcile. By default the signing CA must be in this CR's `openbaoNamespace`; set `internalSign.openbaoNamespace` to sign against a CA in a **different** OpenBao namespace (e.g. a platform CA signing per-tenant intermediates). Only the sign call targets that namespace — generate + set-signed stay in the intermediate's own namespace.
  - `externalSignSecret` — the operator generates the CSR, writes it to a Secret named `<cr-name>-intermediate-csr` (key `csr`), and waits (`Ready=False, reason=AwaitingExternalSignature`) until the signed cert appears in the referenced Secret under `certificateKey` (default `tls.crt`); it then `set-signed`s and activates.

`permittedDnsDomains` applies X.509 name constraints (RFC 5280) at signing — the issued CA may only sign for those domains.

**`IsDeletable=false`.** The CR's finalizer is released without touching bao on delete. Disabling a PKI mount destroys the private key irreversibly and silently invalidates every cert ever issued. Same applies to renames: `spec.path` change leaves an orphan CA at the old mount (logged) rather than risking key loss. The CSR Secret (for intermediates) is owner-ref'd to the CR and garbage-collected with it.

### Samples

See [config/samples/security_v1alpha1_openbaopkisecretengineconfig.yaml](../config/samples/security_v1alpha1_openbaopkisecretengineconfig.yaml) for root + both intermediate modes.

```yaml
# Root CA (self-signed)
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoPKISecretEngineConfig
metadata:
  name: pki-root
  namespace: mto-extension-openbao-system
spec:
  path: pki-root
  type: root
  commonName: "Demo Root CA"
  ttl: "87600h"
  keyType: rsa
  keyBits: 4096
  organization: "Stakater Demo"   # flat, single-valued subject fields
  ou: "Platform"
  country: "US"
  issuingCertificates: ["https://bao.example.com/v1/pki-root/ca"]
  CRLDistributionPoints: ["https://bao.example.com/v1/pki-root/crl"]
---
# Intermediate signed in-bao by the root mount (same OpenBao namespace)
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoPKISecretEngineConfig
metadata:
  name: pki-int
  namespace: mto-extension-openbao-system
spec:
  path: pki-int
  type: intermediate
  commonName: "Demo Intermediate CA"
  ttl: "43800h"
  internalSign: { name: pki-root }     # root MOUNT path
  permittedDnsDomains: ["svc.cluster.local"]
```

### Spec fields

| Field | Type | Required | Description |
|---|---|---|---|
| `spec.path` | string | yes | PKI mount path. Must match an existing `OpenBaoSecretEngine` of kind=pki at the same path. |
| `spec.openbaoNamespace` | string | no | X-Vault-Namespace target. Empty = root. |
| `spec.type` | enum | no | `root` (default) or `intermediate`. |
| `spec.privateKeyType` | enum | no | `internal` (default) or `exported`. |
| `spec.commonName` | string | yes | X.509 CN of the generated CA cert. |
| `spec.ttl` | duration | no | CA cert validity. Bao default is short — set explicitly for any production CA. |
| `spec.keyType` | enum | no | `rsa` (default) or `ec`. |
| `spec.keyBits` | int | no | Key size; default 2048. |
| `spec.maxPathLength` | int | no | CA pathlen basic constraint; default -1 (no limit). |
| `spec.altNames` / `spec.IPSans` / `spec.URISans` / `spec.otherSans` | string | no | Comma-separated SANs. |
| `spec.excludeCnFromSans` | bool | no | Omit the CN from generated SANs. |
| `spec.permittedDnsDomains` | []string | no | X.509 name-constraints DNS allow-list, applied at signing. |
| `spec.ou` / `spec.organization` / `spec.country` / `spec.locality` / `spec.province` / `spec.streetAddress` / `spec.postalCode` / `spec.serialNumber` | string | no | Flat (single-valued) X.509 subject fields. |
| `spec.format` / `spec.privateKeyFormat` | enum / string | no | Output formats; `format` ∈ `pem` (default) / `pem_bundle` / `der`. |
| `spec.issuingCertificates` / `spec.CRLDistributionPoints` / `spec.ocspServers` | []string | no | AIA / CRL / OCSP distribution points published in every issued cert. |
| `spec.CRLExpiry` | duration | no | CRL rotation period; default `72h`. |
| `spec.CRLDisable` | bool | no | Turn off CRL building. |
| `spec.internalSign` | object | intermediate | Signing CA: `name` = its bao **mount path**; `openbaoNamespace` = its namespace (empty → this CR's own namespace; set it to sign cross-namespace, e.g. a platform CA). Mutually exclusive with `externalSignSecret`. |
| `spec.externalSignSecret` | objectRef | intermediate | Secret holding the externally-signed cert. Mutually exclusive with `internalSign`. |
| `spec.certificateKey` | string | no | Key within `externalSignSecret` holding the signed cert; default `tls.crt`. |
| `spec.publishCABundleConfigMap` | string | no | Names a ConfigMap (this CR's namespace) kept populated with the active CA cert PEM under `ca.crt`, plus the CA that key held before the last change under `ca-previous.crt`. Owner-ref'd to the CR. Empty = don't publish. |

`type=intermediate` requires **exactly one** of `internalSign` / `externalSignSecret`; `type=root` rejects both.

### Status

| Field | Description |
|---|---|
| `conditions[Ready]` | `Reconciled` / `Invalid` / `NameCollision` / `Forbidden` / `BaoError` / `AwaitingExternalSignature` / `InternalError`. |
| `generated` / `exported` / `signed` | Intermediate-bootstrap booleans; all true once an intermediate is Active. |
| `baoWritten` | True after first successful CA write. |
| `lastWrittenBaoName` / `lastWrittenOpenBaoNamespace` | Identity of the last successful write; rename-cleanup is skipped (IsDeletable=false). |
| `phase` | `""` before activation, `Active` after. An intermediate awaiting its external signature is surfaced via the `Ready` condition (reason `AwaitingExternalSignature`), not `phase`. |
| `caSerialNumber` | X.509 serial of the active CA, captured from bao after generate / set-signed. |

### Operational notes

- **Idempotent on existing CA.** BaoWrite re-probes via ReadPKICA; if a CA exists, only URLs are updated. Generate / sign is never run twice on the same mount.
- **External-sign generates the CSR exactly once.** While awaiting the offline signature the operator does not regenerate — the existing CSR Secret gates regeneration, so a retried signature uses the same key.
- **Drift correction.** URL config is the only mutable surface once the CA is active. CR-spec changes to URL fields are applied; CR-spec changes to CA fields (commonName, ttl, keyType, keyBits, subject, name constraints) are **silently ignored** because regenerating would destroy the private key — change those by creating a new mount + new CR.
- **Published CA bundle retains one predecessor.** When the active CA changes, the cert `ca.crt` held moves to `ca-previous.crt` before the new one is written. Certs issued by the outgoing CA stay in use until every workload re-issues, and they only validate while verifiers still trust it — so a trust distributor must source **every key** of the ConfigMap, not just `ca.crt`. Retention is bounded at one: a second replacement drops the CA before it. The drift check compares `ca.crt` only, so the extra key does not cause repeat writes.
- **Collision.** Two CRs at the same `(spec.path, spec.openbaoNamespace)` tuple → older `creationTimestamp` wins; loser `Ready=False, reason=NameCollision`.
- **Force-delete footgun.** `kubectl delete --grace-period=0 --force` releases the finalizer without the operator running cleanup. Same effect as the normal delete in this case — bao state is preserved either way.

### RBAC

- `security.mto.stakater.com/openbaopkisecretengineconfigs`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaopkisecretengineconfigs/status`: `get, update, patch`
- `security.mto.stakater.com/openbaopkisecretengineconfigs/finalizers`: `update`
- Bao token must have `update` on `<mount>/root/generate/internal`, `read` on `<mount>/cert/ca`, and `update` on `<mount>/config/urls`.

### Watches

- `OpenBaoPKISecretEngineConfig` CRs, filtered by `predicate.GenerationChangedPredicate`.

---

## `OpenBaoPKISecretEngineRole`

PKI issuance role at `<path>/roles/<name>`. Pairs with `OpenBaoPKISecretEngineConfig` at the same `spec.path` (the PKI mount must have a CA before roles can issue from it).

### Sample

See [config/samples/security_v1alpha1_openbaopkisecretenginerole.yaml](../config/samples/security_v1alpha1_openbaopkisecretenginerole.yaml):

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoPKISecretEngineRole
metadata:
  name: web-server
  namespace: mto-extension-openbao-system
spec:
  path: pki
  allowedDomains: ["*.demo.example.com"]
  allowSubdomains: true
  serverFlag: true
  keyType: rsa
  keyBits: 2048
  ttl: "720h"
  maxTtl: "8760h"
```

### Spec fields

| Field | Type | Description |
|---|---|---|
| `spec.path` | string | PKI mount path. Must match an existing `OpenBaoSecretEngine` of kind=pki. |
| `spec.name` | string | Bao-side role name. Defaults to `metadata.name`. |
| `spec.openbaoNamespace` | string | X-Vault-Namespace target. |
| `spec.allowedDomains` | string[] | CN/SAN allow-list for issued certs. |
| `spec.allowSubdomains` / `allowBareDomains` / `allowAnyName` / `allowGlobDomains` | bool | Domain-matching modifiers. |
| `spec.enforceHostnames` / `allowIpSans` | bool | Hostname / IP SAN gating. |
| `spec.serverFlag` / `clientFlag` / `codeSigningFlag` / `emailProtection` | bool | EKU permission flags. |
| `spec.keyType` | enum | `rsa` / `ec` / `ed25519` / `any`. |
| `spec.keyBits` | int | RSA: 2048\|3072\|4096. EC: 224\|256\|384\|521. |
| `spec.keyUsage` / `extKeyUsage` | string[] | X.509 usage strings (e.g. `DigitalSignature`, `ServerAuth`). |
| `spec.ttl` / `maxTtl` | duration | Issued-cert validity. |
| `spec.generateLease` / `noStore` / `requireCN` | bool | Per-issuance behaviour. |

`IsValid` rejects a spec that allows nothing — at least one of `allowAnyName`, `allowedDomains`, `allowGlobDomains`, `allowBareDomains`, `allowSubdomains` must be set; otherwise bao silently rejects every issuance.

### Status

Standard `Ready` condition. Reasons: `Reconciled`, `Invalid`, `NameCollision`, `Forbidden`, `BaoError`. Plus `lastWrittenBaoName` / `lastWrittenOpenBaoNamespace` for rename tracking.

### Operational notes

- **Drift correction.** The drift comparator sorts list-shaped fields (`allowedDomains`, `keyUsage`, `extKeyUsage`) before compare and treats unset spec fields as "bao default" so a CR that omits `keyBits` doesn't false-positive against bao's default of 2048.
- **Collision tuple is (mount path, role name, openbaoNamespace).** Same role name on a different mount or in a different bao namespace is not a collision.
- **IsDeletable=true.** CR delete removes the bao role. Issued certs remain valid until they expire — bao's PKI role is just an issuance gate, not a revocation list.

### RBAC

- `security.mto.stakater.com/openbaopkisecretengineroles`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaopkisecretengineroles/status`: `get, update, patch`
- `security.mto.stakater.com/openbaopkisecretengineroles/finalizers`: `update`
- Bao token must have `update` / `read` / `delete` on `<mount>/roles/*`.

---

## `OpenBaoGroup`

Reconciles a CR to an OpenBao identity group at `identity/group`. Bao
upserts groups by `(id, name)`; reads at `identity/group/name/<name>`;
deletes the same path. Groups bundle a list of policies that every
member inherits.

### Sample

See [config/samples/security_v1alpha1_openbaogroup.yaml](../config/samples/security_v1alpha1_openbaogroup.yaml).

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoGroup
metadata:
  name: platform-admins
  namespace: mto-extension-openbao-system
spec:
  type: internal
  policies:
    - platform-admin
```

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.name` | string | no | `metadata.name` | Bao-side group name. Pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`. |
| `spec.type` | enum | no | `internal` | `internal` (members held directly) or `external` (members come from `OpenBaoGroupAlias`). Immutable on bao's side. |
| `spec.policies` | []string | no | — | Bao policy names attached to the group. |
| `spec.memberGroupIds` | []string | no | — | Bao group ids. Only valid for `type=internal`. |
| `spec.memberEntityIds` | []string | no | — | Bao entity ids. Only valid for `type=internal`. |
| `spec.metadata` | map[string]string | no | — | Free-form key/value labels persisted on the bao group. |
| `spec.openbaoNamespace` | string | no | `""` | X-Vault-Namespace target. |

### Status

| Field | Description |
|---|---|
| `status.conditions[Ready]` | `Reconciled` / `Invalid` / `NameCollision` / `Forbidden` / `BaoError` / `InternalError`. |
| `status.baoWritten` | True after first successful write. Gates `BaoDelete` on the deletion path. |
| `status.lastWrittenBaoName` / `status.lastWrittenOpenBaoNamespace` | Identity tuple for rename cleanup. |
| `status.groupId` | Bao-side group id. Stamped on first create; re-stamped if recreated. Other CRs (notably `OpenBaoGroupAlias`) reference this. |

### Operational notes

- **Type immutability.** Bao does not allow changing a group's `type`
  in place. Editing `spec.type` on an existing group surfaces as
  `Ready=False / Reason=InternalError` with a clear message; delete
  and recreate to switch.
- **Drift comparator.** Sorts `policies`, `memberGroupIds`,
  `memberEntityIds` before compare. `type=external` groups skip
  member-id fields because bao silently drops them server-side.
- **External group members come through aliases.** Set members via
  `OpenBaoGroupAlias` CRs whose `canonicalGroupRef` points back at
  this group, not via `memberEntityIds`.
- **Collision tuple.** `(BaoName, openbaoNamespace)`. Same name in
  different bao namespaces is not a collision. Older
  `CreationTimestamp` wins; on tie, lex order of `<k8s-ns>/<name>`.

### RBAC

- `security.mto.stakater.com/openbaogroups`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaogroups/status`: `get, update, patch`
- `security.mto.stakater.com/openbaogroups/finalizers`: `update`
- Bao token must have `update` / `read` / `delete` on `identity/group/*`.

---

## `OpenBaoGroupAlias`

Reconciles a CR to an OpenBao identity group-alias at
`identity/group-alias`. An alias maps a `(name, mountAccessor)` tuple
from an external auth method (OIDC, JWT, LDAP, …) into a parent
`type=external` `OpenBaoGroup`. Bao keys aliases by id; the controller
stamps the bao-side id on `status.aliasId` so subsequent reads /
updates / deletes target the same alias even after a CR re-create.

### Sample

See [config/samples/security_v1alpha1_openbaogroupalias.yaml](../config/samples/security_v1alpha1_openbaogroupalias.yaml).

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoGroupAlias
metadata:
  name: alice-oidc-admin
  namespace: mto-extension-openbao-system
spec:
  name: alice@example.com
  mountAccessor: auth_oidc_abc123
  canonicalGroupRef:
    name: oidc-admins
```

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.name` | string | no | `metadata.name` | Alias name as seen by the auth method (OIDC sub, LDAP CN, etc.). Stored verbatim — case-sensitive. |
| `spec.mountAccessor` | string | yes | — | Bao accessor of the auth mount this alias maps from. Look up via `bao auth list -format=json`. |
| `spec.canonicalGroupRef` | object | one of | — | `{ name, namespace }` reference to an `OpenBaoGroup` CR. Mutually exclusive with `canonicalId`. |
| `spec.canonicalId` | string | one of | — | Literal bao group id when the parent is managed out of band. Mutually exclusive with `canonicalGroupRef`. |
| `spec.openbaoNamespace` | string | no | `""` | X-Vault-Namespace target. |

### Status

| Field | Description |
|---|---|
| `status.conditions[Ready]` | `Reconciled` / `Invalid` / `NameCollision` / `Forbidden` / `BaoError` / `InternalError` (parent group not yet ready). |
| `status.baoWritten` | True after first successful write. |
| `status.aliasId` | Bao-side alias id. Stamped on first create; recovered via `Backfill` when status is lost. |
| `status.lastWrittenMountAccessor` | Mount accessor the alias was last written under. Used on `mountAccessor` rename cleanup. |
| `status.resolvedCanonicalId` | Parent group id resolved from `canonicalGroupRef` or `canonicalId`. |

### Operational notes

- **Parent must be ready.** When `canonicalGroupRef` is used, the
  controller waits until the referenced `OpenBaoGroup`'s
  `status.groupId` is populated. Until then the alias surfaces
  `Ready=False / Reason=InternalError` and requeues. The alias
  controller watches `OpenBaoGroup` so it wakes up when the parent
  ready transitions.
- **Aliases are id-keyed.** Bao stores aliases by id, not by
  `(name, mountAccessor)`. The controller stamps the bao id on
  `status.aliasId`. If a CR is re-applied from manifest with no
  status, `Backfill` finds the existing alias by `(name,
  mountAccessor)` and re-stamps the id.
- **Mount-accessor rename.** `mountAccessor` is immutable on bao's
  side. Editing it deletes the old alias (using the previously
  stamped id) and creates a new one — managed automatically by the
  controller.
- **Collision tuple.** `(BaoName, mountAccessor, openbaoNamespace)`.
  Same alias name on a different mount or in a different bao
  namespace is not a collision.

### RBAC

- `security.mto.stakater.com/openbaogroupaliases`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaogroupaliases/status`: `get, update, patch`
- `security.mto.stakater.com/openbaogroupaliases/finalizers`: `update`
- `security.mto.stakater.com/openbaogroups`: `get, list, watch` (for parent resolution + watch).
- Bao token must have `update` / `read` / `delete` on
  `identity/group-alias` and `list` on `identity/group-alias/id`
  (used by `Backfill`).

---

## `OpenBaoIdentityTokenRole`

Reconciles a CR to an OIDC token role at `identity/oidc/role/<name>`.
The role binds a name to a pre-existing OIDC key
(`identity/oidc/key/<key>`) and a JWT claims template. Used to mint
OIDC ID tokens for federated auth — typical case is tenants pulling
AWS / GCP creds via OIDC trust.

### Sample

See [config/samples/security_v1alpha1_openbaoidentitytokenrole.yaml](../config/samples/security_v1alpha1_openbaoidentitytokenrole.yaml).

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoIdentityTokenRole
metadata:
  name: aws-tokens
  namespace: mto-extension-openbao-system
spec:
  key: platform
  clientId: arn:aws:iam::123456789012:role/openbao-federated
  template: |
    {
      "sub": "{{identity.entity.id}}",
      "name": "{{identity.entity.name}}"
    }
  ttl: 1h
```

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.name` | string | no | `metadata.name` | Bao-side role name. Pattern `^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`. |
| `spec.key` | string | yes | — | Name of a pre-existing OIDC key at `identity/oidc/key/<key>`. The controller does not create OIDC keys. |
| `spec.template` | string (JSON) | no | — | JWT claims template. Bao accepts plain JSON or base64-wrapped. |
| `spec.clientId` | string | no | — | Audience claim ("aud") of issued tokens. |
| `spec.ttl` | string | no | key default | Bao duration (`1h`, `3600s`, `30m`). |
| `spec.openbaoNamespace` | string | no | `""` | X-Vault-Namespace target. |

### Status

| Field | Description |
|---|---|
| `status.conditions[Ready]` | `Reconciled` / `Invalid` / `NameCollision` / `Forbidden` / `BaoError`. |
| `status.baoWritten` | True after first successful write. |
| `status.lastWrittenBaoName` / `status.lastWrittenOpenBaoNamespace` | Identity tuple for rename cleanup. |

### Operational notes

- **OIDC key must already exist.** The role write fails with a 4xx
  if `spec.key` does not name an existing `identity/oidc/key/*`.
  Create the key out of band: `bao write identity/oidc/key/<key>
  allowed_client_ids="*"`.
- **TTL drift comparator.** Bao stores TTL as int seconds; the
  wrapper renders `<n>s` so a spec of `3600s` round-trips against
  bao's `3600` without false drift.
- **Empty TTL adopts the key default.** A spec leaving `ttl` unset
  is equivalent to bao's key default — no drift signal regardless
  of what bao echoes.
- **Collision tuple.** `(BaoName, openbaoNamespace)`.

### RBAC

- `security.mto.stakater.com/openbaoidentitytokenroles`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaoidentitytokenroles/status`: `get, update, patch`
- `security.mto.stakater.com/openbaoidentitytokenroles/finalizers`: `update`
- Bao token must have `update` / `read` / `delete` on `identity/oidc/role/*`.

---

## `OpenBaoAuthMethod`

Reconciles a CR to a bao auth-method mount at `sys/auth/<path>`.
Sibling of `OpenBaoSecretEngine` for the auth side: same enable /
tune / disable shape, different bao endpoint. Stamps the bao-side
mount accessor on `status.mountAccessor` so downstream CRs (notably
`OpenBaoGroupAlias`) can bind to it without a manual `bao auth list`
step.

### Sample

See [config/samples/security_v1alpha1_openbaoauthmethod.yaml](../config/samples/security_v1alpha1_openbaoauthmethod.yaml).

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoAuthMethod
metadata:
  name: tenant-oidc
  namespace: mto-extension-openbao-system
spec:
  path: oidc
  type: oidc
  description: Tenant OIDC auth mount
  config:
    defaultLeaseTtl: 1h
    maxLeaseTtl: 24h
```

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.path` | string | yes | — | Bao-side mount path (e.g. `oidc`, `jwt`, `cert`). |
| `spec.type` | enum | yes | — | Auth-method kind: `cert`, `jwt`, `oidc`, `kubernetes`, `approle`, `userpass`, `ldap`. Immutable on bao's side. |
| `spec.description` | string | no | — | Free-form mount description. |
| `spec.config.defaultLeaseTtl` | string | no | bao default | Bao duration. |
| `spec.config.maxLeaseTtl` | string | no | bao default | Bao duration. |
| `spec.config.listingVisibility` | enum | no | — | `unauth` or `hidden`. |
| `spec.openbaoNamespace` | string | no | `""` | X-Vault-Namespace target. |

### Status

| Field | Description |
|---|---|
| `status.conditions[Ready]` | Standard reasons. |
| `status.baoWritten` | True after first successful enable. |
| `status.lastWrittenBaoName` / `status.lastWrittenOpenBaoNamespace` | Identity tuple for rename cleanup. |
| `status.mountAccessor` | Bao-side mount accessor. Stamped on first reconcile and refreshed via `Backfill` on every no-drift read. |

### Operational notes

- **Type immutability.** Bao does not allow auth-method type to
  change in place. Editing `spec.type` on an existing mount surfaces
  as `Ready=False / Reason=InternalError`; delete and recreate to
  switch.
- **Enable vs tune.** The controller probes for an existing mount
  before write — routes to enable on missing, tune on present. Bao's
  POST `sys/auth` creates only; re-POST returns `400 "already in
  use"` (the wrapper swallows that as idempotent success on the
  first-write path).
- **Accessor backfill.** `status.mountAccessor` is repopulated on
  every no-drift read. A CR re-applied from manifest with no status
  picks up the accessor from the first matching read.
- **Collision tuple.** `(BaoPath, openbaoNamespace)`. Same path in
  different bao namespaces is not a collision.
- **kubernetes auth mount.** The operator's own `kubernetes` auth
  mount is enabled by `clusterauth` at startup with the narrow
  legacy `EnableAuthMount` API. Use `OpenBaoAuthMethod` for
  arbitrary auth mounts that downstream primitives need.

### RBAC

- `security.mto.stakater.com/openbaoauthmethods`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaoauthmethods/status`: `get, update, patch`
- `security.mto.stakater.com/openbaoauthmethods/finalizers`: `update`
- Bao token must have `update` / `read` / `delete` on `sys/auth/*`
  and `update` on `sys/mounts/auth/*/tune`.

---

## `OpenBaoCertAuthEngineConfig`

Reconciles a CR to the mount-level cert auth config at
`auth/<path>/config`. Pairs with an `OpenBaoAuthMethod` of
`type=cert` at the same path. **IsDeletable=false**: bao has no
DELETE endpoint here, so CR delete releases the finalizer without
touching bao.

### Sample

See [config/samples/security_v1alpha1_openbaocertauthengineconfig.yaml](../config/samples/security_v1alpha1_openbaocertauthengineconfig.yaml).

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.path` | string | yes | — | Cert auth mount path. |
| `spec.disableBinding` | bool | no | bao default | Turns off cert binding to a specific identity alias. |
| `spec.enableIdentityAliasMetadata` | bool | no | bao default | Copy cert subject + serial onto identity alias metadata. |
| `spec.ocspCacheSize` | int | no | bao default | OCSP response-cache entries. |
| `spec.ocspFailOpen` | bool | no | bao default | Treat unreachable OCSP as success. |
| `spec.ocspQueryAllServers` | bool | no | bao default | Query all OCSP responders in parallel. |
| `spec.openbaoNamespace` | string | no | `""` | X-Vault-Namespace target. |

### Status

Standard `Ready` condition + `lastWrittenBaoName` /
`lastWrittenOpenBaoNamespace` for rename tracking.

### Operational notes

- **Drift comparator.** Pointer fields with `nil` desired adopt
  bao's value (no drift). Pinning a value causes drift on diff.
- **Collision tuple.** `(spec.path, openbaoNamespace)`.

### RBAC

- `security.mto.stakater.com/openbaocertauthengineconfigs`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaocertauthengineconfigs/status`: `get, update, patch`
- `security.mto.stakater.com/openbaocertauthengineconfigs/finalizers`: `update`
- Bao token: `update` / `read` on `auth/<mount>/config`.

---

## `OpenBaoCertAuthEngineRole`

Reconciles a CR to a per-cert role at `auth/<path>/certs/<name>`.
Owns the trusted CA bundle plus the allow-list (SAN/CN patterns)
that gates which client certs successfully authenticate. The cert
bundle is sourced from a Kubernetes Secret; a Secret rotation
re-enqueues the CR via the Secret watch.

### Sample

See [config/samples/security_v1alpha1_openbaocertauthenginerole.yaml](../config/samples/security_v1alpha1_openbaocertauthenginerole.yaml).

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.path` | string | yes | — | Cert auth mount path. |
| `spec.name` | string | no | `metadata.name` | Bao-side cert entry name. |
| `spec.certificateRef` | object | yes | — | `{ name, namespace, key }` reference to a Secret holding the PEM bundle. `key` defaults to `ca.crt`. |
| `spec.displayName` | string | no | — | Free-form bao-side label. |
| `spec.allowedNames` | []string | no | — | Glob allow-list against SAN-or-CN. |
| `spec.allowedCommonNames` | []string | no | — | Restrict by Subject CN. |
| `spec.allowedDnsSans` | []string | no | — | Restrict by DNS SAN. |
| `spec.allowedEmailSans` | []string | no | — | Restrict by email SAN. |
| `spec.allowedUriSans` | []string | no | — | Restrict by URI SAN. |
| `spec.allowedOrganizations` | []string | no | — | Restrict by Subject O. |
| `spec.requiredExtensions` | []string | no | — | Required X.509 extension OIDs. |
| `spec.tokenPolicies` | []string | no | — | Bao policies granted on successful login. |
| `spec.tokenTtl` / `spec.tokenMaxTtl` / `spec.tokenPeriod` | string | no | bao default | Bao duration strings. |
| `spec.tokenBoundCidrs` | []string | no | — | Source-IP restriction for issued tokens. |

### Status

Standard plus `status.lastWrittenPath` and
`status.resolvedCertificate` (the PEM body resolved from the
Secret).

### Operational notes

- **Cert from a Secret.** The PEM bundle never appears in the CR
  spec. The controller watches Secrets and re-enqueues on rotation.
- **Drift comparator.** Slices sorted before compare. The cert
  body is compared against the resolved value.
- **Collision tuple.** `(spec.path, BaoName, openbaoNamespace)`.
  Same role name on a different mount or in a different bao
  namespace is not a collision.

### RBAC

- `security.mto.stakater.com/openbaocertauthengineroles`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaocertauthengineroles/status`: `get, update, patch`
- `security.mto.stakater.com/openbaocertauthengineroles/finalizers`: `update`
- `secrets`: `get, list, watch` (for cert-bundle resolution + rotation).
- Bao token: `update` / `read` / `delete` on `auth/<mount>/certs/*`.

---

## `OpenBaoJWTOIDCAuthEngineConfig`

Reconciles a CR to the mount-level config of a JWT or OIDC auth
method at `auth/<path>/config`. Pairs with an `OpenBaoAuthMethod`
of `type=jwt` or `type=oidc`. The OIDC client secret is read from a
Kubernetes Secret; the cleartext value never appears in the CR
spec. **IsDeletable=false**.

### Sample

See [config/samples/security_v1alpha1_openbaojwtoidcauthengineconfig.yaml](../config/samples/security_v1alpha1_openbaojwtoidcauthengineconfig.yaml).

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.path` | string | yes | — | JWT/OIDC auth mount path. |
| `spec.oidcDiscoveryUrl` | string | one-of | — | OIDC well-known discovery URL. One of `oidcDiscoveryUrl`, `jwksUrl`, `jwtValidationPubkeys` is required. |
| `spec.oidcDiscoveryCaPem` | string | no | — | Optional CA bundle for the discovery URL's TLS. |
| `spec.oidcClientId` | string | no | — | OAuth2 client_id. |
| `spec.oidcClientSecretRef` | object | no | — | `{ name, namespace, key }` Secret reference; `key` defaults to `oidcClientSecret`. |
| `spec.oidcResponseMode` | enum | no | bao default | `query` or `form_post`. |
| `spec.oidcResponseTypes` | []string | no | — | OIDC response_type list. |
| `spec.jwksUrl` | string | one-of | — | Static JWKS endpoint. |
| `spec.jwksCaPem` | string | no | — | Optional CA bundle for JWKS TLS. |
| `spec.jwtValidationPubkeys` | []string | one-of | — | Static PEM public keys. |
| `spec.jwtSupportedAlgs` | []string | no | bao default | Restrict accepted JWT algorithms. |
| `spec.boundIssuer` | string | no | — | Restrict accepted tokens by `iss` claim. |
| `spec.defaultRole` | string | no | — | Falls back when login doesn't pick a role. |

### Status

Standard plus `status.resolvedClientSecret` (cleartext from the
Secret; not user-settable).

### Operational notes

- **client_secret from a Secret.** Watched; rotations re-enqueue.
- **One of three validation modes.** `IsValid` rejects a config
  that gives bao no way to validate inbound tokens.
- **Collision tuple.** `(spec.path, openbaoNamespace)`.

### RBAC

- `security.mto.stakater.com/openbaojwtoidcauthengineconfigs`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaojwtoidcauthengineconfigs/status`: `get, update, patch`
- `security.mto.stakater.com/openbaojwtoidcauthengineconfigs/finalizers`: `update`
- `secrets`: `get, list, watch`.
- Bao token: `update` / `read` on `auth/<mount>/config`.

---

## `OpenBaoJWTOIDCAuthEngineRole`

Reconciles a CR to a JWT/OIDC role at `auth/<path>/role/<name>`.
Maps inbound JWT/OIDC claims (sub, email, groups, etc.) to bao
identity + policies. `roleType=oidc` requires
`allowedRedirectUris`.

### Sample

See [config/samples/security_v1alpha1_openbaojwtoidcauthenginerole.yaml](../config/samples/security_v1alpha1_openbaojwtoidcauthenginerole.yaml).

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.path` | string | yes | — | JWT/OIDC auth mount path. |
| `spec.name` | string | no | `metadata.name` | Bao role name. |
| `spec.roleType` | enum | yes | — | `jwt` or `oidc`. |
| `spec.userClaim` | string | yes | — | JWT claim used as identity entity name. |
| `spec.boundAudiences` | []string | no | — | Required for JWT roles when no boundIssuer; OIDC defaults to client_id. |
| `spec.boundSubject` | string | no | — | Restrict by `sub` claim. |
| `spec.boundClaimsType` | enum | no | bao default | `string` or `glob`. |
| `spec.groupsClaim` | string | no | — | JWT claim feeding bao identity groups. |
| `spec.claimMappings` | map[string]string | no | — | JWT claim → identity metadata. |
| `spec.oidcScopes` | []string | no | — | OIDC scopes requested on login. |
| `spec.allowedRedirectUris` | []string | yes (oidc) | — | OAuth2 redirect_uri allow-list. |
| `spec.tokenPolicies` | []string | no | — | Bao policies granted on success. |
| `spec.tokenTtl` / `spec.tokenMaxTtl` | string | no | bao default | Bao duration strings. |
| `spec.tokenBoundCidrs` | []string | no | — | Source-IP restriction. |

### Status

Standard plus `status.lastWrittenPath`.

### Operational notes

- **Drift comparator.** Slices sorted; map-shaped `claimMappings`
  via DeepEqual; TTLs adopt bao defaults when spec is empty.
- **Collision tuple.** `(spec.path, BaoName, openbaoNamespace)`.

### RBAC

- `security.mto.stakater.com/openbaojwtoidcauthengineroles`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaojwtoidcauthengineroles/status`: `get, update, patch`
- `security.mto.stakater.com/openbaojwtoidcauthengineroles/finalizers`: `update`
- Bao token: `update` / `read` / `delete` on `auth/<mount>/role/*`.

---

## `OpenBaoKubernetesAuthEngineConfig`

Reconciles a CR to the kubernetes auth-mount config at
`auth/<spec.path>/config`. Pairs with an `OpenBaoAuthMethod` of
`type=kubernetes` at the same path; the auth-method controller owns
mount lifecycle, this CRD only writes `/config`.

The token-reviewer JWT and the (optional) Kubernetes CA bundle are
sourced from Kubernetes Secrets via `spec.tokenReviewerJwtRef` and
`spec.kubernetesCaCertRef`. A Secret-watch re-enqueues the CR on
rotation, so the next reconcile re-writes the new value to bao.

`IsDeletable=false` — bao has no DELETE on `/config`, so CR delete
releases the finalizer without touching bao state.

### Sample

See [config/samples/security_v1alpha1_openbaokubernetesauthengineconfig.yaml](../config/samples/security_v1alpha1_openbaokubernetesauthengineconfig.yaml):

```yaml
apiVersion: security.mto.stakater.com/v1alpha1
kind: OpenBaoKubernetesAuthEngineConfig
metadata:
  name: tenant-k8s-auth
  namespace: mto-extension-openbao-system
spec:
  path: kubernetes
  kubernetesHost: https://kubernetes.default.svc:443
  tokenReviewerJwtRef:
    name: openbao-token-reviewer
    key: token
  kubernetesCaCertRef:
    name: openbao-token-reviewer
    key: ca.crt
  issuer: kubernetes/serviceaccount
```

### Spec fields

- `path` — bao auth-method mount path (required).
- `openbaoNamespace` — optional bao namespace.
- `kubernetesHost` — apiserver URL bao calls `TokenReview` against (required).
- `tokenReviewerJwtRef` — Secret holding the SA JWT bao presents to the apiserver. `key` defaults to `token`.
- `kubernetesCaCertRef` — Secret holding the PEM CA bundle. `key` defaults to `ca.crt`.
- `pemKeys` — optional list of PEM-encoded public keys for local SA-JWT verification (mutually-exclusive with the TokenReview flow).
- `issuer` — narrow accepted tokens to a specific `iss` claim. Defaults to bao's `kubernetes/serviceaccount`.
- `disableIssValidation` — skip JWT iss-claim validation (kind / minikube).
- `disableLocalCaJwt` — disable bao's pod-local CA + JWT defaulting.
- `useAnnotationsAsAliasMetadata` — propagate `vault.hashicorp.com/alias-metadata-` SA annotations onto the bao identity alias.

### Status

- `conditions[Ready]` — drives observability.
- `baoWritten`, `lastWrittenBaoName`, `lastWrittenOpenBaoNamespace` — last-good identity stamp.
- `resolvedTokenReviewerJwt`, `resolvedKubernetesCaCert` — resolved Secret values used for drift comparison. Same etcd-storage trade-off as `OpenBaoJWTOIDCAuthEngineConfig.status.resolvedClientSecret`.

### Operational notes

- **No DELETE on `/config`.** `IsDeletable=false`; CR delete leaves the bao mount config in place.
- **Drift on redacted JWT.** Bao redacts the JWT on read; the comparator only fires drift when both sides have a non-empty value, so a redacted echo is treated as no-drift.
- **Collision tuple.** `(spec.path, openbaoNamespace)`. Two CRs targeting the same auth mount in the same bao namespace collide; older `creationTimestamp` wins.
- **Parent mount.** Apply an `OpenBaoAuthMethod` (or `bao auth enable kubernetes`) at the same path first, otherwise bao 400s on the config write.

### RBAC

- `security.mto.stakater.com/openbaokubernetesauthengineconfigs`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaokubernetesauthengineconfigs/status`: `get, update, patch`
- `security.mto.stakater.com/openbaokubernetesauthengineconfigs/finalizers`: `update`
- `core/secrets`: `get, list, watch` (for the Secret-watch).
- Bao token: `update` / `read` on `auth/<mount>/config`.

### Watches

- `OpenBaoKubernetesAuthEngineConfig` itself (filtered by `GenerationChangedPredicate`).
- `Secret` watch — any change to a Secret named by `spec.tokenReviewerJwtRef` or `spec.kubernetesCaCertRef` re-enqueues the CR.

---

## `OpenBaoTransitKey`

Reconciles a CR to a single transit key at `<path>/keys/<name>` on a
pre-existing transit secret-engine mount.

The bao API splits the spec across two endpoints — `POST /keys/<name>`
on create and `POST /keys/<name>/config` for the mutable subset — so
the controller does the same split internally. Type, derived,
convergent encryption, and key size are immutable post-create on the
bao side; the controller surfaces an immutability mismatch as
`Ready=False reason=Invalid` rather than letting the drift loop retry
forever.

### Sample

See [config/samples/security_v1alpha1_openbaotransitkey.yaml](../config/samples/security_v1alpha1_openbaotransitkey.yaml).

### Spec fields

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `spec.path` | string | yes | `transit` | Parent transit secret-engine mount. |
| `spec.name` | string | yes | — | Bao key name. |
| `spec.openbaoNamespace` | string | no | — | `X-Vault-Namespace` target. |
| `spec.type` | enum | yes | `aes256-gcm96` | Algorithm. Immutable post-create. |
| `spec.keySize` | int (32–512) | no | bao default | Bytes for hmac keys; ignored otherwise. Immutable. |
| `spec.derived` | bool | no | bao default (false) | Per-context subkeys. Immutable. |
| `spec.convergentEncryption` | bool | no | bao default (false) | Same plaintext+context → same ciphertext. Requires `derived=true`. Immutable. |
| `spec.exportable` | bool | no | bao default (false) | Allow `/export`. **Mutable but one-way** on bao's side — once enabled, bao refuses to disable. |
| `spec.allowPlaintextBackup` | bool | no | bao default (false) | Same one-way semantics as `exportable`. |
| `spec.autoRotatePeriod` | string | no | — | Go duration (`720h`); `0` or empty disables. `30d` is not a Go duration unit — use hours. |
| `spec.deletionAllowed` | bool | no | bao default (false) | Gates `DELETE` on the bao side. CR delete with this unset/false surfaces `Ready=False reason=DeleteBlocked`. |
| `spec.minDecryptionVersion` | int | no | 0 | Floor for decrypt operations. |
| `spec.minEncryptionVersion` | int | no | 0 | Floor for encrypt operations. `0` = latest. |

### Status

Standard (`conditions`, `baoWritten`, `lastWrittenBaoName`,
`lastWrittenOpenBaoNamespace`) plus:

- `lastWrittenPath` — bao mount path the controller last wrote into.
  Drives rename cleanup when both `spec.name` and `spec.path` change in
  one edit.
- `latestVersion` — bao's current key version. Apps targeting a
  specific version pin against this field. Refreshed on every reconcile
  (≤5 min staleness).
- `creationTime` — bao-side key creation timestamp.
- `supportsEncryption` / `supportsDecryption` / `supportsSigning` /
  `supportsDerivation` — capability flags surfaced from bao on read.

### Operational notes

- **Two-phase write.** `BaoWrite` reads first to decide create-vs-config
  and to enforce post-create immutability; the create body carries the
  immutable fields, the follow-up `/config` call carries the mutable
  subset.
- **Drift comparator.** `auto_rotate_period` is normalized between the
  spec's Go-duration string and bao's int-seconds read shape. Spec
  fields left unset adopt bao's value rather than appearing as drift.
  Immutable-field divergence drives the comparator to `false` so the
  immutability check inside `BaoWrite` catches it as `ErrInvalidSpec`.
- **Delete gating.** Bao's own `deletion_allowed` flag is the canonical
  gate. CR-level `spec.deletionAllowed` is plumbed through to bao via
  the `/config` endpoint. Bao's 400 "deletion is not allowed" surfaces
  as `Ready=False reason=DeleteBlocked`; finalizer holds until the user
  flips `spec.deletionAllowed=true` and re-applies.
- **Rotation is not reconcile-driven.** `auto_rotate_period` is the
  bao-managed knob; explicit rotation via `transit/keys/<name>/rotate`
  is out of scope for this CRD. `status.latestVersion` reflects the
  rotated value on the next reconcile (≤5 min).
- **Collision tuple.** `(spec.path, BaoName, openbaoNamespace)`. Two
  CRs at the same key name on different mounts don't collide because
  the bao path differs.

### RBAC

- `security.mto.stakater.com/openbaotransitkeys`: `get, list, watch, update, patch`
- `security.mto.stakater.com/openbaotransitkeys/status`: `get, update, patch`
- `security.mto.stakater.com/openbaotransitkeys/finalizers`: `update`
- Bao token: `create` / `read` / `update` / `delete` on
  `<mount>/keys/<name>` and `<mount>/keys/<name>/config`.
