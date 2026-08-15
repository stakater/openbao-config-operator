#!/usr/bin/env bash
set -euo pipefail

# Bootstraps the operator's own bao identity so the operator process never
# holds a stored credential: it logs in with its ServiceAccount at
# auth/k8s-operator/login and gets a short-lived token bound to the
# operator-manage policy.
#
# Idempotent — safe to re-run any time (repair, policy update on upgrade).
#
# Run with a privileged token. The recommended flow keeps root down to two
# commands (see bootstrap-policy.hcl):
#   VAULT_TOKEN=<root> bao policy write obx-bootstrap hack/e2e/openbao/bootstrap-policy.hcl
#   VAULT_TOKEN=$(VAULT_TOKEN=<root> bao token create -field=token -policy=obx-bootstrap -ttl=20m) \
#     ./hack/e2e/openbao/bootstrap_operator_auth.sh
# For dev/kind (openbao in dev mode) plain VAULT_TOKEN=root works too.

# ---- Inputs ----
OPENBAO_NS=${OPENBAO_NS:-openbao}
OPERATOR_NS=${OPERATOR_NS:-openbao-config-operator-system}
VAULT_ADDR=${VAULT_ADDR:-http://openbao.${OPENBAO_NS}.svc.cluster.local:8200}
VAULT_TOKEN=${VAULT_TOKEN:-root}
AUTH_MOUNT=${AUTH_MOUNT:-k8s-operator}
OPERATOR_ROLE=${OPERATOR_ROLE:-openbao-config-operator}
OPERATOR_SA=${OPERATOR_SA:-openbao-config-operator-controller-manager}
POLICY_NAME=${POLICY_NAME:-operator-manage}
POLICY_FILE=${POLICY_FILE:-hack/e2e/openbao/operator-policy.hcl}
TOKEN_TTL=${TOKEN_TTL:-1h}
AUDIENCE=${AUDIENCE:-openbao}
REVIEWER_SA=${REVIEWER_SA:-bao-token-reviewer}
# Namespace holding the identity bao presents to the apiserver for TokenReview.
# Independent of OPERATOR_NS: bao's reviewer is not the operator, and keeping it
# in a fixed namespace means bao's auth config survives the operator moving.
# Defaults to OPERATOR_NS so kind stays a single-input setup. On GitOps installs
# the reviewer is usually chart-managed (the bootstrap chart's
# 10-token-reviewer.yaml) — set REVIEWER_NS to that chart's namespace, or this
# script creates a second identity that the cluster-scoped auth-delegator
# binding does not name, and every login fails 403 "permission denied".
REVIEWER_NS=${REVIEWER_NS:-$OPERATOR_NS}

[ -f "$POLICY_FILE" ] || { echo "Policy file not found: $POLICY_FILE" >&2; exit 1; }

# kcurl runs curl inside the openbao namespace, attached to the same network
# the bao pod resolves over. Same TTY/trailer quirks as
# provision_credentials.sh — see the comments there.
kcurl() {
  kubectl -n "${OPENBAO_NS}" run "curl-$$-${RANDOM}" --image=curlimages/curl:8.10.1 \
    --restart=Never --rm -i --quiet -- \
    -sS -H "X-Vault-Token: ${VAULT_TOKEN}" -H "Content-Type: application/json" "$@"
}

kcurl_json() {
  kcurl "$@" | sed -E '/^pod ".*" deleted$/d' | awk '/^[{[]/{p=1} p'
}

# Status code on stdout, response body in LAST_BODY. Both from one request:
# re-issuing to fetch the body would be a different request, and with several
# nodes behind VAULT_ADDR it can land elsewhere and describe a different
# failure than the one being reported. A bare "HTTP 500" sends the reader
# looking for the wrong problem, so every caller reports the body too.
LAST_BODY=""
kcurl_code() {
  local out
  out=$(kubectl -n "${OPENBAO_NS}" run "curl-$$-${RANDOM}" --image=curlimages/curl:8.10.1 \
    --restart=Never --rm -i --quiet -- \
    -sS -w '\n%{http_code}' \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    --connect-timeout 2 --max-time 10 "$@" \
    | sed -E '/^pod ".*" deleted$/d')
  LAST_BODY=$(printf '%s\n' "${out}" | sed '$d')
  printf '%s\n' "${out}" | tail -n1 | sed -n 's/^\([0-9][0-9][0-9]\)$/\1/p'
}

# Reports an unexpected status with bao's own words, and names the one cause
# that is neither a bad request nor a broken policy: a request answered by a
# standby that cannot reach the leader. That is an OpenBao clustering problem,
# not a bootstrap one, and it is indistinguishable from a real failure until
# you read the body.
bao_fail() {
  echo "$1 (HTTP ${2:-no response})" >&2
  if [ -n "${LAST_BODY}" ]; then
    printf '%s\n' "${LAST_BODY}" | sed 's/^/  /' >&2
  fi
  case "${LAST_BODY}" in
    *"active cluster node not found"*|*"local node not active"*)
      cat >&2 <<EOF

  VAULT_ADDR resolved to a standby that could not forward to the leader. Point
  it at the active-only Service (openbao-active) rather than the round-robin
  one. If that Service has no endpoints, OpenBao is missing its
  service_registration "kubernetes" stanza, so nothing ever labels the leader —
  fix that on the OpenBao side, or this script and the operator will both fail
  intermittently depending on which node answers.
EOF
      ;;
  esac
  exit 1
}

# Sends no X-Vault-Token, matching the operator's own login request: login is
# an unauthenticated path, and the bootstrap token's grants are irrelevant to
# whether the operator can get in.
kcurl_anon() {
  kubectl -n "${OPENBAO_NS}" run "curl-$$-${RANDOM}" --image=curlimages/curl:8.10.1 \
    --restart=Never --rm -i --quiet -- \
    -sS -H "Content-Type: application/json" "$@" \
  | sed -E '/^pod ".*" deleted$/d' | awk '/^[{[]/{p=1} p'
}

echo ">> Verifying bootstrap token"
kcurl_json "${VAULT_ADDR}/v1/auth/token/lookup-self" >/dev/null

echo ">> Ensuring token-reviewer identity (${REVIEWER_NS}/${REVIEWER_SA})"
# The auth-delegator binding is cluster-scoped and singular: one object, one
# subject list, no namespace in its name. If something else already owns it
# (the bootstrap chart, via ArgoCD) and names an SA in another namespace, then
# applying our own subject either loses to the next sync or steals the grant
# from the identity bao is actually configured with. Either way login fails
# 403 "permission denied" with nothing in this script's output to explain it,
# so refuse rather than write.
EXISTING_REVIEWER_NS=$(kubectl get clusterrolebinding "${REVIEWER_SA}-auth-delegator" \
  -o jsonpath='{.subjects[0].namespace}' 2>/dev/null || true)
if [ -n "${EXISTING_REVIEWER_NS}" ] && [ "${EXISTING_REVIEWER_NS}" != "${REVIEWER_NS}" ]; then
  cat >&2 <<EOF
ClusterRoleBinding ${REVIEWER_SA}-auth-delegator already grants system:auth-delegator
to ${EXISTING_REVIEWER_NS}/${REVIEWER_SA}, not ${REVIEWER_NS}/${REVIEWER_SA}.

It is cluster-scoped, so there is only one, and on a GitOps install its owner
reverts any change made here. Re-run against the existing identity:

  REVIEWER_NS=${EXISTING_REVIEWER_NS} $0

The reviewer namespace is independent of the operator's — it is only the
identity bao uses to call TokenReview — so this is normally the right answer.
EOF
  exit 1
fi

# The SA whose JWT bao presents to the apiserver for TokenReview, plus the
# auth-delegator grant and a long-lived token Secret. Mirrors the bootstrap
# chart's 10-token-reviewer.yaml so this script is self-sufficient on kind.
# Create-if-missing rather than apply: on MTO-managed clusters an admission
# webhook forbids updates to managed-prefix namespaces, and an apply against
# an existing namespace counts as an update.
kubectl get ns "${REVIEWER_NS}" >/dev/null 2>&1 || kubectl create ns "${REVIEWER_NS}"
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${REVIEWER_SA}
  namespace: ${REVIEWER_NS}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${REVIEWER_SA}-auth-delegator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:auth-delegator
subjects:
  - kind: ServiceAccount
    name: ${REVIEWER_SA}
    namespace: ${REVIEWER_NS}
---
apiVersion: v1
kind: Secret
metadata:
  name: ${REVIEWER_SA}
  namespace: ${REVIEWER_NS}
  annotations:
    kubernetes.io/service-account.name: ${REVIEWER_SA}
type: kubernetes.io/service-account-token
EOF

echo ">> Waiting for the reviewer token to materialize"
REVIEWER_JWT=""
for _ in $(seq 1 30); do
  REVIEWER_JWT=$(kubectl -n "${REVIEWER_NS}" get secret "${REVIEWER_SA}" \
    -o jsonpath='{.data.token}' 2>/dev/null | base64 -d || true)
  [ -n "${REVIEWER_JWT}" ] && break
  sleep 2
done
[ -n "${REVIEWER_JWT}" ] || { echo "Reviewer token never materialized" >&2; exit 1; }

echo ">> Enabling kubernetes auth at auth/${AUTH_MOUNT}"
ENABLE_CODE=$(kcurl_code -X POST "${VAULT_ADDR}/v1/sys/auth/${AUTH_MOUNT}" \
  --data '{"type":"kubernetes","description":"operator self-login (bootstrap-owned; do not manage via CRs)"}')
case "${ENABLE_CODE}" in
  200|204) ;;
  400) echo "   already enabled (400 path in use) — continuing" ;;
  *) bao_fail "Failed to enable auth mount" "${ENABLE_CODE}" ;;
esac

echo ">> Writing auth/${AUTH_MOUNT}/config"
CONFIG_BODY=$(jq -n --arg jwt "${REVIEWER_JWT}" \
  '{kubernetes_host:"https://kubernetes.default.svc", token_reviewer_jwt:$jwt}')
CONFIG_CODE=$(kcurl_code -X POST "${VAULT_ADDR}/v1/auth/${AUTH_MOUNT}/config" --data "${CONFIG_BODY}")
case "${CONFIG_CODE}" in
  200|204) ;;
  *) bao_fail "Failed to write auth config" "${CONFIG_CODE}" ;;
esac

echo ">> Writing policy '${POLICY_NAME}' from ${POLICY_FILE}"
POLICY_BODY=$(jq -n --rawfile policy "${POLICY_FILE}" '{policy:$policy}')
kcurl_json -X PUT "${VAULT_ADDR}/v1/sys/policies/acl/${POLICY_NAME}" --data "${POLICY_BODY}" >/dev/null
READ_POLICY=$(kcurl_code "${VAULT_ADDR}/v1/sys/policies/acl/${POLICY_NAME}" 2>/dev/null || echo 000)
[ "${READ_POLICY}" = "200" ] || bao_fail "Policy ${POLICY_NAME} failed to install" "${READ_POLICY}"

echo ">> Writing role '${OPERATOR_ROLE}' bound to ${OPERATOR_NS}/${OPERATOR_SA} (ttl=${TOKEN_TTL}, audience=${AUDIENCE})"
ROLE_BODY=$(jq -n \
  --arg sa "${OPERATOR_SA}" \
  --arg ns "${OPERATOR_NS}" \
  --arg policy "${POLICY_NAME}" \
  --arg ttl "${TOKEN_TTL}" \
  --arg aud "${AUDIENCE}" \
  '{bound_service_account_names:[$sa], bound_service_account_namespaces:[$ns],
    token_policies:[$policy], token_ttl:$ttl, audience:$aud}')
ROLE_CODE=$(kcurl_code -X POST "${VAULT_ADDR}/v1/auth/${AUTH_MOUNT}/role/${OPERATOR_ROLE}" --data "${ROLE_BODY}")
case "${ROLE_CODE}" in
  200|204) ;;
  *) bao_fail "Failed to write role" "${ROLE_CODE}" ;;
esac

READ_ROLE=$(kcurl_code "${VAULT_ADDR}/v1/auth/${AUTH_MOUNT}/role/${OPERATOR_ROLE}")
[ "${READ_ROLE}" = "200" ] || bao_fail "Role failed to install" "${READ_ROLE}"

# Every value written above is half of a pair whose other half lives in the
# operator Deployment: the role's audience and bound SA against the projected
# token volume and serviceAccountName, and AUTH_MOUNT/OPERATOR_ROLE against
# BAO_AUTH_MOUNT/BAO_AUTH_ROLE. A readable role proves none of that.
#
# So the probe below takes every input from the Deployment, never from this
# script's own variables — reusing them would make it agree with itself and
# pass through exactly the mismatch it exists to catch. A login is also the
# only check that exercises the reviewer JWT and bao's TokenReview access.
# Costs one operator token, which expires after its TTL (the bootstrap policy
# grants no revoke).
echo ">> Verifying the operator can log in"
DEPLOY_JSON=$(kubectl -n "${OPERATOR_NS}" get deploy -l control-plane=controller-manager \
  -o json 2>/dev/null | jq -c '.items[0] // empty' 2>/dev/null || true)
DEPLOY_METHOD=$(printf '%s' "${DEPLOY_JSON}" | jq -r \
  '.spec.template.spec.containers[0].env[]? | select(.name=="BAO_AUTH_METHOD") | .value' 2>/dev/null || true)

if [ -z "${DEPLOY_JSON}" ]; then
  echo "   SKIPPED — no controller-manager Deployment in ${OPERATOR_NS} yet."
  echo "   Re-run this script once the operator is deployed to verify the login."
elif [ "${DEPLOY_METHOD}" != "kubernetes" ]; then
  echo "   SKIPPED — the Deployment runs BAO_AUTH_METHOD=${DEPLOY_METHOD:-token},"
  echo "   so it does not use this login path."
else
  # Read the pod's half of each pair. Mount and role fall back to the client's
  # own defaults, which apply when the Deployment leaves the env unset.
  DEP_SA=$(printf '%s' "${DEPLOY_JSON}" | jq -r '.spec.template.spec.serviceAccountName // empty')
  DEP_AUD=$(printf '%s' "${DEPLOY_JSON}" | jq -r \
    '[.spec.template.spec.volumes[]?.projected.sources[]?.serviceAccountToken.audience
      | select(. != null and . != "")] | first // empty')
  DEP_MOUNT=$(printf '%s' "${DEPLOY_JSON}" | jq -r \
    '.spec.template.spec.containers[0].env[]? | select(.name=="BAO_AUTH_MOUNT") | .value' || true)
  DEP_ROLE=$(printf '%s' "${DEPLOY_JSON}" | jq -r \
    '.spec.template.spec.containers[0].env[]? | select(.name=="BAO_AUTH_ROLE") | .value' || true)
  DEP_MOUNT=${DEP_MOUNT:-k8s-operator}
  DEP_ROLE=${DEP_ROLE:-openbao-config-operator}

  [ -n "${DEP_AUD}" ] || {
    echo "The Deployment projects no audience-bound ServiceAccount token, so its" >&2
    echo "JWT would also be valid against the API server. Expected a projected" >&2
    echo "volume with serviceAccountToken.audience set." >&2
    exit 1
  }

  PROBE_JWT=$(kubectl -n "${OPERATOR_NS}" create token "${DEP_SA}" \
    --audience="${DEP_AUD}" --duration=10m 2>/dev/null || true)
  [ -n "${PROBE_JWT}" ] || {
    echo "Could not mint a ServiceAccount token for ${OPERATOR_NS}/${DEP_SA}" >&2
    exit 1
  }
  PROBE_BODY=$(jq -n --arg role "${DEP_ROLE}" --arg jwt "${PROBE_JWT}" '{role:$role, jwt:$jwt}')
  PROBE_OUT=$(kcurl_anon -X POST "${VAULT_ADDR}/v1/auth/${DEP_MOUNT}/login" \
    --data "${PROBE_BODY}" || true)
  PROBE_POLICIES=$(printf '%s' "${PROBE_OUT}" | jq -rc '.auth.token_policies // empty' 2>/dev/null || true)
  if [ -z "${PROBE_POLICIES}" ]; then
    echo "Login FAILED — the mount, policy and role were written, but the operator" >&2
    echo "cannot authenticate with them. bao said:" >&2
    printf '%s' "${PROBE_OUT}" | jq -r '.errors[]?' 2>/dev/null | sed 's/^/  /' >&2 \
      || printf '  %s\n' "${PROBE_OUT}" >&2
    cat >&2 <<EOF
                  written here      operator Deployment
  audience        ${AUDIENCE}       ${DEP_AUD}
  serviceaccount  ${OPERATOR_SA}    ${DEP_SA}
  auth mount      ${AUTH_MOUNT}     ${DEP_MOUNT}
  role            ${OPERATOR_ROLE}  ${DEP_ROLE}
EOF
    exit 1
  fi
  echo "   OK — ${OPERATOR_NS}/${DEP_SA} logged in at auth/${DEP_MOUNT}/login, policies: ${PROBE_POLICIES}"
fi

echo ">> Done. The operator authenticates at auth/${AUTH_MOUNT}/login with role '${OPERATOR_ROLE}'."
echo "   No token Secret is created; the bootstrap token can now expire or be revoked."
