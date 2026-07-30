#!/usr/bin/env bash
set -euo pipefail

# ---- Inputs ----
OPENBAO_NS=${OPENBAO_NS:-openbao}
OPERATOR_NS=${OPERATOR_NS:-openbao-config-operator-system}
VAULT_ADDR=${VAULT_ADDR:-http://openbao.${OPENBAO_NS}.svc.cluster.local:8200}
VAULT_TOKEN=${VAULT_TOKEN:-root}
POLICY_NAME=${POLICY_NAME:-obx-e2e-manage}
POLICY_FILE=${POLICY_FILE:-test/policies/obx-e2e-manage.hcl}
SECRET_NAME=${SECRET_NAME:-mto-openbao-token}
SECRET_KEY=${SECRET_KEY:-token}
# Periodic token instead of a fixed-TTL one. Periodic tokens have no
# max_ttl; their period is the maximum interval allowed between
# renewals, and bao rolls the period forward on every renew call.
# For a long-running operator that's never expected to be re-bootstrapped,
# this is the right shape — a 1h TTL silently kills the operator's
# bao access exactly 60 minutes after `make deploy`. Default 168h (7d)
# is large enough that even an operator that never renews stays alive
# across normal dev sessions.
TOKEN_PERIOD=${TOKEN_PERIOD:-168h}

[ -f "$POLICY_FILE" ] || { echo "Policy file not found: $POLICY_FILE" >&2; exit 1; }

# kcurl runs curl inside the openbao namespace, attached to the same
# network the bao pod resolves over. --tty is intentionally omitted: it
# allocates a pseudo-terminal that wraps stdout in CR/LF and a TTY
# control-prefix, which then breaks the `jq` parse downstream when stdin
# is not actually a terminal (i.e. every CI run). Without --tty kubectl
# pipes the raw stdout cleanly. The awk strip removes any non-JSON
# prefix kubectl prepends ("If you don't see a command prompt..." etc.)
# and the sed drops the trailer ("pod \"curl\" deleted") that kubectl
# emits when --rm tears the pod down.
kcurl() {
  kubectl -n "${OPENBAO_NS}" run curl --image=curlimages/curl:8.10.1 \
    --restart=Never --rm -i --quiet -- \
    -sS -H "X-Vault-Token: ${VAULT_TOKEN}" -H "Content-Type: application/json" "$@"
}

kcurl_json() {
  kcurl "$@" | sed -E '/^pod ".*" deleted$/d' | awk '/^[{[]/{p=1} p'
}

kcurl_code() {
  kubectl -n "${OPENBAO_NS}" run curl --image=curlimages/curl:8.10.1 \
    --restart=Never --rm -i --quiet -- \
    -sS -o /dev/null -w "%{http_code}\n" \
    -H "X-Vault-Token: ${VAULT_TOKEN}" \
    -H "Content-Type: application/json" \
    --connect-timeout 2 --max-time 5 "$@" \
  | sed -n '1s/^\([0-9][0-9][0-9]\).*/\1/p'
}

# Authentication-less variant: used only for /v1/sys/health, which is
# unauthenticated and returns 472/473 if a token is sent against a
# sealed/standby instance.
kcurl_code_anon() {
  kubectl -n "${OPENBAO_NS}" run curl --image=curlimages/curl:8.10.1 \
    --restart=Never --rm -i --quiet -- \
    -sS -o /dev/null -w "%{http_code}\n" \
    --connect-timeout 2 --max-time 5 "$@" \
  | sed -n '1s/^\([0-9][0-9][0-9]\).*/\1/p'
}

echo ">> Waiting for OpenBao to be reachable at ${VAULT_ADDR}"
ok=0
for _ in {1..90}; do
  code=$(kcurl_code_anon "${VAULT_ADDR}/v1/sys/health" 2>/dev/null || echo 000)
  case "$code" in
    200|429|472|473) echo "   health OK (${code})"; ok=1; break ;;
    *)               echo "   waiting... (${code})"; sleep 2 ;;
  esac
done
[ "$ok" -eq 1 ] || { echo "OpenBao health never became OK" >&2; exit 1; }

echo ">> Verifying admin token"
kcurl_json "${VAULT_ADDR}/v1/auth/token/lookup-self" >/dev/null

echo ">> Tuning 'secret/' to KV v2"
# Verify the tune call actually landed: bao returns 204 on success. The
# previous "|| true" hid every failure (auth, network, malformed body) —
# the suite would then run against a KV-v1 mount and most kv-v2 specs
# would silently fail at write time with a confusing 404 on /data/<path>.
TUNE_CODE=$(kcurl_code -X POST "${VAULT_ADDR}/v1/sys/mounts/secret/tune" \
  --data '{"options":{"version":"2"}}')
case "${TUNE_CODE}" in
  204|200) ;;
  *) echo "Failed to tune secret/ to KV v2 (HTTP ${TUNE_CODE})" >&2; exit 1 ;;
esac

echo ">> Writing policy '${POLICY_NAME}' from ${POLICY_FILE}"
POLICY_BODY=$(jq -n --rawfile policy "${POLICY_FILE}" '{policy:$policy}')
kcurl_json -X PUT "${VAULT_ADDR}/v1/sys/policies/acl/${POLICY_NAME}" --data "${POLICY_BODY}" >/dev/null

# Verify the policy actually landed. Token mint will silently produce a
# token bound to a non-existent policy if we skip this check, and that
# token then 403s on every operator call.
READ_POLICY=$(kcurl_code "${VAULT_ADDR}/v1/sys/policies/acl/${POLICY_NAME}" 2>/dev/null || echo 000)
[ "${READ_POLICY}" = "200" ] || { echo "Policy ${POLICY_NAME} failed to install (HTTP ${READ_POLICY})" >&2; exit 1; }

echo ">> Creating periodic token bound to ${POLICY_NAME} (period=${TOKEN_PERIOD})"
TOKEN_REQUEST=$(jq -n \
  --argjson policies "[\"${POLICY_NAME}\"]" \
  --arg period "${TOKEN_PERIOD}" \
  --argjson renewable true \
  '{policies:$policies,period:$period,renewable:$renewable}')
TOKEN=$(kcurl_json -X POST "${VAULT_ADDR}/v1/auth/token/create" --data "${TOKEN_REQUEST}" \
  | jq -r '.auth.client_token')
[ -n "${TOKEN}" ] && [ "${TOKEN}" != "null" ] || { echo "Failed to create token" >&2; exit 1; }

# Verify the minted token works before storing it. Catches the silent
# "policy didn't exist at mint time" failure mode end-to-end. Uses the
# script-local VAULT_TOKEN slot temporarily so kcurl_code picks up the
# new credential.
VERIFY_CODE=$(VAULT_TOKEN="${TOKEN}" kcurl_code "${VAULT_ADDR}/v1/auth/token/lookup-self")
[ "${VERIFY_CODE}" = "200" ] || { echo "Minted token cannot lookup-self (HTTP ${VERIFY_CODE})" >&2; exit 1; }

echo ">> Storing token in ${OPERATOR_NS}/${SECRET_NAME}.${SECRET_KEY}"
kubectl create ns "${OPERATOR_NS}" --dry-run=client -o yaml | kubectl apply -f -
kubectl -n "${OPERATOR_NS}" delete secret "${SECRET_NAME}" --ignore-not-found >/dev/null 2>&1 || true
kubectl -n "${OPERATOR_NS}" create secret generic "${SECRET_NAME}" --from-literal="${SECRET_KEY}=${TOKEN}"

echo ">> Done."
