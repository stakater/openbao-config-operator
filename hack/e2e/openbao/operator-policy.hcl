# operator-manage — the least-privilege policy for the openbao-config-operator
# operator's own bao identity. Derived from the operator's API surface
# (internal/client Client interface); test/policies/obx-e2e-manage.hcl is the
# e2e-harness superset of this file.
#
# sudo appears only on sys/auth (bao's root-protected path for enabling and
# disabling auth mounts). The full e2e suite passes with sudo absent from
# sys/mounts, sys/namespaces, sys/policies/acl, and the PKI generate paths —
# do not re-add it there without a failing call that proves the need.
#
# The deny stanzas at the bottom are the anti-lockout guard: the operator
# manages sys/auth/* and sys/policies/acl/* for tenants, and without them a
# user-authored CR could reach the operator's own login mount or its own
# policy. Deny beats every allow in bao policy evaluation, so these win over
# the grants above them. auth/k8s-operator/login stays reachable — login is
# an unauthenticated path, unaffected by this token's policy.

# mounts & auth listing
path "sys/mounts"            { capabilities = ["read","list"] }
path "sys/mounts/*"          { capabilities = ["create","read","update","delete","list"] }
path "sys/auth"              { capabilities = ["read","list","sudo","create","update"] }
path "sys/auth/*"            { capabilities = ["read","list","sudo","create","update","delete"] }

# manage OpenBao namespaces
path "sys/namespaces"        { capabilities = ["read","list"] }
path "sys/namespaces/*"      { capabilities = ["create","read","update","delete","list"] }

# manage ACL policies
path "sys/policies/acl"      { capabilities = ["read","list"] }
path "sys/policies/acl/*"    { capabilities = ["create","update","read","list","delete"] }

# manage kubernetes / jwt / oidc auth (per-mount; spec.path is user-supplied
# on the auth primitives, so wildcards cover non-default mounts)
path "auth/+/config"         { capabilities = ["create","read","update","delete","list"] }
path "auth/+/role"           { capabilities = ["read","list"] }
path "auth/+/role/*"         { capabilities = ["create","read","update","delete","list"] }

# cert auth method stores trusted CAs at /auth/<mount>/certs/<name>
path "auth/+/certs"          { capabilities = ["read","list"] }
path "auth/+/certs/*"        { capabilities = ["create","read","update","delete","list"] }

# manage identity store (groups, group-aliases, OIDC roles/keys)
path "identity/group"            { capabilities = ["create","update"] }
path "identity/group/name/*"     { capabilities = ["create","read","update","delete","list"] }
path "identity/group/id"         { capabilities = ["list"] }
path "identity/group/id/*"       { capabilities = ["create","read","update","delete","list"] }
path "identity/group-alias"      { capabilities = ["create","update"] }
path "identity/group-alias/id"   { capabilities = ["list"] }
path "identity/group-alias/id/*" { capabilities = ["create","read","update","delete","list"] }
path "identity/oidc/role/*"      { capabilities = ["create","read","update","delete","list"] }
path "identity/oidc/key/*"       { capabilities = ["create","read","update","delete","list"] }

# manage transit keys (per-mount; spec.path is user-supplied)
path "+/keys"               { capabilities = ["read","list"] }
path "+/keys/*"             { capabilities = ["create","read","update","delete","list"] }

# manage PKI engines (per-mount; spec.path is user-supplied)
path "+/root/generate/*"    { capabilities = ["create","read","update"] }
path "+/root/sign-intermediate" { capabilities = ["create","update"] }
path "+/intermediate/generate/*" { capabilities = ["create","update"] }
path "+/intermediate/set-signed" { capabilities = ["create","update"] }
path "+/cert/*"             { capabilities = ["read"] }
path "+/roles"              { capabilities = ["read","list"] }
path "+/roles/*"            { capabilities = ["create","read","update","delete","list"] }
path "+/issuers"            { capabilities = ["read","list"] }
path "+/issuers/*"          { capabilities = ["create","read","update","delete","list"] }
path "+/config/*"           { capabilities = ["create","read","update","delete","list"] }

# The same set of permissions inside any direct child OpenBao namespace.
# The leading `+` matches one bao-namespace segment; primitives carrying
# spec.openbaoNamespace route their calls there via X-Vault-Namespace, and
# a root-only policy returns 403 for them.
path "+/sys/mounts"          { capabilities = ["read","list"] }
path "+/sys/mounts/*"        { capabilities = ["create","read","update","delete","list"] }
path "+/sys/auth"            { capabilities = ["read","list","sudo","create","update"] }
path "+/sys/auth/*"          { capabilities = ["read","list","sudo","create","update","delete"] }
path "+/sys/policies/acl"    { capabilities = ["read","list"] }
path "+/sys/policies/acl/*"  { capabilities = ["create","update","read","list","delete"] }
path "+/auth/+/config"       { capabilities = ["create","read","update","delete","list"] }
path "+/auth/+/role"         { capabilities = ["read","list"] }
path "+/auth/+/role/*"       { capabilities = ["create","read","update","delete","list"] }
path "+/auth/+/certs"        { capabilities = ["read","list"] }
path "+/auth/+/certs/*"      { capabilities = ["create","read","update","delete","list"] }
path "+/identity/group"            { capabilities = ["create","update"] }
path "+/identity/group/name/*"     { capabilities = ["create","read","update","delete","list"] }
path "+/identity/group/id"         { capabilities = ["list"] }
path "+/identity/group/id/*"       { capabilities = ["create","read","update","delete","list"] }
path "+/identity/group-alias"      { capabilities = ["create","update"] }
path "+/identity/group-alias/id"   { capabilities = ["list"] }
path "+/identity/group-alias/id/*" { capabilities = ["create","read","update","delete","list"] }
path "+/identity/oidc/role/*"      { capabilities = ["create","read","update","delete","list"] }
path "+/identity/oidc/key/*"       { capabilities = ["create","read","update","delete","list"] }
path "+/+/keys"              { capabilities = ["read","list"] }
path "+/+/keys/*"            { capabilities = ["create","read","update","delete","list"] }
path "+/+/root/generate/*"   { capabilities = ["create","read","update"] }
path "+/+/root/sign-intermediate" { capabilities = ["create","update"] }
path "+/+/intermediate/generate/*" { capabilities = ["create","update"] }
path "+/+/intermediate/set-signed" { capabilities = ["create","update"] }
path "+/+/cert/*"            { capabilities = ["read"] }
path "+/+/roles"             { capabilities = ["read","list"] }
path "+/+/roles/*"           { capabilities = ["create","read","update","delete","list"] }
path "+/+/issuers"           { capabilities = ["read","list"] }
path "+/+/issuers/*"         { capabilities = ["create","read","update","delete","list"] }
path "+/+/config/*"          { capabilities = ["create","read","update","delete","list"] }

# ---- anti-lockout guard: the operator's own identity ----
# Deny wins over every allow above. No CR reconciled with this token can
# delete, tune, or reconfigure the mount/role the operator logs in through.
path "sys/auth/k8s-operator"      { capabilities = ["deny"] }
path "sys/auth/k8s-operator/*"    { capabilities = ["deny"] }
path "auth/k8s-operator/config"   { capabilities = ["deny"] }
path "auth/k8s-operator/role"     { capabilities = ["deny"] }
path "auth/k8s-operator/role/*"   { capabilities = ["deny"] }

# ...nor these two policies. bao does not bound a policy's contents by what
# the writer holds, so a CR claiming one of these names picks the operator's
# own permissions outright, and deleting that CR strips them. Reserved names:
# the sys/policies/acl/* grant above covers every other policy.
path "sys/policies/acl/operator-manage" { capabilities = ["deny"] }
path "sys/policies/acl/obx-bootstrap"   { capabilities = ["deny"] }
