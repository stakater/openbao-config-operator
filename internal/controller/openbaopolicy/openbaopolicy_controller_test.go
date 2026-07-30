package openbaopolicy

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// ---- fake bao ----

// fakeBao implements baoclient.Client with in-memory policy state, keyed
// by (openbaoNamespace, name) to model bao's namespace isolation. The
// OpenBaoPolicyController doesn't touch k8s-auth roles, so this fake
// stubs those methods to return success without state.
type fakeBao struct {
	// policies keyed as "<openbaoNs>|<name>" so the same name in different
	// namespaces stays separate (matches bao's actual storage).
	policies map[string]string

	// Error injection.
	upsertErr error
	getErr    error
	deleteErr error

	// Call counters.
	upserts, gets, deletes int

	// Last namespace observed per call category — exposed for tests that
	// assert the X-Vault-Namespace plumbing.
	lastUpsertNS string
	lastGetNS    string
	lastDeleteNS string
}

func newFakeBao() *fakeBao {
	return &fakeBao{policies: map[string]string{}}
}

func policyKey(ns, name string) string { return ns + "|" + name }

// extractNS resolves the namespace passed via WithNamespace, or "" when no
// option is supplied. Mirrors what the real bao client does (X-Vault-Namespace
// header) so the fake can key its in-memory store by the same tuple bao does.
func extractNS(opts []baoclient.CallOption) string {
	return baoclient.NamespaceFromOpts(opts)
}

func (f *fakeBao) CheckKVv2Mount(ctx context.Context, mount string, opts ...baoclient.CallOption) (bool, error) {
	return true, nil
}

func (f *fakeBao) UpsertPolicy(ctx context.Context, name, rules string, opts ...baoclient.CallOption) error {
	f.upserts++
	f.lastUpsertNS = extractNS(opts)
	if f.upsertErr != nil {
		return f.upsertErr
	}
	f.policies[policyKey(f.lastUpsertNS, name)] = rules
	return nil
}
func (f *fakeBao) GetPolicy(ctx context.Context, name string, opts ...baoclient.CallOption) (string, error) {
	f.gets++
	f.lastGetNS = extractNS(opts)
	if f.getErr != nil {
		return "", f.getErr
	}
	body, ok := f.policies[policyKey(f.lastGetNS, name)]
	if !ok {
		return "", baoclient.ErrNotFound
	}
	return body, nil
}
func (f *fakeBao) DeletePolicy(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	f.deletes++
	f.lastDeleteNS = extractNS(opts)
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.policies, policyKey(f.lastDeleteNS, name))
	return nil
}

// K8s role + mount methods are unused by the OpenBaoPolicy controller;
// stub them so the fake satisfies the full baoclient.Client interface.
func (f *fakeBao) UpsertK8sRole(ctx context.Context, authMount, roleName string, spec baoclient.K8sRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetK8sRole(ctx context.Context, authMount, roleName string, opts ...baoclient.CallOption) (*baoclient.K8sRole, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteK8sRole(ctx context.Context, authMount, roleName string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) EnableSecretEngine(ctx context.Context, mount string, spec baoclient.SecretEngineMountSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) TuneSecretEngine(ctx context.Context, mount string, spec baoclient.SecretEngineMountSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetSecretEngineMount(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.SecretEngineMount, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DisableSecretEngineMount(ctx context.Context, mount string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) DisableAuthMount(ctx context.Context, mount string, opts ...baoclient.CallOption) error {
	return nil
}

// AuthMethod stubs — this controller does not exercise sys/auth tune.
func (f *fakeBao) EnableAuthMethod(ctx context.Context, mount string, spec baoclient.AuthMethodMountSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) TuneAuthMethod(ctx context.Context, mount string, spec baoclient.AuthMethodMountSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetAuthMethod(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.AuthMethodMount, error) {
	return nil, baoclient.ErrNotFound
}

func (f *fakeBao) CreateNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.Namespace, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteNamespace(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}

func (f *fakeBao) GenerateRootPKI(ctx context.Context, mount string, in baoclient.PKIRootGenerateInput, opts ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	return nil, baoclient.ErrNotFound
}

// Intermediate-CA stubs — these controllers do not exercise the intermediate flow.
func (f *fakeBao) GenerateIntermediateCSR(ctx context.Context, mount string, in baoclient.PKIIntermediateGenerateInput, opts ...baoclient.CallOption) (string, error) {
	return "", baoclient.ErrNotFound
}
func (f *fakeBao) SignIntermediate(ctx context.Context, rootMount, csr string, in baoclient.PKISignIntermediateInput, opts ...baoclient.CallOption) (string, error) {
	return "", baoclient.ErrNotFound
}
func (f *fakeBao) SetSignedIntermediate(ctx context.Context, mount, certificate string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadPKICA(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WritePKIURLs(ctx context.Context, mount string, in baoclient.PKIURLsInput, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadPKIURLs(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.PKIURLsInput, error) {
	return &baoclient.PKIURLsInput{}, nil
}

func (f *fakeBao) WritePKIRole(ctx context.Context, mount, name string, spec baoclient.PKIRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadPKIRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.PKIRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeletePKIRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
}

// Identity stubs — this controller does not exercise the identity API.
func (f *fakeBao) WriteIdentityGroup(ctx context.Context, spec baoclient.IdentityGroupSpec, opts ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadIdentityGroup(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityGroup(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteIdentityGroupAlias(ctx context.Context, spec baoclient.IdentityGroupAliasSpec, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadIdentityGroupAliasByID(ctx context.Context, id string, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) FindIdentityGroupAlias(ctx context.Context, name, mountAccessor string, opts ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityGroupAliasByID(ctx context.Context, id string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteIdentityTokenRole(ctx context.Context, name string, spec baoclient.IdentityTokenRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadIdentityTokenRole(ctx context.Context, name string, opts ...baoclient.CallOption) (*baoclient.IdentityTokenRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityTokenRole(ctx context.Context, name string, opts ...baoclient.CallOption) error {
	return nil
}

// ---- helpers ----

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoPolicyReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoPolicy{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoPolicy]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoPolicyFinalizer,
		Handlers:      OpenBaoPolicyHandlers(cl, fb),
	}
	return &OpenBaoPolicyReconciler{VaultResource: base}
}

func toClientObjects(in []runtime.Object) []client.Object {
	out := make([]client.Object, 0, len(in))
	for _, o := range in {
		if co, ok := o.(client.Object); ok {
			out = append(out, co)
		}
	}
	return out
}

func samplePolicy(name string) *v1alpha1.OpenBaoPolicy {
	p := &v1alpha1.OpenBaoPolicy{}
	p.Name = name
	p.Namespace = "default"
	p.Spec.Policy = `path "secret/*" { capabilities = ["read"] }`
	return p
}

func samplePolicyIn(ns, name string) *v1alpha1.OpenBaoPolicy {
	p := samplePolicy(name)
	p.Namespace = ns
	return p
}

func reconcileNS(t *testing.T, r *OpenBaoPolicyReconciler, ns, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getPolicyNS(t *testing.T, r *OpenBaoPolicyReconciler, ns, name string) *v1alpha1.OpenBaoPolicy {
	t.Helper()
	var p v1alpha1.OpenBaoPolicy
	err := r.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &p)
	require.NoError(t, err)
	return &p
}

func reconcile(t *testing.T, r *OpenBaoPolicyReconciler, name string) ctrl.Result {
	return reconcileNS(t, r, "default", name)
}

func getPolicy(t *testing.T, r *OpenBaoPolicyReconciler, name string) *v1alpha1.OpenBaoPolicy {
	return getPolicyNS(t, r, "default", name)
}

func readyCond(t *testing.T, p *v1alpha1.OpenBaoPolicy) *metav1.Condition {
	t.Helper()
	for i := range p.Status.Conditions {
		if p.Status.Conditions[i].Type == resource.ConditionReady {
			return &p.Status.Conditions[i]
		}
	}
	return nil
}

// Test-fixture UIDs reused across collision-test cases. Bare literals trip
// goconst when the same string appears three or more times across cases.
const (
	uidA = "uid-a"
	uidB = "uid-b"
)

// ---- tests ----

func TestOpenBaoPolicy_CreatePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("secret-reader")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name)
	got := getPolicy(t, r, p.Name)
	require.Contains(t, got.Finalizers, OpenBaoPolicyFinalizer, "finalizer should be added")

	reconcile(t, r, p.Name)
	require.Equal(t, 1, fb.upserts, "bao policy should be upserted once")
	require.Equal(t, p.Spec.Policy, fb.policies[policyKey("", p.Name)])

	cond := readyCond(t, getPolicy(t, r, p.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, resource.ReasonReconciled, cond.Reason)
}

func TestOpenBaoPolicy_EditPath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("editable")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name)
	reconcile(t, r, p.Name)
	require.Equal(t, 1, fb.upserts)

	cur := getPolicy(t, r, p.Name)
	cur.Spec.Policy = `path "secret/*" { capabilities = ["read", "list"] }`
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, p.Name)
	require.Equal(t, 2, fb.upserts, "edit should trigger a second upsert")
	require.Equal(t, cur.Spec.Policy, fb.policies[policyKey("", p.Name)])
}

func TestOpenBaoPolicy_DriftCorrection(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("drifter")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name)
	reconcile(t, r, p.Name)
	require.Equal(t, 1, fb.upserts)

	fb.policies[policyKey("", p.Name)] = "drifted body"

	reconcile(t, r, p.Name)
	require.Equal(t, 2, fb.upserts, "drift should trigger re-upsert")
	require.Equal(t, p.Spec.Policy, fb.policies[policyKey("", p.Name)])
}

func TestOpenBaoPolicy_DeletePath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("to-delete")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name)
	reconcile(t, r, p.Name)
	require.Equal(t, 1, fb.upserts)

	cur := getPolicy(t, r, p.Name)
	require.NoError(t, r.Delete(context.Background(), cur))

	reconcile(t, r, p.Name)
	require.Equal(t, 1, fb.deletes, "delete should have been called once")
	_, stillThere := fb.policies[policyKey("", p.Name)]
	require.False(t, stillThere, "bao-side policy should be gone")

	err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: p.Name}, &v1alpha1.OpenBaoPolicy{})
	require.True(t, apierrors.IsNotFound(err), "CR should be deleted after finalizer removal")
}

func TestOpenBaoPolicy_BaoForbidden(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.upsertErr = &baoclient.StatusError{
		StatusCode: http.StatusForbidden,
		Inner:      errors.New("permission denied"),
	}
	p := samplePolicy("forbidden-p")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name)
	res := reconcile(t, r, p.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter, "should requeue with error backoff")
	cond := readyCond(t, getPolicy(t, r, p.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonForbidden, cond.Reason)
}

func TestOpenBaoPolicy_BaoUnreachable(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.getErr = errors.New("dial tcp 127.0.0.1:8200: connection refused")
	p := samplePolicy("unreachable-p")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name)
	res := reconcile(t, r, p.Name)

	require.Equal(t, 30*time.Second, res.RequeueAfter)
	cond := readyCond(t, getPolicy(t, r, p.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonBaoError, cond.Reason)
}

// Accessor-placeholder rejection is a spec-level invalid (lives in IsValid),
// not a runtime error. The base must NOT requeue; the user has to fix the
// spec to recover. Asserts: Ready=False/Reason=Invalid, no requeue, no bao
// write.
func TestOpenBaoPolicy_AccessorTemplating_RejectedAsInvalidNoRequeue(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("templater")
	p.Spec.Policy = `path "x" { allowed_parameters = { "accessor" = ["${auth/kubernetes/@accessor}"] } }`
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name)
	res := reconcile(t, r, p.Name)

	require.True(t, res.IsZero(), "Invalid spec should not requeue (user must fix spec)")
	require.Equal(t, 0, fb.upserts, "no bao write should happen when spec is invalid")
	cond := readyCond(t, getPolicy(t, r, p.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
}

func TestOpenBaoPolicy_Idempotent_NoChangeNoRewrite(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("stable")
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name)
	reconcile(t, r, p.Name)
	require.Equal(t, 1, fb.upserts)

	reconcile(t, r, p.Name)
	require.Equal(t, 1, fb.upserts, "equivalent state should not trigger a rewrite")
}

// Bao policy names are namespace-scoped on the bao side, so two CRs with the
// same metadata.name targeting the SAME OpenBao namespace would otherwise
// silently overwrite each other. The collision check guards this; older
// CreationTimestamp wins, loser surfaces Ready=False, Reason=NameCollision.
func TestOpenBaoPolicy_NameCollision_OlderWinsLoserRefusesWrite(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := samplePolicyIn("ns-a", "editor")
	older.UID = "uid-older"
	older.CreationTimestamp = metav1.NewTime(time.Now().Add(-1 * time.Hour))

	newer := samplePolicyIn("ns-b", "editor")
	newer.UID = "uid-newer"
	newer.CreationTimestamp = metav1.NewTime(time.Now())
	newer.Spec.Policy = `path "secret/somethingelse/*" { capabilities = ["read"] }`

	r := buildReconciler(t, fb, older, newer)

	reconcileNS(t, r, "ns-a", "editor")
	reconcileNS(t, r, "ns-a", "editor")
	require.Equal(t, 1, fb.upserts, "older CR should successfully write")
	require.Equal(t, older.Spec.Policy, fb.policies[policyKey("", "editor")])

	cond := readyCond(t, getPolicyNS(t, r, "ns-a", "editor"))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionTrue, cond.Status, "older CR should be Ready=True")

	reconcileNS(t, r, "ns-b", "editor")
	res := reconcileNS(t, r, "ns-b", "editor")

	require.Equal(t, resource.PeriodicInterval, res.RequeueAfter,
		"collision is a stable state — loser should requeue at PeriodicInterval, not ErrorBackoff")
	require.Equal(t, 1, fb.upserts, "newer CR must NOT have written — older still owns the bao name")
	require.Equal(t, older.Spec.Policy, fb.policies[policyKey("", "editor")], "older's body must not be overwritten")

	loser := getPolicyNS(t, r, "ns-b", "editor")
	cond = readyCond(t, loser)
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status, "newer (loser) should be Ready=False")
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
	require.Contains(t, cond.Message, "ns-a/editor", "message should name the winning CR")
}

func TestOpenBaoPolicy_NameCollision_TimestampTieBrokenLexicographically(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	now := metav1.NewTime(time.Now())

	a := samplePolicyIn("ns-a", "editor")
	a.UID = uidA
	a.CreationTimestamp = now

	b := samplePolicyIn("ns-b", "editor")
	b.UID = uidB
	b.CreationTimestamp = now
	b.Spec.Policy = `path "different/*" { capabilities = ["list"] }`

	r := buildReconciler(t, fb, a, b)

	reconcileNS(t, r, "ns-a", "editor")
	reconcileNS(t, r, "ns-a", "editor")
	require.Equal(t, 1, fb.upserts, "ns-a (lex earlier) should write")

	reconcileNS(t, r, "ns-b", "editor")
	reconcileNS(t, r, "ns-b", "editor")

	require.Equal(t, 1, fb.upserts, "ns-b (lex later) must NOT write")
	condB := readyCond(t, getPolicyNS(t, r, "ns-b", "editor"))
	require.NotNil(t, condB)
	require.Equal(t, resource.ReasonNameCollision, condB.Reason)
}

func TestOpenBaoPolicy_NameCollision_DistinctSpecNamesDoNotCollide(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	a := samplePolicyIn("ns-a", "shared")
	a.UID = uidA
	a.Spec.Name = "ns-a-shared"

	b := samplePolicyIn("ns-b", "shared")
	b.UID = uidB
	b.Spec.Name = "ns-b-shared"

	r := buildReconciler(t, fb, a, b)

	reconcileNS(t, r, "ns-a", "shared")
	reconcileNS(t, r, "ns-a", "shared")
	reconcileNS(t, r, "ns-b", "shared")
	reconcileNS(t, r, "ns-b", "shared")

	require.Equal(t, 2, fb.upserts, "distinct bao names → both writes succeed")
	require.Contains(t, fb.policies, policyKey("", "ns-a-shared"))
	require.Contains(t, fb.policies, policyKey("", "ns-b-shared"))
}

// New for OpenBaoPolicy: same metadata.name in different OpenBao namespaces
// is not a collision because bao stores them as separate objects scoped by
// X-Vault-Namespace. The collision check must compare the
// (BaoName, OpenBaoNamespace) tuple, not BaoName alone.
func TestOpenBaoPolicy_NameCollision_SameNameDifferentOpenBaoNamespaceDoesNotCollide(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	a := samplePolicyIn("ns-a", "editor")
	a.UID = uidA
	a.Spec.OpenBaoNamespace = "acme/"

	b := samplePolicyIn("ns-b", "editor")
	b.UID = uidB
	b.Spec.OpenBaoNamespace = "globex/"

	r := buildReconciler(t, fb, a, b)

	reconcileNS(t, r, "ns-a", "editor")
	reconcileNS(t, r, "ns-a", "editor")
	reconcileNS(t, r, "ns-b", "editor")
	reconcileNS(t, r, "ns-b", "editor")

	require.Equal(t, 2, fb.upserts, "different OpenBao namespaces → both writes succeed")

	condA := readyCond(t, getPolicyNS(t, r, "ns-a", "editor"))
	require.NotNil(t, condA)
	require.Equal(t, metav1.ConditionTrue, condA.Status, "ns-a (acme/) should be Ready=True")

	condB := readyCond(t, getPolicyNS(t, r, "ns-b", "editor"))
	require.NotNil(t, condB)
	require.Equal(t, metav1.ConditionTrue, condB.Status, "ns-b (globex/) should be Ready=True")
}

// Regression for the wasEverReady guard: a CR that never reached Ready=True
// (e.g. spec.policy contained an accessor placeholder → IsValid rejected)
// must delete cleanly without ever calling BaoDelete. Otherwise primitives
// with strict delete endpoints would strand CRs in Terminating.
func TestOpenBaoPolicy_DeleteSkipsBaoIfNeverReady(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	p := samplePolicy("never-ready")
	p.Spec.Policy = `path "x" { allowed_parameters = { "accessor" = ["${auth/kubernetes/@accessor}"] } }`
	r := buildReconciler(t, fb, p)

	reconcile(t, r, p.Name)
	reconcile(t, r, p.Name)
	require.Equal(t, 0, fb.upserts)

	cond := readyCond(t, getPolicy(t, r, p.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInvalid, cond.Reason)

	cur := getPolicy(t, r, p.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, p.Name)

	require.Equal(t, 0, fb.deletes, "BaoDelete should be skipped for CRs that never reached Ready=True")

	err := r.Get(context.Background(), types.NamespacedName{Namespace: "default", Name: p.Name}, &v1alpha1.OpenBaoPolicy{})
	require.True(t, apierrors.IsNotFound(err))
}

// Cert auth + JWT/OIDC stubs — this controller does not exercise them.
func (f *fakeBao) WriteCertAuthConfig(ctx context.Context, mount string, spec baoclient.CertAuthConfigSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadCertAuthConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.CertAuthConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteCertAuthRole(ctx context.Context, mount, name string, spec baoclient.CertAuthRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadCertAuthRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.CertAuthRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteCertAuthRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteJWTOIDCConfig(ctx context.Context, mount string, spec baoclient.JWTOIDCConfigSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadJWTOIDCConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.JWTOIDCConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteK8sAuthConfig(ctx context.Context, mount string, spec baoclient.K8sAuthConfigSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadK8sAuthConfig(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.K8sAuthConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteJWTOIDCRole(ctx context.Context, mount, name string, spec baoclient.JWTOIDCRoleSpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadJWTOIDCRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.JWTOIDCRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteJWTOIDCRole(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteTransitKey(ctx context.Context, mount, name string, spec baoclient.TransitKeySpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadTransitKey(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.TransitKeyInfo, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) UpdateTransitKeyConfig(ctx context.Context, mount, name string, spec baoclient.TransitKeySpec, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) DeleteTransitKey(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	return nil
}
