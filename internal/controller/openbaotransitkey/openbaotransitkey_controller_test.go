package openbaotransitkey

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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

const (
	envtestNS   = "default"
	mount       = "transit"
	keyName     = "app-key"
	sharedKeyNm = "shared"
)

// fakeBao keys keys (heh) by (openbaoNs, mount, name) so the same key
// name on different mounts or namespaces is correctly distinct.
type fakeBao struct {
	keys map[string]*baoclient.TransitKeyInfo
	// deletionBlocked, when true for a given key, causes
	// DeleteTransitKey to return ErrDeletionNotAllowed regardless of
	// the key's own deletion_allowed field. Models bao's behaviour
	// when transit refuses delete due to its server-side gate.
	deletionBlocked map[string]bool

	writes, configs, reads, deletes int

	writeErr  error
	readErr   error
	configErr error
	deleteErr error
}

func newFakeBao() *fakeBao {
	return &fakeBao{
		keys:            map[string]*baoclient.TransitKeyInfo{},
		deletionBlocked: map[string]bool{},
	}
}

func tkKey(ns, mount, name string) string { return ns + "|" + mount + "|" + name }

// fakeKeyFromCreate builds the TransitKeyInfo the fake stores after a
// create call. Mirrors what bao does internally: defaults for unset
// fields, version=1, capability bools derived from type.
func fakeKeyFromCreate(spec baoclient.TransitKeySpec, name string) *baoclient.TransitKeyInfo {
	info := &baoclient.TransitKeyInfo{
		Name:               name,
		Type:               spec.Type,
		LatestVersion:      1,
		CreationTime:       "2026-05-04T00:00:00Z",
		SupportsEncryption: isSymmetric(spec.Type) || strings.HasPrefix(spec.Type, "rsa"),
		SupportsDecryption: isSymmetric(spec.Type) || strings.HasPrefix(spec.Type, "rsa"),
		SupportsSigning:    !isSymmetric(spec.Type),
		SupportsDerivation: spec.Derived != nil && *spec.Derived,
	}
	if spec.KeySize != nil {
		info.KeySize = *spec.KeySize
	}
	if spec.Derived != nil {
		info.Derived = *spec.Derived
	}
	if spec.ConvergentEncryption != nil {
		info.ConvergentEncryption = *spec.ConvergentEncryption
	}
	if spec.Exportable != nil {
		info.Exportable = *spec.Exportable
	}
	if spec.AllowPlaintextBackup != nil {
		info.AllowPlaintextBackup = *spec.AllowPlaintextBackup
	}
	if spec.AutoRotatePeriod != "" && spec.AutoRotatePeriod != "0" {
		if d, err := time.ParseDuration(spec.AutoRotatePeriod); err == nil {
			info.AutoRotatePeriod = int(d.Seconds())
		}
	}
	return info
}

func isSymmetric(t string) bool {
	return strings.HasPrefix(t, "aes") || strings.HasPrefix(t, "chacha") || t == "hmac"
}

// ---- methods under test ----

func (f *fakeBao) WriteTransitKey(ctx context.Context, mount, name string, spec baoclient.TransitKeySpec, opts ...baoclient.CallOption) error {
	f.writes++
	if f.writeErr != nil {
		return f.writeErr
	}
	f.keys[tkKey(baoclient.NamespaceFromOpts(opts), mount, name)] = fakeKeyFromCreate(spec, name)
	return nil
}

func (f *fakeBao) ReadTransitKey(ctx context.Context, mount, name string, opts ...baoclient.CallOption) (*baoclient.TransitKeyInfo, error) {
	f.reads++
	if f.readErr != nil {
		return nil, f.readErr
	}
	cur, ok := f.keys[tkKey(baoclient.NamespaceFromOpts(opts), mount, name)]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	cp := *cur
	return &cp, nil
}

func (f *fakeBao) UpdateTransitKeyConfig(ctx context.Context, mount, name string, spec baoclient.TransitKeySpec, opts ...baoclient.CallOption) error {
	f.configs++
	if f.configErr != nil {
		return f.configErr
	}
	cur, ok := f.keys[tkKey(baoclient.NamespaceFromOpts(opts), mount, name)]
	if !ok {
		return baoclient.ErrNotFound
	}
	if spec.MinDecryptionVersion != nil {
		cur.MinDecryptionVersion = *spec.MinDecryptionVersion
	}
	if spec.MinEncryptionVersion != nil {
		cur.MinEncryptionVersion = *spec.MinEncryptionVersion
	}
	if spec.DeletionAllowed != nil {
		cur.DeletionAllowed = *spec.DeletionAllowed
	}
	if spec.Exportable != nil {
		cur.Exportable = *spec.Exportable
	}
	if spec.AllowPlaintextBackup != nil {
		cur.AllowPlaintextBackup = *spec.AllowPlaintextBackup
	}
	if spec.AutoRotatePeriod != "" {
		if spec.AutoRotatePeriod == "0" {
			cur.AutoRotatePeriod = 0
		} else if d, err := time.ParseDuration(spec.AutoRotatePeriod); err == nil {
			cur.AutoRotatePeriod = int(d.Seconds())
		}
	}
	return nil
}

func (f *fakeBao) DeleteTransitKey(ctx context.Context, mount, name string, opts ...baoclient.CallOption) error {
	f.deletes++
	if f.deleteErr != nil {
		return f.deleteErr
	}
	k := tkKey(baoclient.NamespaceFromOpts(opts), mount, name)
	if f.deletionBlocked[k] {
		return baoclient.ErrDeletionNotAllowed
	}
	if _, ok := f.keys[k]; !ok {
		// Idempotent: not-found is fine.
		return nil
	}
	delete(f.keys, k)
	return nil
}

// ---- stubs for the rest of baoclient.Client ----

func (f *fakeBao) CheckKVv2Mount(ctx context.Context, m string, o ...baoclient.CallOption) (bool, error) {
	return true, nil
}
func (f *fakeBao) UpsertPolicy(ctx context.Context, n, r string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetPolicy(ctx context.Context, n string, o ...baoclient.CallOption) (string, error) {
	return "", baoclient.ErrNotFound
}
func (f *fakeBao) DeletePolicy(ctx context.Context, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) UpsertK8sRole(ctx context.Context, m, n string, s baoclient.K8sRoleSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetK8sRole(ctx context.Context, m, n string, o ...baoclient.CallOption) (*baoclient.K8sRole, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteK8sRole(ctx context.Context, m, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) EnableSecretEngine(ctx context.Context, m string, s baoclient.SecretEngineMountSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) TuneSecretEngine(ctx context.Context, m string, s baoclient.SecretEngineMountSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetSecretEngineMount(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.SecretEngineMount, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DisableSecretEngineMount(ctx context.Context, m string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) DisableAuthMount(ctx context.Context, m string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) EnableAuthMethod(ctx context.Context, m string, s baoclient.AuthMethodMountSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) TuneAuthMethod(ctx context.Context, m string, s baoclient.AuthMethodMountSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetAuthMethod(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.AuthMethodMount, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) CreateNamespace(ctx context.Context, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetNamespace(ctx context.Context, n string, o ...baoclient.CallOption) (*baoclient.Namespace, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteNamespace(ctx context.Context, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GenerateRootPKI(ctx context.Context, m string, in baoclient.PKIRootGenerateInput, o ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
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
func (f *fakeBao) ReadPKICA(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WritePKIURLs(ctx context.Context, m string, in baoclient.PKIURLsInput, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadPKIURLs(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.PKIURLsInput, error) {
	return &baoclient.PKIURLsInput{}, nil
}
func (f *fakeBao) WritePKIRole(ctx context.Context, m, n string, s baoclient.PKIRoleSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadPKIRole(ctx context.Context, m, n string, o ...baoclient.CallOption) (*baoclient.PKIRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeletePKIRole(ctx context.Context, m, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteIdentityGroup(ctx context.Context, s baoclient.IdentityGroupSpec, o ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadIdentityGroup(ctx context.Context, n string, o ...baoclient.CallOption) (*baoclient.IdentityGroup, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityGroup(ctx context.Context, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteIdentityGroupAlias(ctx context.Context, s baoclient.IdentityGroupAliasSpec, o ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) ReadIdentityGroupAliasByID(ctx context.Context, id string, o ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) FindIdentityGroupAlias(ctx context.Context, n, ma string, o ...baoclient.CallOption) (*baoclient.IdentityGroupAlias, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityGroupAliasByID(ctx context.Context, id string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteIdentityTokenRole(ctx context.Context, n string, s baoclient.IdentityTokenRoleSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadIdentityTokenRole(ctx context.Context, n string, o ...baoclient.CallOption) (*baoclient.IdentityTokenRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteIdentityTokenRole(ctx context.Context, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteCertAuthConfig(ctx context.Context, m string, s baoclient.CertAuthConfigSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadCertAuthConfig(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.CertAuthConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteCertAuthRole(ctx context.Context, m, n string, s baoclient.CertAuthRoleSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadCertAuthRole(ctx context.Context, m, n string, o ...baoclient.CallOption) (*baoclient.CertAuthRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteCertAuthRole(ctx context.Context, m, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) WriteJWTOIDCConfig(ctx context.Context, m string, s baoclient.JWTOIDCConfigSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadJWTOIDCConfig(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.JWTOIDCConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteK8sAuthConfig(ctx context.Context, m string, s baoclient.K8sAuthConfigSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadK8sAuthConfig(ctx context.Context, m string, o ...baoclient.CallOption) (*baoclient.K8sAuthConfigSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) WriteJWTOIDCRole(ctx context.Context, m, n string, s baoclient.JWTOIDCRoleSpec, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) ReadJWTOIDCRole(ctx context.Context, m, n string, o ...baoclient.CallOption) (*baoclient.JWTOIDCRoleSpec, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteJWTOIDCRole(ctx context.Context, m, n string, o ...baoclient.CallOption) error {
	return nil
}

// ---- harness ----

func ptrBool(b bool) *bool { return &b }
func ptrInt(i int) *int    { return &i }

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoTransitKeyReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoTransitKey{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoTransitKey]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoTransitKeyFinalizer,
		Handlers:      OpenBaoTransitKeyHandlers(cl, fb),
	}
	return &OpenBaoTransitKeyReconciler{VaultResource: base}
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

func sampleKey(name string) *v1alpha1.OpenBaoTransitKey {
	k := &v1alpha1.OpenBaoTransitKey{}
	k.Name = name
	k.Namespace = envtestNS
	k.Spec.Path = mount
	k.Spec.Name = name
	k.Spec.Type = "aes256-gcm96"
	k.Spec.DeletionAllowed = ptrBool(true)
	return k
}

func reconcile(t *testing.T, r *OpenBaoTransitKeyReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: envtestNS, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getKey(t *testing.T, r *OpenBaoTransitKeyReconciler, name string) *v1alpha1.OpenBaoTransitKey {
	t.Helper()
	var got v1alpha1.OpenBaoTransitKey
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: name}, &got))
	return &got
}

func readyCond(t *testing.T, k *v1alpha1.OpenBaoTransitKey) *metav1.Condition {
	t.Helper()
	for i := range k.Status.Conditions {
		if k.Status.Conditions[i].Type == resource.ConditionReady {
			return &k.Status.Conditions[i]
		}
	}
	return nil
}

// ---- tests ----

func TestTransitKey_CreatePath_WritesKey(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("app-key")
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name) // finalizer
	reconcile(t, r, tk.Name) // write

	require.Equal(t, 1, fb.writes)
	require.Equal(t, 1, fb.configs, "config call must follow create")
	stored, ok := fb.keys[tkKey("", mount, "app-key")]
	require.True(t, ok)
	require.Equal(t, "aes256-gcm96", stored.Type)
	require.True(t, stored.DeletionAllowed, "config call propagates deletion_allowed=true")

	got := getKey(t, r, tk.Name)
	cond := readyCond(t, got)
	require.Equal(t, metav1.ConditionTrue, cond.Status)
	require.Equal(t, resource.ReasonReconciled, cond.Reason)

	// Status reflects observed bao state.
	require.Equal(t, 1, got.Status.LatestVersion)
	require.NotEmpty(t, got.Status.CreationTime)
	require.True(t, got.Status.SupportsEncryption)
	require.True(t, got.Status.BaoWritten)
	require.Equal(t, "app-key", got.Status.LastWrittenBaoName)
	require.Equal(t, mount, got.Status.LastWrittenPath)
}

// Backfill path: when bao already has the desired key and the
// comparator returns no-drift, the controller's Backfill closure must
// still stamp Status.LastWrittenPath. This locks down the upgrade
// case where an existing CR was written by a pre-LastWrittenPath
// version of the operator and the field is empty in etcd; the next
// reconcile should populate it without a spurious BaoWrite. A future
// refactor that drops the Backfill stamp would silently regress the
// rename-cleanup path (BaoDeleteIdentity reads LastWrittenPath).
func TestTransitKey_Backfill_StampsLastWrittenPath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	// Pre-populate bao as if a previous successful write had happened.
	fb.keys[tkKey("", mount, "app-key")] = &baoclient.TransitKeyInfo{
		Type:               "aes256-gcm96",
		LatestVersion:      1,
		DeletionAllowed:    true,
		SupportsEncryption: true,
	}

	// CR exists, finalizer set, status.baoWritten=true, but
	// LastWrittenPath empty (upgrade case). Comparator must say
	// no-drift; Backfill must stamp the path.
	tk := sampleKey("app-key")
	tk.Status.BaoWritten = true
	tk.Status.LastWrittenBaoName = "app-key"
	tk.Status.LastWrittenPath = ""
	tk.Finalizers = []string{OpenBaoTransitKeyFinalizer}

	r := buildReconciler(t, fb, tk)
	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)

	require.Equal(t, 0, fb.writes, "Backfill path must not write")
	got := getKey(t, r, tk.Name)
	require.Equal(t, mount, got.Status.LastWrittenPath,
		"Backfill closure must stamp LastWrittenPath on the no-drift path")
}

func TestTransitKey_StableState_NoExtraWrites(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("app-key")
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)
	require.Equal(t, 1, fb.writes)

	// Reconcile again — drift comparator must return true, no re-write.
	reconcile(t, r, tk.Name)
	require.Equal(t, 1, fb.writes,
		"steady-state reconcile must not re-write — comparator returns true")
	require.Equal(t, 1, fb.configs,
		"steady-state reconcile must not re-call /config either")
}

func TestTransitKey_AutoRotateNormalization_NoSpuriousWrite(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("app-key")
	tk.Spec.AutoRotatePeriod = "720h"
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)
	require.Equal(t, 1, fb.writes)
	stored := fb.keys[tkKey("", mount, "app-key")]
	require.Equal(t, 2592000, stored.AutoRotatePeriod)

	// Reconcile again — bao read returns int seconds, spec is "720h".
	// Normalization in IsEquivalentToDesiredState must treat them equal.
	reconcile(t, r, tk.Name)
	require.Equal(t, 1, fb.writes,
		"spec '720h' vs bao 2592000s must normalize — no spurious write")
}

func TestTransitKey_DriftCorrection_OnSpecChange(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("app-key")
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)
	require.Equal(t, 1, fb.writes)
	require.Equal(t, 1, fb.configs)

	// Edit a mutable, config-only field. BaoWrite re-fires
	// (drift detected on min_decryption_version), but no fresh
	// /keys/<name> write — only a /config call.
	cur := getKey(t, r, tk.Name)
	cur.Spec.MinDecryptionVersion = ptrInt(2)
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, tk.Name)
	require.Equal(t, 1, fb.writes, "mutable-only drift must not re-create the key")
	require.Equal(t, 2, fb.configs, "mutable-only drift drives a /config update")

	stored := fb.keys[tkKey("", mount, "app-key")]
	require.Equal(t, 2, stored.MinDecryptionVersion)
}

func TestTransitKey_TypeImmutability_RejectedWithReasonInvalid(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("app-key")
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)
	require.Equal(t, 1, fb.writes)

	// Edit spec.type after a successful write.
	cur := getKey(t, r, tk.Name)
	cur.Spec.Type = "ed25519"
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, tk.Name)

	// No new write — bao state must be unchanged.
	require.Equal(t, 1, fb.writes, "type change must not write")
	stored := fb.keys[tkKey("", mount, "app-key")]
	require.Equal(t, "aes256-gcm96", stored.Type, "bao state unchanged")

	cond := readyCond(t, getKey(t, r, tk.Name))
	require.NotNil(t, cond)
	require.Equal(t, metav1.ConditionFalse, cond.Status)
	require.Equal(t, resource.ReasonInvalid, cond.Reason,
		"type-immutability violation must surface as ReasonInvalid (not InternalError or BaoError)")
	require.Contains(t, cond.Message, "spec.type")
}

func TestTransitKey_DerivedImmutability_Rejected(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("app-key")
	tk.Spec.Derived = ptrBool(true)
	tk.Spec.ConvergentEncryption = ptrBool(true)
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)
	require.Equal(t, 1, fb.writes)

	// Flip derived false on the spec — bao key still has derived=true.
	cur := getKey(t, r, tk.Name)
	cur.Spec.Derived = ptrBool(false)
	cur.Spec.ConvergentEncryption = ptrBool(false)
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, tk.Name)
	require.Equal(t, 1, fb.writes)
	cond := readyCond(t, getKey(t, r, tk.Name))
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
}

func TestTransitKey_KeySizeImmutability_Rejected(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("hmac-key")
	tk.Spec.Type = "hmac"
	tk.Spec.KeySize = ptrInt(32)
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)

	cur := getKey(t, r, tk.Name)
	cur.Spec.KeySize = ptrInt(64)
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, tk.Name)
	cond := readyCond(t, getKey(t, r, tk.Name))
	require.Equal(t, resource.ReasonInvalid, cond.Reason)
	require.Contains(t, cond.Message, "keySize")
}

func TestTransitKey_DeletePath_OrphansBaoKey(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("app-key")
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)
	require.Contains(t, fb.keys, tkKey("", mount, "app-key"))

	cur := getKey(t, r, tk.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, tk.Name)

	got := &v1alpha1.OpenBaoTransitKey{}
	err := r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: tk.Name}, got)
	require.Error(t, err, "finalizer must be released so the CR is removed")
	require.Equal(t, 0, fb.deletes,
		"IsDeletable=false must keep the delete path away from bao entirely")
	require.Contains(t, fb.keys, tkKey("", mount, "app-key"),
		"bao key outlives the CR — key material is never destroyed by CR deletion")
}

// Even with spec.deletionAllowed=true the operator must not remove the
// bao key: the spec field configures bao's own gate, it is not an
// instruction to the operator to delete.
func TestTransitKey_DeletionAllowedTrue_StillOrphans(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("app-key")
	tk.Spec.DeletionAllowed = ptrBool(true)
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)
	require.True(t, fb.keys[tkKey("", mount, "app-key")].DeletionAllowed,
		"spec.deletionAllowed must still reach bao on the write path")

	cur := getKey(t, r, tk.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, tk.Name)

	require.Equal(t, 0, fb.deletes)
	require.Contains(t, fb.keys, tkKey("", mount, "app-key"))
}

// Regression for the wedge: a key whose bao-side deletion_allowed gate is
// closed used to leave the CR in Terminating forever, because the
// finalizer waited on a delete bao would never accept and the write path
// that carries the flag does not run once a deletionTimestamp is set. The
// delete path no longer calls bao at all, so the gate cannot wedge it.
func TestTransitKey_DeleteNeverWedges_WhenBaoGateClosed(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("app-key")
	tk.Spec.DeletionAllowed = nil // bao's gate stays closed
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)
	fb.deletionBlocked[tkKey("", mount, "app-key")] = true

	cur := getKey(t, r, tk.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, tk.Name)

	got := &v1alpha1.OpenBaoTransitKey{}
	err := r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: tk.Name}, got)
	require.Error(t, err, "CR must not be stuck Terminating behind bao's deletion_allowed gate")
	require.Contains(t, fb.keys, tkKey("", mount, "app-key"))
}

// Re-creating a CR over a key that already exists in bao must adopt it
// rather than recreate it. This is what makes an accidental CR removal
// recoverable: the key material, and therefore existing ciphertext,
// survives the round trip.
func TestTransitKey_ReCreate_AdoptsExistingBaoKey(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.keys[tkKey("", mount, "app-key")] = &baoclient.TransitKeyInfo{
		Type:               "aes256-gcm96",
		LatestVersion:      7,
		SupportsEncryption: true,
	}

	tk := sampleKey("app-key")
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)

	require.Equal(t, 0, fb.writes,
		"an existing key must be adopted, not re-created")
	require.Equal(t, 7, fb.keys[tkKey("", mount, "app-key")].LatestVersion,
		"adoption must not reset the key's version history")
	require.Equal(t, 7, getKey(t, r, tk.Name).Status.LatestVersion)
}

func TestTransitKey_NeverWrote_DeleteFinalizesCleanly(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.writeErr = baoclient.ErrNotFound // create fails → status.baoWritten stays false
	tk := sampleKey("app-key")
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name) // finalizer
	reconcile(t, r, tk.Name) // create attempt fails

	require.False(t, getKey(t, r, tk.Name).Status.BaoWritten)
	fb.writeErr = nil // not relevant once we delete

	cur := getKey(t, r, tk.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, tk.Name)

	require.Equal(t, 0, fb.deletes)
	got := &v1alpha1.OpenBaoTransitKey{}
	err := r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: tk.Name}, got)
	require.Error(t, err, "a CR that never wrote to bao must still finalize")
}

func TestTransitKey_NameCollision_DifferentMountsDoNotCollide(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	a := sampleKey("k8s-a")
	a.Spec.Path = "transit-a"
	a.Spec.Name = sharedKeyNm
	a.UID = "uid-a"

	b := sampleKey("k8s-b")
	b.Spec.Path = "transit-b"
	b.Spec.Name = sharedKeyNm
	b.UID = "uid-b"

	r := buildReconciler(t, fb, a, b)

	reconcile(t, r, a.Name)
	reconcile(t, r, a.Name)
	reconcile(t, r, b.Name)
	reconcile(t, r, b.Name)

	require.Equal(t, 2, fb.writes, "different mounts: both must write")
	require.Contains(t, fb.keys, tkKey("", "transit-a", sharedKeyNm))
	require.Contains(t, fb.keys, tkKey("", "transit-b", sharedKeyNm))
}

func TestTransitKey_NameCollision_OlderWins(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleKey(sharedKeyNm)
	older.UID = "uid-older"
	older.CreationTimestamp = metav1.Now()

	younger := sampleKey("younger-cr")
	younger.UID = "uid-younger"
	younger.CreationTimestamp = metav1.NewTime(older.CreationTimestamp.Add(time.Second))
	younger.Spec.Name = sharedKeyNm // same bao key name

	r := buildReconciler(t, fb, older, younger)

	reconcile(t, r, older.Name)
	reconcile(t, r, older.Name)
	require.Equal(t, 1, fb.writes)

	reconcile(t, r, younger.Name)
	reconcile(t, r, younger.Name)
	require.Equal(t, 1, fb.writes, "younger must NOT write — collision")

	cond := readyCond(t, getKey(t, r, younger.Name))
	require.NotNil(t, cond)
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
}

// A rename points the CR at a new bao identity and leaves the previous
// one in place. The old key still holds the material for everything
// encrypted before the rename, and a rename is not a decision to destroy
// that, so the base skips rename-cleanup for this kind.
func TestTransitKey_Rename_OrphansPrevious(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("orig")
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)
	require.Contains(t, fb.keys, tkKey("", mount, "orig"))

	cur := getKey(t, r, tk.Name)
	cur.Spec.Name = "renamed"
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, tk.Name)

	require.Contains(t, fb.keys, tkKey("", mount, "renamed"),
		"new identity must be present")
	require.Contains(t, fb.keys, tkKey("", mount, "orig"),
		"previous identity must survive the rename — no key material is destroyed")
	require.Equal(t, 0, fb.deletes)
	require.Equal(t, "renamed", getKey(t, r, tk.Name).Status.LastWrittenBaoName)
}

func TestTransitKey_Rename_AcrossMountPath_OrphansAtOldPath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("orig")
	tk.Spec.Path = "transit-original"
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)
	require.Contains(t, fb.keys, tkKey("", "transit-original", "orig"))
	require.Equal(t, "transit-original", getKey(t, r, tk.Name).Status.LastWrittenPath)

	// Rename BOTH name and path in one edit.
	cur := getKey(t, r, tk.Name)
	cur.Spec.Name = "renamed"
	cur.Spec.Path = "transit-new"
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, tk.Name)

	require.Contains(t, fb.keys, tkKey("", "transit-new", "renamed"))
	require.Contains(t, fb.keys, tkKey("", "transit-original", "orig"),
		"the key at the previous (path,name) must survive — a values edit that moves "+
			"the mount must not destroy a CA-equivalent secret")
	require.Equal(t, 0, fb.deletes)
}

func TestTransitKey_LatestVersion_RefreshedOnReconcile(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	tk := sampleKey("app-key")
	r := buildReconciler(t, fb, tk)

	reconcile(t, r, tk.Name)
	reconcile(t, r, tk.Name)
	require.Equal(t, 1, getKey(t, r, tk.Name).Status.LatestVersion)

	// Out-of-band rotate: bao bumps latest_version to 3.
	stored := fb.keys[tkKey("", mount, "app-key")]
	stored.LatestVersion = 3

	reconcile(t, r, tk.Name)
	require.Equal(t, 3, getKey(t, r, tk.Name).Status.LatestVersion,
		"Backfill mutator must refresh observed status on no-drift reconcile")
}
