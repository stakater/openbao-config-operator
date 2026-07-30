package openbaopkisecretengineconfig

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
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
	envtestNS      = "default"
	pkiPath        = "pki"
	testCommonName = "Test CA"
	caBundleCMName = "team-a-ca"
)

// fakeBao models PKI mount state in-memory. Only the four PKI methods
// the controller exercises (GenerateRootPKI, ReadPKICA, WritePKIURLs,
// ReadPKIURLs) carry behaviour. Everything else is a stub — the
// controller never touches them, but the type must satisfy the full
// baoclient.Client interface.
type fakeBao struct {
	caBySerial map[string]*baoclient.PKICAResponse // keyed "<openbaoNs>|<mount>"
	urls       map[string]*baoclient.PKIURLsInput  // same key
	nextSerial int

	generateErr error
	readCAErr   error
	writeURLErr error
	readURLErr  error

	// intermediate-flow injection + capture
	genCSRErr           error
	signErr             error
	setSignedErr        error
	lastSignCSR         string
	lastSignRoot        string
	lastSetSigned       string
	lastGenCSRNS        string // openbao namespace the CSR was generated in
	lastSignNS          string // openbao namespace the sign call targeted
	lastSetSignedNS     string // openbao namespace set-signed targeted
	lastTuneMaxLeaseTTL string // max_lease_ttl the controller tuned the mount to
	// callOrder records the CA-mutating PKI calls plus the pre-generate mount
	// tune (in order), so tests can assert tune→generate→sign→set-signed
	// sequencing.
	callOrder []string

	generates, readCAs, writeURLs, readURLs int
	genCSRs, signs, setSigneds              int
}

func newFakeBao() *fakeBao {
	return &fakeBao{
		caBySerial: map[string]*baoclient.PKICAResponse{},
		urls:       map[string]*baoclient.PKIURLsInput{},
	}
}

func key(ns, mount string) string { return ns + "|" + mount }

// ---- PKI methods under test ----

func (f *fakeBao) GenerateRootPKI(ctx context.Context, mount string, in baoclient.PKIRootGenerateInput, opts ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	f.generates++
	f.callOrder = append(f.callOrder, "generate-root")
	if f.generateErr != nil {
		return nil, f.generateErr
	}
	f.nextSerial++
	resp := &baoclient.PKICAResponse{
		SerialNumber: "fake-serial-" + string(rune('0'+f.nextSerial)),
		Certificate:  "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n",
	}
	f.caBySerial[key(baoclient.NamespaceFromOpts(opts), mount)] = resp
	return resp, nil
}

// GenerateIntermediateCSR returns a deterministic fake CSR; the pending key is
// modelled implicitly (a CA appears only after SetSignedIntermediate).
func (f *fakeBao) GenerateIntermediateCSR(ctx context.Context, mount string, in baoclient.PKIIntermediateGenerateInput, opts ...baoclient.CallOption) (string, error) {
	f.genCSRs++
	f.callOrder = append(f.callOrder, "generate-csr")
	f.lastGenCSRNS = baoclient.NamespaceFromOpts(opts)
	if f.genCSRErr != nil {
		return "", f.genCSRErr
	}
	return "FAKE-CSR-" + mount, nil
}

func (f *fakeBao) SignIntermediate(ctx context.Context, rootMount, csr string, in baoclient.PKISignIntermediateInput, opts ...baoclient.CallOption) (string, error) {
	f.signs++
	f.callOrder = append(f.callOrder, "sign")
	f.lastSignCSR = csr
	f.lastSignRoot = rootMount
	f.lastSignNS = baoclient.NamespaceFromOpts(opts)
	if f.signErr != nil {
		return "", f.signErr
	}
	return "FAKE-SIGNED-CERT", nil
}

func (f *fakeBao) SetSignedIntermediate(ctx context.Context, mount, certificate string, opts ...baoclient.CallOption) error {
	f.setSigneds++
	f.callOrder = append(f.callOrder, "set-signed")
	f.lastSetSigned = certificate
	f.lastSetSignedNS = baoclient.NamespaceFromOpts(opts)
	if f.setSignedErr != nil {
		return f.setSignedErr
	}
	// Binding the signed cert makes a CA appear at this mount.
	f.caBySerial[key(baoclient.NamespaceFromOpts(opts), mount)] = &baoclient.PKICAResponse{
		SerialNumber: "intermediate-serial",
		Certificate:  certificate,
	}
	return nil
}

func (f *fakeBao) ReadPKICA(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.PKICAResponse, error) {
	f.readCAs++
	if f.readCAErr != nil {
		return nil, f.readCAErr
	}
	cur, ok := f.caBySerial[key(baoclient.NamespaceFromOpts(opts), mount)]
	if !ok {
		return nil, baoclient.ErrNotFound
	}
	return cur, nil
}

func (f *fakeBao) WritePKIURLs(ctx context.Context, mount string, in baoclient.PKIURLsInput, opts ...baoclient.CallOption) error {
	f.writeURLs++
	if f.writeURLErr != nil {
		return f.writeURLErr
	}
	cp := in
	f.urls[key(baoclient.NamespaceFromOpts(opts), mount)] = &cp
	return nil
}

func (f *fakeBao) ReadPKIURLs(ctx context.Context, mount string, opts ...baoclient.CallOption) (*baoclient.PKIURLsInput, error) {
	f.readURLs++
	if f.readURLErr != nil {
		return nil, f.readURLErr
	}
	cur, ok := f.urls[key(baoclient.NamespaceFromOpts(opts), mount)]
	if !ok {
		return &baoclient.PKIURLsInput{}, nil
	}
	return cur, nil
}

// ---- stubs for the rest of baoclient.Client ----

func (f *fakeBao) CheckKVv2Mount(ctx context.Context, mount string, opts ...baoclient.CallOption) (bool, error) {
	return true, nil
}
func (f *fakeBao) UpsertPolicy(ctx context.Context, name, rules string, opts ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetPolicy(ctx context.Context, name string, opts ...baoclient.CallOption) (string, error) {
	return "", baoclient.ErrNotFound
}
func (f *fakeBao) DeletePolicy(ctx context.Context, name string, opts ...baoclient.CallOption) error {
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
	f.callOrder = append(f.callOrder, "tune")
	f.lastTuneMaxLeaseTTL = s.MaxLeaseTTL
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

func (f *fakeBao) CreateNamespace(ctx context.Context, n string, o ...baoclient.CallOption) error {
	return nil
}
func (f *fakeBao) GetNamespace(ctx context.Context, n string, o ...baoclient.CallOption) (*baoclient.Namespace, error) {
	return nil, baoclient.ErrNotFound
}
func (f *fakeBao) DeleteNamespace(ctx context.Context, n string, o ...baoclient.CallOption) error {
	return nil
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

func buildReconciler(t *testing.T, fb *fakeBao, objs ...runtime.Object) *OpenBaoPKISecretEngineConfigReconciler {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	cl := crfake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(toClientObjects(objs)...).
		WithStatusSubresource(&v1alpha1.OpenBaoPKISecretEngineConfig{}).
		Build()

	base := &resource.VaultResource[*v1alpha1.OpenBaoPKISecretEngineConfig]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoPKISecretEngineConfigFinalizer,
		Handlers:      OpenBaoPKISecretEngineConfigHandlers(cl, scheme, fb),
	}
	return &OpenBaoPKISecretEngineConfigReconciler{VaultResource: base}
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

func sampleConfig(name string) *v1alpha1.OpenBaoPKISecretEngineConfig {
	c := &v1alpha1.OpenBaoPKISecretEngineConfig{}
	c.Name = name
	c.Namespace = envtestNS
	c.Spec.Path = pkiPath
	c.Spec.Type = "root"
	c.Spec.CommonName = testCommonName
	c.Spec.IssuingCertificates = []string{"https://example.com/ca"}
	return c
}

func sampleIntermediateInternal() *v1alpha1.OpenBaoPKISecretEngineConfig {
	c := &v1alpha1.OpenBaoPKISecretEngineConfig{}
	c.Name = "pki-int"
	c.Namespace = envtestNS
	c.Spec.Path = pkiPath
	c.Spec.Type = "intermediate"
	c.Spec.CommonName = "Test Intermediate"
	c.Spec.InternalSign = &v1alpha1.PKIInternalSign{Name: "pki-root"}
	c.Spec.PermittedDnsDomains = []string{"svc.cluster.local"}
	return c
}

func sampleIntermediateExternal(name, signSecret string) *v1alpha1.OpenBaoPKISecretEngineConfig {
	c := &v1alpha1.OpenBaoPKISecretEngineConfig{}
	c.Name = name
	c.Namespace = envtestNS
	c.Spec.Path = pkiPath
	c.Spec.Type = "intermediate"
	c.Spec.CommonName = "Test Intermediate External"
	c.Spec.ExternalSignSecret = &corev1.LocalObjectReference{Name: signSecret}
	return c
}

func csrSecretFor(t *testing.T, r *OpenBaoPKISecretEngineConfigReconciler, crName string) (*corev1.Secret, bool) {
	t.Helper()
	var sec corev1.Secret
	err := r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: crName + "-intermediate-csr"}, &sec)
	if err != nil {
		return nil, false
	}
	return &sec, true
}

func reconcile(t *testing.T, r *OpenBaoPKISecretEngineConfigReconciler, name string) ctrl.Result {
	t.Helper()
	res, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: envtestNS, Name: name},
	})
	require.NoError(t, err)
	return res
}

func getCfg(t *testing.T, r *OpenBaoPKISecretEngineConfigReconciler, name string) *v1alpha1.OpenBaoPKISecretEngineConfig {
	t.Helper()
	var c v1alpha1.OpenBaoPKISecretEngineConfig
	require.NoError(t, r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: name}, &c))
	return &c
}

// ---- tests ----

func TestPKIConfig_CreatePath_GeneratesCAAndWritesURLs(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // write

	require.Equal(t, 1, fb.generates, "first reconcile must generate CA")
	require.GreaterOrEqual(t, fb.writeURLs, 1, "URLs must be written")

	got := getCfg(t, r, c.Name)
	require.Equal(t, v1alpha1.PhaseActive, got.Status.Phase, "phase must be Active after generate")
	require.NotEmpty(t, got.Status.CASerialNumber, "serial must be captured from bao response")
}

// A root CA with a long spec.TTL must have its mount's max_lease_ttl raised
// BEFORE generate — otherwise bao caps the CA cert to the mount default
// (768h) and a 20-year root is silently issued for ~32 days.
func TestPKIConfig_CreatePath_TunesMaxLeaseTTLBeforeGenerate(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-cfg")
	c.Spec.TTL = metav1.Duration{Duration: 175200 * time.Hour}
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // write

	require.Equal(t, 1, fb.generates, "CA must be generated")
	require.Equal(t, "175200h0m0s", fb.lastTuneMaxLeaseTTL,
		"mount max_lease_ttl must be tuned to cover spec.TTL before generating")
	require.Equal(t, []string{"tune", "generate-root"}, fb.callOrder,
		"tune must run before generate-root so bao does not cap the CA to the 768h default")
}

// Destructive-overwrite guard: the second reconcile (or any later one)
// must NOT call GenerateRootPKI again. Calling it would overwrite the
// CA's private key and silently invalidate every cert ever issued by
// the previous CA. This is the most important invariant for PKIConfig.
func TestPKIConfig_DestructiveOverwriteGuard(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	// First create — generate fires once.
	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	require.Equal(t, 1, fb.generates, "create path: generate runs once")

	// Multiple later reconciles — generate must NEVER fire again.
	for i := 0; i < 5; i++ {
		reconcile(t, r, c.Name)
	}
	require.Equal(t, 1, fb.generates,
		"DESTRUCTIVE OVERWRITE: GenerateRootPKI must not be called once a CA exists; would destroy private key")
}

// URL-only update: changing spec.urls drives a writeURLs call but
// leaves the CA untouched.
func TestPKIConfig_UpdatePath_URLsOnly(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	urlsAfterCreate := fb.writeURLs

	// Change URL spec, bump generation.
	cur := getCfg(t, r, c.Name)
	cur.Spec.IssuingCertificates = []string{"https://new.example.com/ca"}
	require.NoError(t, r.Update(context.Background(), cur))

	reconcile(t, r, c.Name)

	require.Equal(t, 1, fb.generates, "URL change must NOT regenerate the CA")
	require.Greater(t, fb.writeURLs, urlsAfterCreate, "URL change must propagate via WritePKIURLs")
}

// IsDeletable=false branch: deleting the CR releases the finalizer
// without calling BaoDelete (or any bao-side teardown). The CA stays
// in bao indefinitely.
func TestPKIConfig_DeletePath_IsDeletableFalse_PreservesCA(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	require.Equal(t, 1, fb.generates)
	caKey := key("", pkiPath)
	require.Contains(t, fb.caBySerial, caKey, "CA must exist before delete")

	// Now delete the CR.
	cur := getCfg(t, r, c.Name)
	require.NoError(t, r.Delete(context.Background(), cur))
	reconcile(t, r, c.Name)

	// CR should be gone.
	var post v1alpha1.OpenBaoPKISecretEngineConfig
	err := r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: c.Name}, &post)
	require.Error(t, err, "CR must be deleted (finalizer released)")

	// Bao state must NOT be touched — IsDeletable=false guards the CA.
	require.Contains(t, fb.caBySerial, caKey,
		"IsDeletable=false: bao CA must survive CR delete; private key is irreplaceable")
}

// Collision: older creationTimestamp wins. Younger CR pointed at the
// same (path, openbaoNamespace) tuple goes Ready=False with reason
// NameCollision.
func TestPKIConfig_NameCollision_OlderWins(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()

	older := sampleConfig("older")
	older.UID = "uid-older"
	older.CreationTimestamp = metav1.Now()

	younger := sampleConfig("younger")
	younger.UID = "uid-younger"
	younger.CreationTimestamp = metav1.NewTime(older.CreationTimestamp.Add(1))

	r := buildReconciler(t, fb, older, younger)

	reconcile(t, r, older.Name)
	reconcile(t, r, older.Name)
	require.Equal(t, 1, fb.generates, "older must own the CA")

	reconcile(t, r, younger.Name)
	reconcile(t, r, younger.Name)
	require.Equal(t, 1, fb.generates,
		"younger CR must NOT regenerate; collision check guards the destructive call")

	cond := readyCond(t, getCfg(t, r, younger.Name))
	require.NotNil(t, cond)
	require.Equal(t, resource.ReasonNameCollision, cond.Reason)
}

// Backfill in steady state: BaoWrite has run successfully, status
// shows Phase=Active and a serial. A subsequent reconcile (no spec
// drift, URLs match bao) must NOT call writeURLs again — that's
// busywork and surfaces as periodic write storms in audit logs.
func TestPKIConfig_SteadyState_DoesNotRewriteURLs(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // create CA + write URLs
	urlsAfterCreate := fb.writeURLs

	// Steady-state reconcile — no spec change, bao matches.
	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)

	require.Equal(t, urlsAfterCreate, fb.writeURLs,
		"steady-state reconcile must NOT re-write URLs — bao state already matches")
}

// Backfill on status-incomplete CR: a CR with status.Phase blank
// (e.g. controller upgrade introduced new status fields, or a
// previous reconcile's status patch was rejected) must catch up to
// observed bao state on the next reconcile via the Backfill hook,
// even if no BaoWrite is needed.
func TestPKIConfig_BackfillStampsPhaseFromObservedState(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	// Pre-populate bao with a CA + matching URLs.
	fb.caBySerial[key("", pkiPath)] = &baoclient.PKICAResponse{SerialNumber: "stale-status-serial"}
	fb.urls[key("", pkiPath)] = &baoclient.PKIURLsInput{
		IssuingCertificates: []string{"https://example.com/ca"},
	}

	// CR with empty status — represents controller upgrade or earlier
	// failed status patch.
	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // bao matches; no BaoWrite

	require.Equal(t, 0, fb.generates, "must not regenerate")
	got := getCfg(t, r, c.Name)
	require.Equal(t, v1alpha1.PhaseActive, got.Status.Phase,
		"Backfill hook must stamp Phase=Active when bao has a CA but status is empty")
	require.Equal(t, "stale-status-serial", got.Status.CASerialNumber,
		"Backfill must populate serial from observed bao state")
}

// Backfill on adoption: a CR pointed at an existing bao CA (created
// by an earlier CR or out of band) must end up with Phase=Active and
// CASerialNumber populated, even though BaoWrite doesn't generate.
// This relies on the PostWrite-mutator path: if the fakeBao's
// existing CA is observed, the mutator stamps phase/serial.
func TestPKIConfig_AdoptsExistingCA_PopulatesPhaseAndSerial(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	// Pre-populate bao with a CA the controller didn't create.
	preexisting := &baoclient.PKICAResponse{SerialNumber: "out-of-band-serial", Certificate: "PEM"}
	fb.caBySerial[key("", pkiPath)] = preexisting

	c := sampleConfig("pki-cfg")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // write — adopts existing CA

	got := getCfg(t, r, c.Name)
	require.Equal(t, 0, fb.generates,
		"existing CA must NOT be regenerated (destructive overwrite guard)")
	require.Equal(t, v1alpha1.PhaseActive, got.Status.Phase,
		"adopting an existing CA must still flip phase to Active via the StatusMutator")
	require.Equal(t, "out-of-band-serial", got.Status.CASerialNumber,
		"serial of the adopted CA must be captured via the StatusMutator")
}

// ---- intermediate: internalSign ----

func TestPKIConfig_Intermediate_InternalSign_HappyPath(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleIntermediateInternal()
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // generate CSR → sign → set-signed

	require.Equal(t, 0, fb.generates, "intermediate must not call root/generate")
	require.Equal(t, 1, fb.genCSRs, "CSR generated once")
	require.Equal(t, 1, fb.signs, "CSR signed once")
	require.Equal(t, 1, fb.setSigneds, "signed cert bound once")
	require.Equal(t, []string{"generate-csr", "sign", "set-signed"}, fb.callOrder,
		"ordering must be generate→sign→set-signed")
	require.Equal(t, "pki-root", fb.lastSignRoot, "internalSign.Name is used as the root mount")
	require.Equal(t, "FAKE-CSR-"+pkiPath, fb.lastSignCSR, "the generated CSR must be the one signed")

	// Backward-compat: no internalSign.openbaoNamespace ⇒ all three calls run
	// in the intermediate's own namespace (here the root openbao namespace, "").
	require.Equal(t, "", fb.lastGenCSRNS, "generate runs in the intermediate namespace")
	require.Equal(t, "", fb.lastSignNS, "sign runs in the intermediate namespace when no cross-ns set")
	require.Equal(t, "", fb.lastSetSignedNS, "set-signed runs in the intermediate namespace")

	// CSR persisted in an owner-ref'd Secret.
	sec, ok := csrSecretFor(t, r, c.Name)
	require.True(t, ok, "CSR Secret must exist")
	require.Equal(t, "FAKE-CSR-"+pkiPath, string(sec.Data["csr"]))
	require.Len(t, sec.OwnerReferences, 1, "CSR Secret must be owner-ref'd to the CR")
	require.Equal(t, "OpenBaoPKISecretEngineConfig", sec.OwnerReferences[0].Kind)
	require.NotNil(t, sec.OwnerReferences[0].Controller)
	require.True(t, *sec.OwnerReferences[0].Controller)

	got := getCfg(t, r, c.Name)
	require.Equal(t, v1alpha1.PhaseActive, got.Status.Phase)
	require.Equal(t, "intermediate-serial", got.Status.CASerialNumber)
	require.True(t, got.Status.Generated)
	require.True(t, got.Status.Exported)
	require.True(t, got.Status.Signed)
}

// Cross-namespace internalSign: the sign call targets the signing CA's
// namespace, while generate + set-signed stay in the intermediate's namespace.
func TestPKIConfig_Intermediate_InternalSign_CrossNamespace(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleIntermediateInternal()
	c.Spec.OpenBaoNamespace = "team-x/"
	c.Spec.InternalSign = &v1alpha1.PKIInternalSign{Name: "pki-platform", OpenBaoNamespace: "platform/"}
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // generate (team-x/) → sign (platform/) → set-signed (team-x/)

	require.Equal(t, 1, fb.genCSRs)
	require.Equal(t, 1, fb.signs)
	require.Equal(t, 1, fb.setSigneds)
	require.Equal(t, "pki-platform", fb.lastSignRoot, "signs against the platform mount")
	require.Equal(t, "platform/", fb.lastSignNS, "sign call targets the platform namespace")
	require.Equal(t, "team-x/", fb.lastGenCSRNS, "CSR is generated in the intermediate's namespace")
	require.Equal(t, "team-x/", fb.lastSetSignedNS, "set-signed runs in the intermediate's namespace")

	got := getCfg(t, r, c.Name)
	require.Equal(t, v1alpha1.PhaseActive, got.Status.Phase)
	require.True(t, got.Status.Signed)
}

func TestPKIConfig_Intermediate_InternalSign_Idempotent(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	// Pre-populate an active CA + matching (empty) URLs.
	fb.caBySerial[key("", pkiPath)] = &baoclient.PKICAResponse{SerialNumber: "already-signed"}
	c := sampleIntermediateInternal()
	c.Spec.PermittedDnsDomains = nil // no URLs either → bao already matches
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // bao already has CA → no sign flow

	require.Equal(t, 0, fb.genCSRs, "active CA must not regenerate a CSR")
	require.Equal(t, 0, fb.signs)
	require.Equal(t, 0, fb.setSigneds)
	_, ok := csrSecretFor(t, r, c.Name)
	require.False(t, ok, "no CSR Secret when the intermediate is already signed")
}

func TestPKIConfig_Intermediate_InternalSign_SignFails_ReusesCSR(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	fb.signErr = errors.New("boom: root mount cannot sign")
	c := sampleIntermediateInternal()
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // CSR generated + stored, sign fails
	reconcile(t, r, c.Name) // sign retried, CSR reused (no regen)

	require.Equal(t, 1, fb.genCSRs, "CSR must be generated once and reused across sign retries")
	require.Equal(t, 2, fb.signs, "sign retried")
	require.Equal(t, 0, fb.setSigneds, "set-signed never reached when sign fails")

	cond := readyCond(t, getCfg(t, r, c.Name))
	require.NotNil(t, cond)
	require.Equal(t, resource.ReasonBaoError, cond.Reason)
}

// ---- intermediate: externalSignSecret ----

func TestPKIConfig_Intermediate_ExternalSign_Pass1_CreatesCSRAndAwaits(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleIntermediateExternal("pki-ext", "team-signed")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // generate CSR → create Secret → await

	require.Equal(t, 1, fb.genCSRs)
	require.Equal(t, 0, fb.signs, "external flow never calls sign-intermediate")
	require.Equal(t, 0, fb.setSigneds, "cannot set-signed until the offline cert lands")

	sec, ok := csrSecretFor(t, r, c.Name)
	require.True(t, ok, "CSR Secret must be created for the offline signer")
	require.Equal(t, "FAKE-CSR-"+pkiPath, string(sec.Data["csr"]))

	cond := readyCond(t, getCfg(t, r, c.Name))
	require.NotNil(t, cond)
	require.Equal(t, resource.ReasonAwaitingExternalSignature, cond.Reason)
}

func TestPKIConfig_Intermediate_ExternalSign_AwaitingNoRegen(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleIntermediateExternal("pki-ext", "team-signed")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // pass 1: CSR created, await
	reconcile(t, r, c.Name) // pass 2: still awaiting, must NOT regenerate
	reconcile(t, r, c.Name) // pass 3: still awaiting

	require.Equal(t, 1, fb.genCSRs, "CSR must be generated exactly once while awaiting signature (R4)")
	require.Equal(t, 0, fb.setSigneds)
	cond := readyCond(t, getCfg(t, r, c.Name))
	require.NotNil(t, cond)
	require.Equal(t, resource.ReasonAwaitingExternalSignature, cond.Reason)
}

func TestPKIConfig_Intermediate_ExternalSign_Completion(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleIntermediateExternal("pki-ext", "team-signed")
	signSec := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "team-signed", Namespace: envtestNS},
		Data: map[string][]byte{
			"tls.crt": []byte("-----BEGIN CERTIFICATE-----\nOFFLINE-SIGNED\n-----END CERTIFICATE-----"),
		},
	}
	r := buildReconciler(t, fb, c, signSec)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // pass 1: CSR created, await (signer hasn't run against THIS csr yet)
	reconcile(t, r, c.Name) // pass 2: signed cert present → set-signed → Active

	require.Equal(t, 1, fb.genCSRs, "CSR generated once")
	require.Equal(t, 1, fb.setSigneds, "signed cert bound once")
	require.Contains(t, fb.lastSetSigned, "OFFLINE-SIGNED", "the offline cert must be the one bound")

	got := getCfg(t, r, c.Name)
	require.Equal(t, v1alpha1.PhaseActive, got.Status.Phase)
	require.Equal(t, "intermediate-serial", got.Status.CASerialNumber)
	require.True(t, got.Status.Generated)
	require.True(t, got.Status.Exported)
	require.True(t, got.Status.Signed)
}

// Regression: type=root must take the unchanged generate path — no
// intermediate calls, no CSR Secret, never AwaitingExternalSignature.
func TestPKIConfig_RootPath_NoIntermediateCalls_NoCSRSecret(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-root")
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // generate root

	require.Equal(t, 1, fb.generates)
	require.Equal(t, 0, fb.genCSRs)
	require.Equal(t, 0, fb.signs)
	require.Equal(t, 0, fb.setSigneds)
	require.Equal(t, []string{"generate-root"}, fb.callOrder)

	_, ok := csrSecretFor(t, r, c.Name)
	require.False(t, ok, "root must not create a CSR Secret")

	cond := readyCond(t, getCfg(t, r, c.Name))
	require.NotNil(t, cond)
	require.Equal(t, resource.ReasonReconciled, cond.Reason,
		"root path must never enter AwaitingExternalSignature")
}

// ---- publishCABundleConfigMap ----

func getCM(t *testing.T, r *OpenBaoPKISecretEngineConfigReconciler) (*corev1.ConfigMap, bool) {
	t.Helper()
	var cm corev1.ConfigMap
	if err := r.Get(context.Background(), types.NamespacedName{Namespace: envtestNS, Name: caBundleCMName}, &cm); err != nil {
		return nil, false
	}
	return &cm, true
}

func TestPKIConfig_PublishCABundle_CreatesOwnedConfigMap(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-root")
	c.Spec.PublishCABundleConfigMap = caBundleCMName
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name) // finalizer
	reconcile(t, r, c.Name) // generate CA + publish bundle

	cm, ok := getCM(t, r)
	require.True(t, ok, "CA-bundle ConfigMap must be created")
	require.Contains(t, cm.Data["ca.crt"], "BEGIN CERTIFICATE")
	require.Len(t, cm.OwnerReferences, 1, "ConfigMap must be owner-ref'd to the CR")
	require.Equal(t, "OpenBaoPKISecretEngineConfig", cm.OwnerReferences[0].Kind)
}

func TestPKIConfig_PublishCABundle_Idempotent(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-root")
	c.Spec.PublishCABundleConfigMap = caBundleCMName
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	cm1, ok := getCM(t, r)
	require.True(t, ok)
	rv := cm1.ResourceVersion

	// Steady-state reconciles must not rewrite the ConfigMap (equality check).
	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	cm2, ok := getCM(t, r)
	require.True(t, ok)
	require.Equal(t, rv, cm2.ResourceVersion, "matching bundle must not be re-written")
}

func TestPKIConfig_PublishCABundle_SelfHealsWhenDeleted(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-root")
	c.Spec.PublishCABundleConfigMap = caBundleCMName
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	cm, ok := getCM(t, r)
	require.True(t, ok)

	// Delete the ConfigMap out-of-band; the drift check must republish it.
	require.NoError(t, r.Delete(context.Background(), cm))
	_, ok = getCM(t, r)
	require.False(t, ok, "ConfigMap should be gone after delete")

	reconcile(t, r, c.Name)
	_, ok = getCM(t, r)
	require.True(t, ok, "deleted CA-bundle ConfigMap must be republished (self-heal)")
}

// replaceCAAtMount swaps the CA the fake serves at pkiPath, modelling a CA
// replacement (new mount adopted, or the CA regenerated in place).
func replaceCAAtMount(fb *fakeBao, serial, cert string) {
	fb.caBySerial[key("", pkiPath)] = &baoclient.PKICAResponse{SerialNumber: serial, Certificate: cert}
}

func TestPKIConfig_PublishCABundle_FirstPublishHasNoPreviousKey(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-root")
	c.Spec.PublishCABundleConfigMap = caBundleCMName
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)

	cm, ok := getCM(t, r)
	require.True(t, ok)
	require.Contains(t, cm.Data[caBundleKey], "BEGIN CERTIFICATE")
	_, hasPrev := cm.Data[caPreviousBundleKey]
	require.False(t, hasPrev, "nothing has been replaced yet, so no retained CA")
}

// A CA replacement must keep the outgoing CA distributable: certs it issued stay
// in use until every workload re-issues, and they only validate while verifiers
// still trust it.
func TestPKIConfig_PublishCABundle_RetainsReplacedCA(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-root")
	c.Spec.PublishCABundleConfigMap = caBundleCMName
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	cm, ok := getCM(t, r)
	require.True(t, ok)
	firstCA := cm.Data[caBundleKey]
	require.NotEmpty(t, firstCA)

	const secondCA = "-----BEGIN CERTIFICATE-----\nREPLACEMENT\n-----END CERTIFICATE-----\n"
	replaceCAAtMount(fb, "replacement-serial", secondCA)
	reconcile(t, r, c.Name)

	cm, ok = getCM(t, r)
	require.True(t, ok)
	require.Equal(t, secondCA, cm.Data[caBundleKey], "active key must hold the new CA")
	require.Equal(t, firstCA, cm.Data[caPreviousBundleKey], "replaced CA must be retained")
}

// Retention is bounded at one: the overlap window spans a single replacement, so
// a second replacement drops the CA before it rather than growing the ConfigMap.
func TestPKIConfig_PublishCABundle_RetainsOnlyMostRecentReplacedCA(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-root")
	c.Spec.PublishCABundleConfigMap = caBundleCMName
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	cm, ok := getCM(t, r)
	require.True(t, ok)
	firstCA := cm.Data[caBundleKey]

	const secondCA = "-----BEGIN CERTIFICATE-----\nSECOND\n-----END CERTIFICATE-----\n"
	replaceCAAtMount(fb, "second-serial", secondCA)
	reconcile(t, r, c.Name)

	const thirdCA = "-----BEGIN CERTIFICATE-----\nTHIRD\n-----END CERTIFICATE-----\n"
	replaceCAAtMount(fb, "third-serial", thirdCA)
	reconcile(t, r, c.Name)

	cm, ok = getCM(t, r)
	require.True(t, ok)
	require.Equal(t, thirdCA, cm.Data[caBundleKey])
	require.Equal(t, secondCA, cm.Data[caPreviousBundleKey], "retains the CA it just replaced")
	require.NotContains(t, cm.Data[caPreviousBundleKey], firstCA, "older CA is dropped")
}

// Retention must not fire on a blank active key — there is nothing certs in the
// field were issued by, so publishing an empty retained CA would be noise.
func TestPKIConfig_PublishCABundle_BlankActiveKeyNotRetained(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-root")
	c.Spec.PublishCABundleConfigMap = caBundleCMName
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	cm, ok := getCM(t, r)
	require.True(t, ok)

	cm.Data[caBundleKey] = "   "
	require.NoError(t, r.Update(context.Background(), cm))
	reconcile(t, r, c.Name)

	cm, ok = getCM(t, r)
	require.True(t, ok)
	require.Contains(t, cm.Data[caBundleKey], "BEGIN CERTIFICATE", "active CA republished")
	_, hasPrev := cm.Data[caPreviousBundleKey]
	require.False(t, hasPrev, "blank outgoing value must not be retained")
}

// The published ConfigMap is a trust root. A consumer that takes every key (the
// only way to pick up ca-previous.crt without a dangling source) would trust any
// cert a third party wrote in, so unmanaged keys must be pruned, not preserved.
func TestPKIConfig_PublishCABundle_PrunesUnmanagedKeys(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-root")
	c.Spec.PublishCABundleConfigMap = caBundleCMName
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	cm, ok := getCM(t, r)
	require.True(t, ok)
	activeCA := cm.Data[caBundleKey]

	cm.Data["rogue.crt"] = "-----BEGIN CERTIFICATE-----\nROGUE\n-----END CERTIFICATE-----\n"
	require.NoError(t, r.Update(context.Background(), cm))

	// Active CA is unchanged, so only the unmanaged key can drive this write.
	reconcile(t, r, c.Name)

	cm, ok = getCM(t, r)
	require.True(t, ok)
	require.NotContains(t, cm.Data, "rogue.crt", "injected trust root must be pruned")
	require.Equal(t, activeCA, cm.Data[caBundleKey], "pruning must not disturb the active CA")
}

// Pruning must not cost the retained CA — otherwise an injected key mid-migration
// would silently end the trust overlap and break certs from the outgoing CA.
func TestPKIConfig_PublishCABundle_PruneKeepsRetainedCA(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-root")
	c.Spec.PublishCABundleConfigMap = caBundleCMName
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	cm, ok := getCM(t, r)
	require.True(t, ok)
	firstCA := cm.Data[caBundleKey]

	const secondCA = "-----BEGIN CERTIFICATE-----\nSECOND\n-----END CERTIFICATE-----\n"
	replaceCAAtMount(fb, "second-serial", secondCA)
	reconcile(t, r, c.Name)

	cm, ok = getCM(t, r)
	require.True(t, ok)
	require.Equal(t, firstCA, cm.Data[caPreviousBundleKey])

	cm.Data["rogue.crt"] = "-----BEGIN CERTIFICATE-----\nROGUE\n-----END CERTIFICATE-----\n"
	require.NoError(t, r.Update(context.Background(), cm))
	reconcile(t, r, c.Name)

	cm, ok = getCM(t, r)
	require.True(t, ok)
	require.NotContains(t, cm.Data, "rogue.crt", "injected key pruned")
	require.Equal(t, secondCA, cm.Data[caBundleKey], "active CA kept")
	require.Equal(t, firstCA, cm.Data[caPreviousBundleKey], "retained CA survives the prune")
}

// When the active mount moves, a different CR takes over publishing the same
// ConfigMap. It must also take over the controller reference — otherwise
// retiring the previous mount garbage-collects the ConfigMap and every consumer
// sourcing it loses the CA.
func TestPKIConfig_PublishCABundle_TakesOverOwnershipFromPreviousPublisher(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-root")
	c.Spec.PublishCABundleConfigMap = caBundleCMName
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	cm, ok := getCM(t, r)
	require.True(t, ok)
	require.Len(t, cm.OwnerReferences, 1)
	require.Equal(t, c.Name, cm.OwnerReferences[0].Name)

	// Model a previous publisher: point the controller ref at a foreign UID.
	cm.OwnerReferences = []metav1.OwnerReference{{
		APIVersion: v1alpha1.GroupVersion.String(),
		Kind:       "OpenBaoPKISecretEngineConfig",
		Name:       "pki-root-old-mount",
		UID:        "00000000-0000-0000-0000-00000000dead",
		Controller: ptrTo(true),
	}}
	require.NoError(t, r.Update(context.Background(), cm))

	// Content already matches, so only the stale owner can drive this write.
	reconcile(t, r, c.Name)

	cm, ok = getCM(t, r)
	require.True(t, ok)
	require.Len(t, cm.OwnerReferences, 1, "the foreign controller ref must be replaced, not appended to")
	require.Equal(t, c.Name, cm.OwnerReferences[0].Name, "publishing CR must own the ConfigMap")
	require.Contains(t, cm.Data[caBundleKey], "BEGIN CERTIFICATE", "takeover must not disturb the CA")
}

func ptrTo[T any](v T) *T { return &v }

// Two CRs publishing one ConfigMap do not merely overwrite each other: each
// prunes the other's cert and takes the controller reference back, so the
// ConfigMap flaps between two CAs forever while both CRs report Ready.
func TestPKIConfig_PublishCABundle_SecondPublisherOfSameConfigMapCollides(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	older := sampleConfig("pki-root")
	older.UID = "uid-older"
	older.Spec.PublishCABundleConfigMap = caBundleCMName
	older.CreationTimestamp = metav1.Now()

	// Different mount, so only the shared ConfigMap target can collide.
	rival := sampleConfig("pki-root-rival")
	rival.UID = "uid-rival"
	rival.Spec.Path = "pki-rival"
	rival.Spec.PublishCABundleConfigMap = caBundleCMName
	rival.CreationTimestamp = metav1.NewTime(older.CreationTimestamp.Add(time.Second))

	r := buildReconciler(t, fb, older, rival)

	reconcile(t, r, older.Name)
	reconcile(t, r, older.Name)
	reconcile(t, r, rival.Name)
	reconcile(t, r, rival.Name)

	olderCond := readyCond(t, getCfg(t, r, older.Name))
	require.NotNil(t, olderCond)
	require.Equal(t, metav1.ConditionTrue, olderCond.Status, "older CR keeps publishing")

	rivalCond := readyCond(t, getCfg(t, r, rival.Name))
	require.NotNil(t, rivalCond)
	require.Equal(t, metav1.ConditionFalse, rivalCond.Status)
	require.Equal(t, resource.ReasonNameCollision, rivalCond.Reason)
	require.Contains(t, rivalCond.Message, caBundleCMName)

	// The winner's CA must be what the ConfigMap holds.
	cm, ok := getCM(t, r)
	require.True(t, ok)
	require.Contains(t, cm.Data[caBundleKey], "BEGIN CERTIFICATE")
	require.Len(t, cm.OwnerReferences, 1)
	require.Equal(t, older.Name, cm.OwnerReferences[0].Name, "rival must not steal ownership")
}

// A CR that publishes no ConfigMap must never collide on that axis.
func TestPKIConfig_PublishCABundle_EmptyTargetNeverCollides(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	a := sampleConfig("pki-root") // no PublishCABundleConfigMap
	a.UID = "uid-a"
	b := sampleConfig("pki-root-two") // no PublishCABundleConfigMap
	b.UID = "uid-b"
	b.Spec.Path = "pki-two"
	r := buildReconciler(t, fb, a, b)

	for _, n := range []string{a.Name, b.Name} {
		reconcile(t, r, n)
		reconcile(t, r, n)
		cond := readyCond(t, getCfg(t, r, n))
		require.NotNil(t, cond)
		require.Equal(t, metav1.ConditionTrue, cond.Status, "%s must not collide", n)
	}
}

func TestPKIConfig_PublishCABundle_EmptyFieldNoConfigMap(t *testing.T) {
	t.Parallel()
	fb := newFakeBao()
	c := sampleConfig("pki-root") // no PublishCABundleConfigMap
	r := buildReconciler(t, fb, c)

	reconcile(t, r, c.Name)
	reconcile(t, r, c.Name)
	got := getCfg(t, r, c.Name)
	require.Equal(t, v1alpha1.PhaseActive, got.Status.Phase, "root still reconciles normally")
	_, ok := getCM(t, r)
	require.False(t, ok, "no ConfigMap when publishCABundleConfigMap is empty")
}

func readyCond(t *testing.T, c *v1alpha1.OpenBaoPKISecretEngineConfig) *metav1.Condition {
	t.Helper()
	for i := range c.Status.Conditions {
		if c.Status.Conditions[i].Type == resource.ConditionReady {
			return &c.Status.Conditions[i]
		}
	}
	return nil
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
