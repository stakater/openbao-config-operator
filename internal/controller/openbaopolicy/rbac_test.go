package openbaopolicy

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/yaml"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// envtest runs its apiserver with --authorization-mode=RBAC, but hands tests a
// system:masters config, so every other envtest test here bypasses RBAC
// entirely. These tests instead impersonate a ServiceAccount bound to the
// generated manager ClusterRole, which is what the operator actually runs as.
// That makes an under-granted rule fail here rather than on a cluster.

func loadManagerRules(t *testing.T) []rbacv1.PolicyRule {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "rbac", "role.yaml"))
	require.NoError(t, err)
	var cr rbacv1.ClusterRole
	require.NoError(t, yaml.Unmarshal(raw, &cr))
	require.NotEmpty(t, cr.Rules, "config/rbac/role.yaml parsed with no rules")
	return cr.Rules
}

// grantRules binds rules to a fresh ServiceAccount and returns a client acting
// as it. system:authenticated is impersonated alongside the user so the
// client's discovery calls resolve; it grants no access to any typed resource.
func grantRules(t *testing.T, name string, rules []rbacv1.PolicyRule) client.Client {
	t.Helper()
	if testCfg == nil {
		t.Fatal("RBAC enforcement requires envtest. KUBEBUILDER_ASSETS is unset; " +
			"run via `make test`, not bare `go test ./...`.")
	}

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	admin, err := client.New(testCfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, admin.Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "default"},
	}))
	require.NoError(t, admin.Create(ctx, &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Rules:      rules,
	}))
	require.NoError(t, admin.Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		RoleRef: rbacv1.RoleRef{
			APIGroup: rbacv1.GroupName,
			Kind:     "ClusterRole",
			Name:     name,
		},
		Subjects: []rbacv1.Subject{{
			Kind:      rbacv1.ServiceAccountKind,
			Name:      name,
			Namespace: "default",
		}},
	}))

	asSA := rest.CopyConfig(testCfg)
	asSA.Impersonate = rest.ImpersonationConfig{
		UserName: "system:serviceaccount:default:" + name,
		Groups:   []string{"system:authenticated"},
	}
	cl, err := client.New(asSA, client.Options{Scheme: scheme})
	require.NoError(t, err)
	return cl
}

func reconcileAs(t *testing.T, cl client.Client, name string) error {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	r := &OpenBaoPolicyReconciler{VaultResource: &resource.VaultResource[*v1alpha1.OpenBaoPolicy]{
		Client:        cl,
		Scheme:        scheme,
		FinalizerName: OpenBaoPolicyFinalizer,
		Handlers:      OpenBaoPolicyHandlers(cl, newFakeBao()),
	}}
	_, err := r.Reconcile(context.Background(), ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: name},
	})
	return err
}

func createPolicy(t *testing.T, name string) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	admin, err := client.New(testCfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	require.NoError(t, admin.Create(context.Background(), samplePolicy(name)))
}

// withoutResource returns the manager rules minus one resource, dropping any
// rule left with nothing in it.
func withoutResource(t *testing.T, drop string) []rbacv1.PolicyRule {
	t.Helper()
	all := loadManagerRules(t)
	rules := make([]rbacv1.PolicyRule, 0, len(all))
	for _, r := range all {
		kept := make([]string, 0, len(r.Resources))
		for _, res := range r.Resources {
			if res != drop {
				kept = append(kept, res)
			}
		}
		if len(kept) == 0 {
			continue
		}
		r.Resources = kept
		rules = append(rules, r)
	}
	return rules
}

func readyCondOf(t *testing.T, name string) *metav1.Condition {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, v1alpha1.AddToScheme(scheme))
	admin, err := client.New(testCfg, client.Options{Scheme: scheme})
	require.NoError(t, err)

	var p v1alpha1.OpenBaoPolicy
	require.NoError(t, admin.Get(context.Background(),
		types.NamespacedName{Namespace: "default", Name: name}, &p))
	return apimeta.FindStatusCondition(p.Status.Conditions, resource.ConditionReady)
}

func TestManagerClusterRole_AllowsFullReconcile(t *testing.T) {
	cl := grantRules(t, "rbac-full", loadManagerRules(t))
	createPolicy(t, "rbac-full-policy")

	// Twice, as the other tests in this package do: the first pass installs
	// the finalizer and returns early, so only the second reaches the bao
	// write and the status patch.
	require.NoError(t, reconcileAs(t, cl, "rbac-full-policy"),
		"the generated manager ClusterRole must permit everything a reconcile does")
	require.NoError(t, reconcileAs(t, cl, "rbac-full-policy"))

	// Asserting the condition landed, not just that Reconcile returned nil:
	// the status write is best-effort (see VaultResource.setReady), so a
	// nil error alone would not prove the role granted the status subresource.
	cond := readyCondOf(t, "rbac-full-policy")
	require.NotNil(t, cond, "Ready condition should be written under the full role")
	require.Equal(t, metav1.ConditionTrue, cond.Status)
}

// Negative control. Without this, TestManagerClusterRole_AllowsFullReconcile
// would pass even if RBAC were not enforced at all, making it worthless.
// Revoking read on the primitive must surface as a reconcile error.
func TestManagerClusterRole_WithoutReadIsDenied(t *testing.T) {
	cl := grantRules(t, "rbac-noread", withoutResource(t, "openbaopolicies"))
	createPolicy(t, "rbac-noread-policy")

	err := reconcileAs(t, cl, "rbac-noread-policy")
	require.Error(t, err, "reconcile must fail when read on the primitive is revoked")
	require.True(t, apierrors.IsForbidden(err), "expected a Forbidden error, got %v", err)
}

// A denied status subresource deliberately does not fail the reconcile:
// VaultResource logs the write failure and carries on, so status-write
// problems cannot wedge reconciliation. The cost is that an under-granted
// /status shows up only as a missing Ready condition plus a log line, never
// as a reconcile error. Pinned here so that trade-off changes on purpose.
func TestManagerClusterRole_WithoutStatusStillReconcilesButSkipsCondition(t *testing.T) {
	cl := grantRules(t, "rbac-nostatus", withoutResource(t, "openbaopolicies/status"))
	createPolicy(t, "rbac-nostatus-policy")

	require.NoError(t, reconcileAs(t, cl, "rbac-nostatus-policy"),
		"a denied status write must not gate the reconcile result")
	require.Nil(t, readyCondOf(t, "rbac-nostatus-policy"),
		"Ready must be absent when the status subresource is denied")
}
