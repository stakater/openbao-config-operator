package openbaopkisecretengineconfig

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// startTestManager runs a manager wired exactly as cmd/main.go wires this
// controller — same SetupWithManager, so the watch configuration under test is
// the real one — against envtest, with an in-memory bao.
func startTestManager(t *testing.T, bao *fakeBao) client.Client {
	t.Helper()
	if testCfg == nil {
		t.Skip("requires envtest; KUBEBUILDER_ASSETS is unset (run via `make test`)")
	}
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme))

	mgr, err := manager.New(testCfg, manager.Options{
		Scheme:         scheme,
		Metrics:        metricsserver.Options{BindAddress: "0"},
		LeaderElection: false,
	})
	require.NoError(t, err)
	require.NoError(t, NewOpenBaoPKISecretEngineConfigReconcilerWithClient(mgr, bao).SetupWithManager(mgr))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			t.Error("manager did not shut down")
		}
	})
	require.True(t, mgr.GetCache().WaitForCacheSync(ctx), "cache did not sync")
	return mgr.GetClient()
}

// TestPublishedCABundleTamperReconcilesPromptly pins the ConfigMap watch.
//
// An unmanaged key added to a published CA bundle is a trust anchor for every
// consumer of that bundle, so the correction must not wait for the periodic
// requeue. Without Owns(&corev1.ConfigMap{}) — or with the generation predicate
// applied cluster-wide, which drops ConfigMap events because ConfigMaps have no
// generation — the prune happens only on the next PeriodicInterval tick. The
// deadline here is far below PeriodicInterval, so either regression fails it
// rather than merely slowing it down.
func TestPublishedCABundleTamperReconcilesPromptly(t *testing.T) {
	bao := newFakeBao()
	cl := startTestManager(t, bao)
	ctx := context.Background()

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "cm-watch-test"}}
	require.NoError(t, client.IgnoreAlreadyExists(cl.Create(ctx, ns)))

	cr := &v1alpha1.OpenBaoPKISecretEngineConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "pki-root", Namespace: ns.Name},
		Spec: v1alpha1.OpenBaoPKISecretEngineConfigSpec{
			Path:                     "pki",
			OpenBaoNamespace:         "tenant-a/",
			Type:                     "root",
			CommonName:               "tenant-a Internal CA",
			PublishCABundleConfigMap: "tenant-a-ca",
		},
	}
	require.NoError(t, cl.Create(ctx, cr))
	t.Cleanup(func() { _ = cl.Delete(ctx, cr) })

	cmKey := client.ObjectKey{Namespace: ns.Name, Name: "tenant-a-ca"}

	// The publisher must get there on its own first, otherwise a "prune" below
	// could just be the initial publish.
	var published corev1.ConfigMap
	require.Eventually(t, func() bool {
		if err := cl.Get(ctx, cmKey, &published); err != nil {
			return false
		}
		return published.Data[caBundleKey] != ""
	}, 60*time.Second, 250*time.Millisecond, "CA bundle was never published")

	tampered := published.DeepCopy()
	if tampered.Data == nil {
		tampered.Data = map[string]string{}
	}
	tampered.Data["rogue.crt"] = "-----BEGIN CERTIFICATE-----\nrogue\n-----END CERTIFICATE-----\n"
	require.NoError(t, cl.Update(ctx, tampered))

	deadline := 30 * time.Second
	require.Less(t, deadline, resource.PeriodicInterval,
		"deadline must be below PeriodicInterval or the periodic requeue could satisfy this test")

	start := time.Now()
	require.Eventually(t, func() bool {
		var got corev1.ConfigMap
		if err := cl.Get(ctx, cmKey, &got); err != nil {
			return false
		}
		_, stillThere := got.Data["rogue.crt"]
		return !stillThere
	}, deadline, 250*time.Millisecond,
		"unmanaged key survived %s; the ConfigMap watch is not delivering events", deadline)
	t.Logf("unmanaged key pruned in %s (PeriodicInterval is %s)", time.Since(start).Round(time.Millisecond), resource.PeriodicInterval)

	// The managed key must survive the prune.
	var final corev1.ConfigMap
	require.NoError(t, cl.Get(ctx, cmKey, &final))
	require.NotEmpty(t, final.Data[caBundleKey], "prune removed the managed CA key")
}
