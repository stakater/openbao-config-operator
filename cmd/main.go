/*
Copyright 2025 Stakater.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"crypto/tls"
	"flag"
	"os"

	_ "k8s.io/client-go/plugin/pkg/client/auth"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	obxv1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	openbaoauthmethod "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaoauthmethod"
	openbaocertcfg "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaocertauthengineconfig"
	openbaocertrole "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaocertauthenginerole"
	openbaogroup "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaogroup"
	openbaogroupalias "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaogroupalias"
	openbaoitr "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaoidentitytokenrole"
	openbaojwtcfg "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaojwtoidcauthengineconfig"
	openbaojwtrole "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaojwtoidcauthenginerole"
	openbaok8scfg "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaokubernetesauthengineconfig"
	openbaokar "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaokubernetesauthrole"
	openbaonamespace "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaonamespace"
	openbaopkic "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaopkisecretengineconfig"
	openbaopkir "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaopkisecretenginerole"
	openbaopolicy "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaopolicy"
	openbaose "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaosecretengine"
	openbaotk "github.com/stakater-ab/mto-extension-openbao/internal/controller/openbaotransitkey"
	"github.com/stakater-ab/mto-extension-openbao/internal/hmacstore"
	// +kubebuilder:scaffold:imports
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(obxv1alpha1.AddToScheme(scheme))
	// +kubebuilder:scaffold:scheme
}

func main() {
	var metricsAddr string
	var enableLeaderElection bool
	var probeAddr string
	var secureMetrics bool
	var enableHTTP2 bool
	var tlsOpts []func(*tls.Config)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0", "The address the metrics endpoint binds to. "+
		"Use :8443 for HTTPS or :8080 for HTTP, or leave as 0 to disable the metrics service.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElection, "leader-elect", false,
		"Enable leader election for controller manager. "+
			"Enabling this will ensure there is only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	opts := zap.Options{
		Development: true,
	}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()

	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	// if the enable-http2 flag is false (the default), http/2 should be disabled
	// due to its vulnerabilities. More specifically, disabling http/2 will
	// prevent from being vulnerable to the HTTP/2 Stream Cancellation and
	// Rapid Reset CVEs. For more information see:
	// - https://github.com/advisories/GHSA-qppj-fm5r-hxr3
	// - https://github.com/advisories/GHSA-4374-p667-p6c8
	disableHTTP2 := func(c *tls.Config) {
		setupLog.Info("disabling http/2")
		c.NextProtos = []string{"http/1.1"}
	}

	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, disableHTTP2)
	}

	webhookServer := webhook.NewServer(webhook.Options{
		TLSOpts: tlsOpts,
	})

	// Metrics endpoint is enabled in 'config/default/kustomization.yaml'. The Metrics options configure the server.
	// More info:
	// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/metrics/server
	// - https://book.kubebuilder.io/reference/metrics.html
	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		// TODO(user): TLSOpts is used to allow configuring the TLS config used for the server. If certificates are
		// not provided, self-signed certificates will be generated by default. This option is not recommended for
		// production environments as self-signed certificates do not offer the same level of trust and security
		// as certificates issued by a trusted Certificate Authority (CA). The primary risk is potentially allowing
		// unauthorized access to sensitive metrics data. Consider replacing with CertDir, CertName, and KeyName
		// to provide certificates, ensuring the server communicates using trusted and secure certificates.
		TLSOpts: tlsOpts,
	}

	if secureMetrics {
		// FilterProvider is used to protect the metrics endpoint with authn/authz.
		// These configurations ensure that only authorized users and service accounts
		// can access the metrics endpoint. The RBAC are configured in 'config/rbac/kustomization.yaml'. More info:
		// https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.19.0/pkg/metrics/filters#WithAuthenticationAndAuthorization
		metricsServerOptions.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		WebhookServer:          webhookServer,
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElection,
		LeaderElectionID:       "c8b83f41.stakater.cloud",
		// LeaderElectionReleaseOnCancel defines if the leader should step down voluntarily
		// when the Manager ends. This requires the binary to immediately end when the
		// Manager is stopped, otherwise, this setting is unsafe. Setting this significantly
		// speeds up voluntary leader transitions as the new leader don't have to wait
		// LeaseDuration time first.
		//
		// In the default scaffold provided, the program ends immediately after
		// the manager stops, so would be fine to enable this option. However,
		// if you are doing or is intended to do any operation such as perform cleanups
		// after the manager stops then its usage might be unsafe.
		// LeaderElectionReleaseOnCancel: true,
	})
	if err != nil {
		setupLog.Error(err, "unable to start manager")
		os.Exit(1)
	}

	// +kubebuilder:scaffold:builder

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	if err := setupReconcilers(mgr); err != nil {
		setupLog.Error(err, "unable to set up reconcilers")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}

// setupReconcilers wires every controller into the manager. All reconcilers
// share one bao client: auth mode (static token vs. in-cluster Kubernetes
// login) is selected once from the environment by baoclient.NewClientFromEnv.
// Only configuration errors are fatal here — bao reachability is checked
// per-reconcile so a sealed or still-starting bao surfaces as CR conditions
// that heal on requeue, not a crash-looping process.
func setupReconcilers(mgr ctrl.Manager) error {
	// +kubebuilder:scaffold:builder

	bao, err := baoclient.NewClientFromEnv()
	if err != nil {
		return err
	}
	setupLog.Info("bao client configured", "authMethod", baoAuthMethod())

	hmac, err := bootstrapHMACComputer(mgr)
	if err != nil {
		return err
	}

	reconcilers := []interface {
		SetupWithManager(ctrl.Manager) error
	}{
		openbaopolicy.NewOpenBaoPolicyReconcilerWithClient(mgr, bao),
		openbaokar.NewOpenBaoKubernetesAuthRoleReconcilerWithClient(mgr, bao),
		openbaose.NewOpenBaoSecretEngineReconcilerWithClient(mgr, bao),
		openbaonamespace.NewOpenBaoNamespaceReconcilerWithClient(mgr, bao),
		openbaopkic.NewOpenBaoPKISecretEngineConfigReconcilerWithClient(mgr, bao),
		openbaopkir.NewOpenBaoPKISecretEngineRoleReconcilerWithClient(mgr, bao),
		openbaogroup.NewOpenBaoGroupReconcilerWithClient(mgr, bao),
		openbaogroupalias.NewOpenBaoGroupAliasReconcilerWithClient(mgr, bao),
		openbaoitr.NewOpenBaoIdentityTokenRoleReconcilerWithClient(mgr, bao),
		openbaoauthmethod.NewOpenBaoAuthMethodReconcilerWithClient(mgr, bao),
		openbaocertcfg.NewOpenBaoCertAuthEngineConfigReconcilerWithClient(mgr, bao),
		openbaocertrole.NewOpenBaoCertAuthEngineRoleReconcilerWithClient(mgr, bao),
		openbaojwtcfg.NewOpenBaoJWTOIDCAuthEngineConfigReconcilerWithClient(mgr, bao, hmac),
		openbaojwtrole.NewOpenBaoJWTOIDCAuthEngineRoleReconcilerWithClient(mgr, bao),
		openbaok8scfg.NewOpenBaoKubernetesAuthEngineConfigReconcilerWithClient(mgr, bao, hmac),
		openbaotk.NewOpenBaoTransitKeyReconcilerWithClient(mgr, bao),
	}
	for _, r := range reconcilers {
		if err := r.SetupWithManager(mgr); err != nil {
			return err
		}
	}
	return nil
}

// baoAuthMethod reports the effective auth mode for the startup log.
// Mirrors the default in baoclient.NewClientFromEnv.
func baoAuthMethod() string {
	if m := os.Getenv("BAO_AUTH_METHOD"); m != "" {
		return m
	}
	return "token"
}

// bootstrapHMACComputer loads or generates the HMAC key used by the
// auth-config controllers to detect rotation of bao-redacted Secret
// fields.
//
// Name resolution: HMAC_KEY_SECRET_NAME → "mto-openbao-hmac-key".
//
// Namespace resolution chain (first non-empty wins):
//  1. HMAC_KEY_SECRET_NAMESPACE — explicit override, used when the key
//     should live outside the operator's own namespace (e.g. shared
//     across multiple operator installs).
//  2. OPERATOR_NS — convention used elsewhere in this binary; downward-
//     API-injected by the kustomize Deployment.
//  3. "openbao-config-operator-system" — last-ditch literal default for
//     `make run` and tests where neither env var is set.
//
// Uses a non-cached direct client because the manager's cache isn't
// started yet at setup time.
func bootstrapHMACComputer(mgr ctrl.Manager) (hmacstore.Computer, error) {
	name := os.Getenv("HMAC_KEY_SECRET_NAME")
	if name == "" {
		name = "mto-openbao-hmac-key"
	}
	namespace := os.Getenv("HMAC_KEY_SECRET_NAMESPACE")
	if namespace == "" {
		namespace = os.Getenv("OPERATOR_NS")
	}
	if namespace == "" {
		namespace = "openbao-config-operator-system"
	}
	directClient, err := client.New(mgr.GetConfig(), client.Options{Scheme: mgr.GetScheme()})
	if err != nil {
		return nil, err
	}
	return hmacstore.Bootstrap(context.Background(), directClient, name, namespace)
}
