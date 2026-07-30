// Adapted from redhat-cop/vault-config-operator
//
//	api/v1alpha1/pkisecretengineconfig_types.go @ 96082119ec2e84595cc85b87808c3a6bd7aca53b
//	<https://github.com/redhat-cop/vault-config-operator>
//
// Licensed under the Apache License, Version 2.0
// <https://www.apache.org/licenses/LICENSE-2.0>.
//
// The spec field set, names, json tags, and defaults match upstream exactly
// (root + intermediate CA generation, the full PKICommon/PKIConfig field set,
// and the PKIIntermediate signing models), with three deliberate exceptions:
//   - Kind renamed PKISecretEngineConfig → OpenBaoPKISecretEngineConfig.
//   - spec.connection and spec.authentication are NOT carried — this operator
//     authenticates every primitive with a single operator token
//     (VAULT_TOKEN), so per-CR Vault auth has no code path.
//     spec.openbaoNamespace (X-Vault-Namespace target) replaces upstream's
//     authentication.namespace.
//   - spec.publishCABundleConfigMap is ADDED; upstream has no equivalent. Its
//     only Kubernetes write is the exported-private-key Secret, which is
//     created once and never updated. Trust distribution needs the CA cert in
//     Kubernetes and needs it to follow CA changes, which nothing upstream
//     does, so the publisher and its ConfigMap-ownership rules are ours.
//
// Status carries upstream's generated/exported/signed booleans PLUS the
// base-tracking fields this operator's shared VaultResource requires
// (baoWritten, lastWrittenBaoName/OpenBaoNamespace, phase, caSerialNumber).
//
// IsDeletable returns false: deleting the CR must not call BaoDelete because
// there is no bao API to "remove" a CA — disabling the PKI mount destroys the
// private key and silently invalidates every cert ever issued by it. The
// shared base releases the finalizer without touching bao and skips
// rename-cleanup for the same reason.
package v1alpha1

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoPKISecretEngineConfig{}
var _ vaultobject.ConditionsAware = &OpenBaoPKISecretEngineConfig{}
var _ vaultobject.WriteTracker = &OpenBaoPKISecretEngineConfig{}
var _ vaultobject.RenameTracker = &OpenBaoPKISecretEngineConfig{}

// Phase values for status.phase.
const (
	// PhaseActive: CA generated/signed and URL config published. This is the
	// only phase the controller sets; an intermediate awaiting its external
	// signature is surfaced via the Ready condition
	// (reason=AwaitingExternalSignature), not phase — the shared base does not
	// apply a status mutator on the awaiting/error path.
	PhaseActive = "Active"
)

// pkiType values for spec.type.
const (
	PKITypeRoot         = "root"
	PKITypeIntermediate = "intermediate"
)

// BaoName returns the canonical bao identity for this CR — the PKI mount path
// the CA + URLs live under. Trimmed of slashes.
func (d *OpenBaoPKISecretEngineConfig) BaoName() string {
	return strings.Trim(d.Spec.Path, "/")
}

// OpenBaoNamespace returns the bao namespace this CR's API calls target.
// Empty = root.
func (d *OpenBaoPKISecretEngineConfig) OpenBaoNamespace() string {
	return strings.TrimSpace(d.Spec.OpenBaoNamespace)
}

// GetPath is the synthetic identifier used in collision messages and log
// lines. Distinct from spec.path because logs distinguish a PKIConfig at "pki"
// from a PKIRole at "pki" by their kind.
func (d *OpenBaoPKISecretEngineConfig) GetPath() string {
	return "pki/config/" + d.BaoName()
}

// GetPayload is unused by the controller's drift comparator —
// IsEquivalentToDesiredState reads from the comparator's payload arg directly.
// Kept on the interface so the type satisfies VaultObject.
func (d *OpenBaoPKISecretEngineConfig) GetPayload() map[string]interface{} {
	return nil
}

// IsEquivalentToDesiredState compares the bao-side read against the CR's spec.
// Once a CA is active, the only mutable surfaces are the URL config and — when
// spec.publishCABundleConfigMap is set — whether the published CA-bundle
// ConfigMap matches the active CA cert. The CA cert itself is locked because
// regenerating it would destroy the private key. URL comparison is
// order-insensitive because bao stores the lists as sets.
func (d *OpenBaoPKISecretEngineConfig) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	caExists, _ := payload["caExists"].(bool)
	if !caExists {
		return false
	}
	// CA-bundle publishing drift: if the CR wants its CA published and the
	// ConfigMap's content doesn't match the active CA cert (missing, stale, or
	// deleted out-of-band), force a write so it self-heals on the next reconcile.
	// An unmanaged key counts as drift too: the ConfigMap is a trust root, and a
	// consumer taking every key would otherwise trust whatever was written there.
	if strings.TrimSpace(d.Spec.PublishCABundleConfigMap) != "" {
		desiredCA, _ := payload["caCert"].(string)
		publishedCA, _ := payload["publishedCABundle"].(string)
		if strings.TrimSpace(publishedCA) != strings.TrimSpace(desiredCA) {
			return false
		}
		if unmanaged, _ := payload["publishedCABundleUnmanagedKeys"].(bool); unmanaged {
			return false
		}
		// A controller reference left behind by a previous publisher means
		// deleting that object garbage-collects this ConfigMap, so ownership has
		// to move even when the content already matches.
		if staleOwner, _ := payload["publishedCABundleStaleOwner"].(bool); staleOwner {
			return false
		}
	}
	desiredURLs := map[string][]string{
		"issuingCertificates":   sortedCopy(d.Spec.IssuingCertificates),
		"crlDistributionPoints": sortedCopy(d.Spec.CRLDistributionPoints),
		"ocspServers":           sortedCopy(d.Spec.OCSPServers),
	}
	currentURLs, _ := payload["urls"].(map[string][]string)
	currentURLs = sortAndCopyURLs(currentURLs)
	return reflect.DeepEqual(desiredURLs, currentURLs)
}

func sortAndCopyURLs(in map[string][]string) map[string][]string {
	out := map[string][]string{
		"issuingCertificates":   nil,
		"crlDistributionPoints": nil,
		"ocspServers":           nil,
	}
	if in == nil {
		return out
	}
	for k := range out {
		out[k] = sortedCopy(in[k])
	}
	return out
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	sort.Strings(out)
	return out
}

func (d *OpenBaoPKISecretEngineConfig) IsInitialized() bool {
	return true
}

// IsDeletable returns false. See package doc — disabling a PKI mount loses the
// private key irreversibly.
func (d *OpenBaoPKISecretEngineConfig) IsDeletable() bool {
	return false
}

func (d *OpenBaoPKISecretEngineConfig) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}

func (d *OpenBaoPKISecretEngineConfig) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// PKIType returns spec.type, defaulting an empty value to root (mirrors the
// CRD default for structs built outside the API server, e.g. in unit tests).
func (d *OpenBaoPKISecretEngineConfig) PKIType() string {
	if strings.TrimSpace(d.Spec.Type) == "" {
		return PKITypeRoot
	}
	return d.Spec.Type
}

// IsValid validates spec-level invariants beyond what the CRD schema markers
// catch (Pattern / Required / Enum). It rejects ambiguous signing shapes for
// intermediates.
func (d *OpenBaoPKISecretEngineConfig) IsValid() (bool, error) {
	if strings.TrimSpace(d.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must not be empty")
	}
	if strings.TrimSpace(d.Spec.CommonName) == "" {
		return false, fmt.Errorf("spec.commonName must not be empty")
	}
	hasInternal := d.Spec.InternalSign != nil && strings.TrimSpace(d.Spec.InternalSign.Name) != ""
	hasExternal := d.Spec.ExternalSignSecret != nil && strings.TrimSpace(d.Spec.ExternalSignSecret.Name) != ""
	switch d.PKIType() {
	case PKITypeRoot:
		if hasInternal || hasExternal {
			return false, fmt.Errorf("spec.internalSign / spec.externalSignSecret are only valid for type=intermediate")
		}
	case PKITypeIntermediate:
		if hasInternal == hasExternal {
			return false, fmt.Errorf("spec.type=intermediate requires exactly one of spec.internalSign or spec.externalSignSecret")
		}
	default:
		return false, fmt.Errorf("spec.type=%q is not supported; must be %q or %q",
			d.Spec.Type, PKITypeRoot, PKITypeIntermediate)
	}
	return true, nil
}

// OpenBaoPKISecretEngineConfigSpec defines the desired state. Field set, names,
// json tags, and defaults match upstream redhat-cop/vault-config-operator
// exactly, except spec.connection/spec.authentication are dropped (single-token
// model) and spec.openbaoNamespace is added.
type OpenBaoPKISecretEngineConfigSpec struct {
	// Path is the bao-side PKI mount path (e.g. "pki", "pki/internal"). Must
	// match an existing OpenBaoSecretEngine of kind=pki at the same path; the
	// controller does NOT enable the mount itself.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Path string `json:"path"`

	// OpenBaoNamespace targets a specific OpenBao namespace via
	// X-Vault-Namespace. Empty = root. Replaces upstream's
	// authentication.namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// Type selects root vs intermediate CA generation.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum:={"root","intermediate"}
	// +kubebuilder:default="root"
	Type string `json:"type,omitempty"`

	// PrivateKeyType controls whether the generated key stays internal to bao
	// or is exported.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum:={"internal","exported"}
	// +kubebuilder:default="internal"
	PrivateKeyType string `json:"privateKeyType,omitempty"`

	// CommonName is the X.509 CN of the generated CA cert.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	CommonName string `json:"commonName"`

	// AltNames is a comma-separated list of subject-alternative DNS/email names.
	// +kubebuilder:validation:Optional
	AltNames string `json:"altNames,omitempty"`

	// IPSans is a comma-separated list of IP subject-alternative names.
	// +kubebuilder:validation:Optional
	IPSans string `json:"IPSans,omitempty"`

	// URISans is a comma-separated list of URI subject-alternative names.
	// +kubebuilder:validation:Optional
	URISans string `json:"URISans,omitempty"`

	// OtherSans is a comma-separated list of custom OID SANs.
	// +kubebuilder:validation:Optional
	OtherSans string `json:"otherSans,omitempty"`

	// TTL is the validity period of the CA cert (bao duration). Empty = bao
	// default.
	// +kubebuilder:validation:Optional
	TTL metav1.Duration `json:"TTL,omitempty"`

	// Format is the output format of the issued cert.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum:={"pem","pem_bundle","der"}
	// +kubebuilder:default="pem"
	Format string `json:"format,omitempty"`

	// PrivateKeyFormat is the output format of the private key.
	// +kubebuilder:validation:Optional
	PrivateKeyFormat string `json:"privateKeyFormat,omitempty"`

	// KeyType is the public-key algorithm.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum:={"rsa","ec"}
	// +kubebuilder:default="rsa"
	KeyType string `json:"keyType,omitempty"`

	// KeyBits is the key size in bits.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=2048
	KeyBits int `json:"keyBits,omitempty"`

	// MaxPathLength is the CA's pathlen basic constraint. -1 = no limit.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default=-1
	MaxPathLength int `json:"maxPathLength,omitempty"`

	// ExcludeCnFromSans omits the CN from the generated SANs.
	// +kubebuilder:validation:Optional
	ExcludeCnFromSans bool `json:"excludeCnFromSans,omitempty"`

	// PermittedDnsDomains is the X.509 name-constraints DNS allow-list applied
	// to the CA cert.
	// +kubebuilder:validation:Optional
	PermittedDnsDomains []string `json:"permittedDnsDomains,omitempty"`

	// OU is the X.509 subject Organizational Unit.
	// +kubebuilder:validation:Optional
	OU string `json:"ou,omitempty"`

	// Organization is the X.509 subject Organization.
	// +kubebuilder:validation:Optional
	Organization string `json:"organization,omitempty"`

	// Country is the X.509 subject Country.
	// +kubebuilder:validation:Optional
	Country string `json:"country,omitempty"`

	// Locality is the X.509 subject Locality.
	// +kubebuilder:validation:Optional
	Locality string `json:"locality,omitempty"`

	// Province is the X.509 subject Province.
	// +kubebuilder:validation:Optional
	Province string `json:"province,omitempty"`

	// StreetAddress is the X.509 subject Street Address.
	// +kubebuilder:validation:Optional
	StreetAddress string `json:"streetAddress,omitempty"`

	// PostalCode is the X.509 subject Postal Code.
	// +kubebuilder:validation:Optional
	PostalCode string `json:"postalCode,omitempty"`

	// SerialNumber is the X.509 subject Serial Number (not the cert serial).
	// +kubebuilder:validation:Optional
	SerialNumber string `json:"serialNumber,omitempty"`

	// IssuingCertificates are the AIA issuing-cert URLs published in issued certs.
	// +kubebuilder:validation:Optional
	IssuingCertificates []string `json:"issuingCertificates,omitempty"`

	// CRLDistributionPoints are the CRL distribution-point URLs.
	// +kubebuilder:validation:Optional
	CRLDistributionPoints []string `json:"CRLDistributionPoints,omitempty"`

	// OCSPServers are the OCSP responder URLs.
	// +kubebuilder:validation:Optional
	OCSPServers []string `json:"ocspServers,omitempty"`

	// CRLExpiry is the CRL rotation period (bao duration).
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="72h"
	CRLExpiry metav1.Duration `json:"CRLExpiry,omitempty"`

	// CRLDisable turns off CRL building.
	// +kubebuilder:validation:Optional
	CRLDisable bool `json:"CRLDisable,omitempty"`

	// ExternalSignSecret references a Secret holding the externally-signed
	// intermediate cert (offline-root signing). Mutually exclusive with
	// InternalSign. type=intermediate only.
	// +kubebuilder:validation:Optional
	ExternalSignSecret *corev1.LocalObjectReference `json:"externalSignSecret,omitempty"`

	// CertificateKey is the key within ExternalSignSecret holding the signed
	// cert PEM.
	// +kubebuilder:validation:Optional
	// +kubebuilder:default="tls.crt"
	CertificateKey string `json:"certificateKey,omitempty"`

	// InternalSign points at a signing CA mount that signs this intermediate's
	// CSR in-bao. Mutually exclusive with ExternalSignSecret. type=intermediate
	// only. By default the signing CA must live in this CR's openbaoNamespace;
	// set internalSign.openbaoNamespace to sign against a CA in a different
	// OpenBao namespace (e.g. a platform CA signing per-tenant intermediates).
	// +kubebuilder:validation:Optional
	InternalSign *PKIInternalSign `json:"internalSign,omitempty"`

	// PublishCABundleConfigMap, when set, names a ConfigMap (in this CR's
	// namespace) the controller keeps populated with the active CA cert PEM
	// (key "ca.crt"), plus the CA that key held before the last change
	// (key "ca-previous.crt") so both stay trustable while certs issued by the
	// outgoing CA are still in use. It exists so a trust-distribution tool
	// (cert-manager trust-manager) can source this CA for cross-tenant trust
	// bundles; sources must take every key, not just "ca.crt", to get the
	// overlap. Empty = don't publish. The ConfigMap is owner-ref'd to this CR
	// (GC on delete).
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:Pattern:=`^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`
	PublishCABundleConfigMap string `json:"publishCABundleConfigMap,omitempty"`
}

// PKIInternalSign references the signing CA for an in-bao intermediate signing.
type PKIInternalSign struct {
	// Name is the signing CA's bao mount path (e.g. "pki-platform").
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	Name string `json:"name"`

	// OpenBaoNamespace is the signing CA's OpenBao namespace. Empty = the
	// intermediate CR's own openbaoNamespace (same-namespace signing — the
	// historical behavior). Set this to sign against a CA in another namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`
}

// OpenBaoPKISecretEngineConfigStatus defines the observed state.
type OpenBaoPKISecretEngineConfigStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// Generated records that the intermediate CSR was generated (upstream).
	// +optional
	Generated bool `json:"generated,omitempty"`

	// Exported records that the CSR was exported to its Secret (upstream).
	// +optional
	Exported bool `json:"exported,omitempty"`

	// Signed records that the intermediate was signed + set-signed (upstream).
	// +optional
	Signed bool `json:"signed,omitempty"`

	// BaoWritten records whether this CR has ever successfully written a CA.
	// +optional
	BaoWritten bool `json:"baoWritten,omitempty"`

	// LastWrittenBaoName records the PKI mount path last written into.
	// +optional
	LastWrittenBaoName string `json:"lastWrittenBaoName,omitempty"`

	// LastWrittenOpenBaoNamespace tracks the bao namespace context.
	// +optional
	LastWrittenOpenBaoNamespace string `json:"lastWrittenOpenBaoNamespace,omitempty"`

	// Phase tracks the CA-bootstrap state: "" → Active, or
	// AwaitingExternalSignature for an external-sign intermediate.
	// +optional
	Phase string `json:"phase,omitempty"`

	// CASerialNumber is the X.509 serial of the active CA cert.
	// +optional
	CASerialNumber string `json:"caSerialNumber,omitempty"`
}

func (m *OpenBaoPKISecretEngineConfig) GetConditions() []metav1.Condition {
	return m.Status.Conditions
}

func (m *OpenBaoPKISecretEngineConfig) SetConditions(conditions []metav1.Condition) {
	m.Status.Conditions = conditions
}

func (m *OpenBaoPKISecretEngineConfig) IsBaoWritten() bool { return m.Status.BaoWritten }
func (m *OpenBaoPKISecretEngineConfig) MarkBaoWritten()    { m.Status.BaoWritten = true }

func (m *OpenBaoPKISecretEngineConfig) LastWrittenBaoName() string {
	return m.Status.LastWrittenBaoName
}

func (m *OpenBaoPKISecretEngineConfig) LastWrittenOpenBaoNamespace() string {
	return m.Status.LastWrittenOpenBaoNamespace
}

func (m *OpenBaoPKISecretEngineConfig) SetLastWrittenBaoIdentity(name, namespace string) {
	m.Status.LastWrittenBaoName = name
	m.Status.LastWrittenOpenBaoNamespace = namespace
}

// MarkActive records the active CA's serial and flips the phase to Active. The
// intermediate-bootstrap booleans (generated/exported/signed) are stamped by
// the controller's success mutator only for type=intermediate; a root has no
// CSR/sign flow, so MarkActive leaves them untouched.
func (m *OpenBaoPKISecretEngineConfig) MarkActive(serial string) {
	m.Status.Phase = PhaseActive
	m.Status.CASerialNumber = serial
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obpkic
// +kubebuilder:printcolumn:name="Type",type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name="Phase",type=string,JSONPath=`.status.phase`

// OpenBaoPKISecretEngineConfig is the Schema for the
// openbaopkisecretengineconfigs API.
type OpenBaoPKISecretEngineConfig struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoPKISecretEngineConfigSpec   `json:"spec,omitempty"`
	Status OpenBaoPKISecretEngineConfigStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoPKISecretEngineConfigList contains a list of
// OpenBaoPKISecretEngineConfig.
type OpenBaoPKISecretEngineConfigList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoPKISecretEngineConfig `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoPKISecretEngineConfig{}, &OpenBaoPKISecretEngineConfigList{})
}
