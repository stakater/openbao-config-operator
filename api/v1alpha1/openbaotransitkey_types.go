// OpenBaoTransitKey owns a single transit key at <mount>/keys/<name> on
// an existing transit secret-engine mount. Transit is greenfield in this
// project (no upstream VCO equivalent), so this type is authored from
// scratch rather than adapted; the shape matches the bao transit API
// surface at /transit/keys/<name> and /transit/keys/<name>/config.
//
// Type immutability: spec.type, spec.derived, spec.convergentEncryption,
// and spec.keySize are immutable post-create. Bao either silently
// ignores updates or 400s on those fields; the controller surfaces a
// Ready=False reason=Invalid with a "field is immutable post-create"
// message instead of letting the drift loop retry forever.
//
// Pairs with an OpenBaoSecretEngine of kind=transit at the same
// spec.path; the mount must exist before this CR's first reconcile
// succeeds. Ordering is reconcile-driven — without the mount, bao 400s
// the create call and the controller retries.
//
// IsDeletable returns false: deleting the CR must not remove the bao key.
// A transit key is the only copy of the material that decrypts every
// ciphertext ever produced under it, and bao has no undo. The CR is
// derived state — it disappears whenever its source stops rendering it,
// including for reasons that are not a decision to destroy anything
// (an opt-in annotation removed, a values typo, a namespace reaped) — so
// tying key destruction to CR deletion makes routine churn unrecoverable.
// The shared base therefore releases the finalizer without touching bao
// and skips rename-cleanup, and the bao key outlives the CR. Re-creating
// a CR at the same (openbaoNamespace, mount, name) adopts the existing
// key, which makes an accidental removal a no-op rather than data loss.
// Destroying a key is a deliberate act performed against bao directly.
package v1alpha1

import (
	"context"
	"fmt"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject"
)

var _ vaultobject.VaultObject = &OpenBaoTransitKey{}
var _ vaultobject.ConditionsAware = &OpenBaoTransitKey{}
var _ vaultobject.WriteTracker = &OpenBaoTransitKey{}
var _ vaultobject.RenameTracker = &OpenBaoTransitKey{}

// BaoName returns the bao-side key name. spec.name takes precedence
// over metadata.name when set; both go through the same lowercase /
// trim normalization the wrapper sends on the wire.
func (k *OpenBaoTransitKey) BaoName() string {
	raw := k.Spec.Name
	if raw == "" {
		raw = k.Name
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func (k *OpenBaoTransitKey) OpenBaoNamespace() string {
	return strings.TrimSpace(k.Spec.OpenBaoNamespace)
}

// MountPath returns the parent transit mount, normalized (trim leading
// and trailing slashes — bao accepts both forms but the wrapper sends a
// clean path so log lines stay diffable across reconciles).
func (k *OpenBaoTransitKey) MountPath() string {
	return strings.Trim(strings.TrimSpace(k.Spec.Path), "/")
}

// GetPath returns the synthetic identifier used in collision messages
// and logs. Including the mount prefix keeps two keys with the same
// name on different mounts unambiguous.
func (k *OpenBaoTransitKey) GetPath() string {
	return k.MountPath() + "/keys/" + k.BaoName()
}

// GetPayload is unused — the comparator works against the bao read
// shape (TransitKeyInfo) directly via IsEquivalentToDesiredState.
func (k *OpenBaoTransitKey) GetPayload() map[string]interface{} {
	return nil
}

func (k *OpenBaoTransitKey) IsInitialized() bool { return true }

// IsDeletable returns false: see the package comment. CR deletion
// releases the finalizer and leaves the bao key in place.
func (k *OpenBaoTransitKey) IsDeletable() bool { return false }

func (k *OpenBaoTransitKey) PrepareInternalValues(ctx context.Context, object client.Object) error {
	return nil
}

func (k *OpenBaoTransitKey) PrepareTLSConfig(ctx context.Context, object client.Object) error {
	return nil
}

// IsValid catches cross-field invariants kubebuilder markers can't
// express compactly. Bao would 400 on these too, but the controller
// surfaces ReasonInvalid (terminal — no retry) rather than ReasonBaoError
// (transient — requeues every reconcile interval) so the user sees the
// correct signal in `kubectl describe`.
func (k *OpenBaoTransitKey) IsValid() (bool, error) {
	if strings.TrimSpace(k.Spec.Path) == "" {
		return false, fmt.Errorf("spec.path must not be empty")
	}
	if k.BaoName() == "" {
		return false, fmt.Errorf("spec.name must not be empty")
	}
	if strings.TrimSpace(k.Spec.Type) == "" {
		return false, fmt.Errorf("spec.type must not be empty")
	}
	// Convergent encryption requires derived=true on bao's side. The
	// pairing isn't expressible as a single CEL XValidation that's
	// cleaner than this check; this also lets us emit a more useful
	// error message than bao's generic 400.
	if k.Spec.ConvergentEncryption != nil && *k.Spec.ConvergentEncryption {
		if k.Spec.Derived == nil || !*k.Spec.Derived {
			return false, fmt.Errorf("spec.convergentEncryption=true requires spec.derived=true")
		}
	}
	// AutoRotatePeriod must parse as a Go duration. The kubebuilder
	// Pattern catches most garbage, but bypass paths (older clients,
	// direct API writes, pre-marker CRs) can still smuggle in a value
	// that parseAutoRotateSeconds rejects. Without this check the
	// comparator returns drift on every reconcile and the controller
	// loops forever in ReasonBaoError; surface it as terminal
	// ReasonInvalid instead.
	if _, ok := parseAutoRotateSeconds(k.Spec.AutoRotatePeriod); !ok {
		return false, fmt.Errorf("spec.autoRotatePeriod=%q is not a valid Go duration (e.g. \"720h\")",
			k.Spec.AutoRotatePeriod)
	}
	return true, nil
}

// IsEquivalentToDesiredState returns true when the passed bao read shape
// matches the spec on every spec-pinned field — both mutable (driven to
// convergence on the next BaoWrite) and immutable (caught at BaoWrite as
// ErrInvalidSpec). Immutable mismatches must drive the comparator to
// return false too: without that, the base never enters BaoWrite on a
// type/derived/keySize/convergentEncryption edit and the user's
// immutable-field violation goes silently undetected.
//
// Observed-only fields (latest_version, creation_time, supports_*, keys,
// imported_key) are excluded — they're populated on status, not pinned
// in spec, and would otherwise drift on every reconcile.
//
// auto_rotate_period normalization: bao reads return int seconds; spec
// is a Go duration string. Parse the string and compare ints. nil-or-
// empty maps to 0 on either side.
func (k *OpenBaoTransitKey) IsEquivalentToDesiredState(payload map[string]interface{}) bool {
	current, ok := payload["info"].(*baoclient.TransitKeyInfo)
	if !ok || current == nil {
		return false
	}
	// Immutable field divergence must trigger a BaoWrite call so the
	// immutability check inside BaoWrite can return ErrInvalidSpec.
	// Without this, the comparator would say "no drift" and the user's
	// type-change edit would silently no-op.
	if _, mismatched := k.ImmutableMismatch(current); mismatched {
		return false
	}
	if k.Spec.Exportable != nil && current.Exportable != *k.Spec.Exportable {
		return false
	}
	if k.Spec.AllowPlaintextBackup != nil && current.AllowPlaintextBackup != *k.Spec.AllowPlaintextBackup {
		return false
	}
	if k.Spec.DeletionAllowed != nil && current.DeletionAllowed != *k.Spec.DeletionAllowed {
		return false
	}
	if k.Spec.MinDecryptionVersion != nil && current.MinDecryptionVersion != *k.Spec.MinDecryptionVersion {
		return false
	}
	if k.Spec.MinEncryptionVersion != nil && current.MinEncryptionVersion != *k.Spec.MinEncryptionVersion {
		return false
	}
	desiredARP, ok := parseAutoRotateSeconds(k.Spec.AutoRotatePeriod)
	if !ok {
		// Pattern admit, ParseDuration reject: should be impossible
		// given the kubebuilder Pattern, but if someone bypasses
		// validation, treat as drift so the controller surfaces an
		// error on the write rather than silently accepting.
		return false
	}
	return desiredARP == current.AutoRotatePeriod
}

// parseAutoRotateSeconds converts the spec's bao duration string into
// int seconds. Empty string and "0" both mean disabled (= 0 seconds).
// Returns ok=false only when ParseDuration rejects the string; the
// kubebuilder Pattern is supposed to keep that case out of the apiserver,
// but the comparator must be defensive in case a CR predates the
// pattern marker or was written through a path that bypassed admission.
func parseAutoRotateSeconds(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" || s == "0" {
		return 0, true
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, false
	}
	return int(d.Seconds()), true
}

// ToCreateSpec materializes the create-time TransitKeySpec — the fields
// bao accepts on POST <mount>/keys/<name>. Mutable-only fields go
// through ToConfigSpec and a separate /config call.
func (k *OpenBaoTransitKey) ToCreateSpec() baoclient.TransitKeySpec {
	out := baoclient.TransitKeySpec{
		Type:                 strings.TrimSpace(k.Spec.Type),
		KeySize:              copyIntPtr(k.Spec.KeySize),
		Derived:              copyBoolPtr(k.Spec.Derived),
		ConvergentEncryption: copyBoolPtr(k.Spec.ConvergentEncryption),
		Exportable:           copyBoolPtr(k.Spec.Exportable),
		AllowPlaintextBackup: copyBoolPtr(k.Spec.AllowPlaintextBackup),
		AutoRotatePeriod:     strings.TrimSpace(k.Spec.AutoRotatePeriod),
	}
	return out
}

// ToConfigSpec materializes the mutable subset for POST
// <mount>/keys/<name>/config. The fields accepted on both endpoints
// (exportable, allow_plaintext_backup, auto_rotate_period) are repeated
// here so the config call can converge them on subsequent reconciles
// without needing a fresh create.
func (k *OpenBaoTransitKey) ToConfigSpec() baoclient.TransitKeySpec {
	return baoclient.TransitKeySpec{
		MinDecryptionVersion: copyIntPtr(k.Spec.MinDecryptionVersion),
		MinEncryptionVersion: copyIntPtr(k.Spec.MinEncryptionVersion),
		DeletionAllowed:      copyBoolPtr(k.Spec.DeletionAllowed),
		Exportable:           copyBoolPtr(k.Spec.Exportable),
		AllowPlaintextBackup: copyBoolPtr(k.Spec.AllowPlaintextBackup),
		AutoRotatePeriod:     strings.TrimSpace(k.Spec.AutoRotatePeriod),
	}
}

// ImmutableMismatch returns a human-readable message when the bao read
// shows one of the post-create-immutable fields diverging from the spec.
// Only fires when the spec actually pins the field — an unset spec field
// inherits whatever bao defaulted on create.
func (k *OpenBaoTransitKey) ImmutableMismatch(info *baoclient.TransitKeyInfo) (string, bool) {
	if info == nil {
		return "", false
	}
	if specType := strings.TrimSpace(k.Spec.Type); specType != "" && specType != info.Type {
		return fmt.Sprintf("spec.type=%q but bao key has type=%q", specType, info.Type), true
	}
	if k.Spec.Derived != nil && *k.Spec.Derived != info.Derived {
		return fmt.Sprintf("spec.derived=%v but bao key has derived=%v", *k.Spec.Derived, info.Derived), true
	}
	if k.Spec.ConvergentEncryption != nil && *k.Spec.ConvergentEncryption != info.ConvergentEncryption {
		return fmt.Sprintf("spec.convergentEncryption=%v but bao key has convergent_encryption=%v",
			*k.Spec.ConvergentEncryption, info.ConvergentEncryption), true
	}
	// keySize=0 on either side means "not pinned": bao reports 0 for
	// algorithms where size isn't tracked (HMAC, ChaCha20, ECDSA),
	// and a spec keySize of 0 is the Go zero value used by callers
	// who don't pin the field. Comparing only when both sides have a
	// non-zero value avoids false positives on those algorithms.
	if k.Spec.KeySize != nil && *k.Spec.KeySize != 0 && info.KeySize != 0 && *k.Spec.KeySize != info.KeySize {
		return fmt.Sprintf("spec.keySize=%d but bao key has key_size=%d", *k.Spec.KeySize, info.KeySize), true
	}
	return "", false
}

// SetObservedStatus stamps observed-only fields from the bao read onto
// the CR's status. Called from the StatusMutator the controller's
// BaoWrite returns and from the Backfill hook on the no-drift path —
// not from BaoGet, since the shared base re-fetches the CR before
// patching and any mutation done in BaoGet would be lost.
func (k *OpenBaoTransitKey) SetObservedStatus(info *baoclient.TransitKeyInfo) {
	if info == nil {
		return
	}
	k.Status.LatestVersion = info.LatestVersion
	k.Status.CreationTime = info.CreationTime
	k.Status.SupportsEncryption = info.SupportsEncryption
	k.Status.SupportsDecryption = info.SupportsDecryption
	k.Status.SupportsSigning = info.SupportsSigning
	k.Status.SupportsDerivation = info.SupportsDerivation
}

func copyBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func copyIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// payloadFromInfo wraps a bao read in the map shape the shared base's
// BaoGet contract expects. The comparator unwraps via payload["info"].
// Exposed (capitalized) so the controller package can use it.
func PayloadFromTransitKeyInfo(info *baoclient.TransitKeyInfo) map[string]any {
	return map[string]any{"info": info}
}

// OpenBaoTransitKeySpec is the user-facing schema for a transit key.
// Fields fall into three groups (immutable post-create, mutable, accepted
// on both endpoints). See the package comment for the overall design.
type OpenBaoTransitKeySpec struct {
	// Path is the parent transit secret-engine mount (must be type=transit;
	// bao 400s otherwise). Defaults to "transit"; the omitempty JSON tag
	// is intentional — kubebuilder defaulting only fires when the field
	// is absent from the wire body, so without omitempty a Go-side
	// zero-value would serialize as `path: ""` and bypass the default.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_./-]*$`
	// +kubebuilder:default="transit"
	Path string `json:"path,omitempty"`

	// Name is the bao-side transit key name. Required, immutable.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=128
	// +kubebuilder:validation:Pattern:=`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`
	Name string `json:"name"`

	// OpenBaoNamespace targets a bao namespace via X-Vault-Namespace.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^([a-z0-9]([-a-z0-9/]*[a-z0-9])?/?)?$`
	OpenBaoNamespace string `json:"openbaoNamespace,omitempty"`

	// Type is the transit key algorithm. Immutable post-create. omitempty
	// JSON tag is intentional — see Path's note for the kubebuilder
	// defaulting interaction.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=aes128-gcm96;aes256-gcm96;chacha20-poly1305;ed25519;ecdsa-p256;ecdsa-p384;ecdsa-p521;rsa-2048;rsa-3072;rsa-4096;hmac;managed_key
	// +kubebuilder:default="aes256-gcm96"
	Type string `json:"type,omitempty"`

	// KeySize sets the byte size for hmac keys; ignored by every other
	// type. Immutable post-create.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=32
	// +kubebuilder:validation:Maximum=512
	KeySize *int `json:"keySize,omitempty"`

	// Derived enables key derivation (per-context subkeys). Immutable
	// post-create.
	// +kubebuilder:validation:Optional
	Derived *bool `json:"derived,omitempty"`

	// ConvergentEncryption requires derived=true; same plaintext +
	// context yields the same ciphertext. Immutable post-create.
	// +kubebuilder:validation:Optional
	ConvergentEncryption *bool `json:"convergentEncryption,omitempty"`

	// Exportable allows /export. Mutable but one-way: once enabled, bao
	// refuses to disable it. The wrapper surfaces bao's 400 verbatim.
	// +kubebuilder:validation:Optional
	Exportable *bool `json:"exportable,omitempty"`

	// AllowPlaintextBackup permits transit/backup/<name> to include
	// plaintext key material. Same one-way semantics as Exportable.
	// +kubebuilder:validation:Optional
	AllowPlaintextBackup *bool `json:"allowPlaintextBackup,omitempty"`

	// AutoRotatePeriod is a Go duration ("720h"; "30d" is not a Go
	// duration shape — use "720h"). "0" or empty disables auto-rotation.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Pattern:=`^(0|[0-9]+(s|m|h))+$`
	AutoRotatePeriod string `json:"autoRotatePeriod,omitempty"`

	// DeletionAllowed sets the bao-side deletion_allowed flag on the key,
	// which gates DELETE transit/keys/<name> for callers of the bao API.
	// It does not make CR deletion remove the key: this kind never
	// deletes its bao object (see the package comment). Leave it unset to
	// keep bao refusing DELETE on the key; set it true to permit an
	// operator-independent teardown of the key against bao directly.
	// +kubebuilder:validation:Optional
	DeletionAllowed *bool `json:"deletionAllowed,omitempty"`

	// MinDecryptionVersion sets the floor for decrypt operations. 0
	// means all versions allowed.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	MinDecryptionVersion *int `json:"minDecryptionVersion,omitempty"`

	// MinEncryptionVersion sets the floor for encrypt operations. 0
	// means latest.
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Minimum=0
	MinEncryptionVersion *int `json:"minEncryptionVersion,omitempty"`
}

// OpenBaoTransitKeyStatus carries reconciler-managed fields plus
// observed-only fields surfaced from bao on read.
type OpenBaoTransitKeyStatus struct {
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`

	// +optional
	BaoWritten bool `json:"baoWritten,omitempty"`
	// +optional
	LastWrittenBaoName string `json:"lastWrittenBaoName,omitempty"`
	// +optional
	LastWrittenOpenBaoNamespace string `json:"lastWrittenOpenBaoNamespace,omitempty"`

	// LastWrittenPath captures the bao mount path the controller last
	// wrote a key into. Without this, a CR that simultaneously edits
	// spec.name AND spec.path would orphan the old key — the rename-
	// cleanup BaoDeleteIdentity would target the new path and silently
	// 404. Same shape as OpenBaoPKISecretEngineRole's status.
	// +optional
	LastWrittenPath string `json:"lastWrittenPath,omitempty"`

	// LatestVersion is bao's current key version. Apps targeting a
	// specific version pin against this field. Refreshed on every
	// reconcile (≤ PeriodicInterval staleness).
	// +optional
	LatestVersion int `json:"latestVersion,omitempty"`

	// CreationTime is the bao-side key creation timestamp (RFC3339).
	// +optional
	CreationTime string `json:"creationTime,omitempty"`

	// Capability flags surfaced from bao. Useful for callers that want
	// to know "does this key support signing?" without mapping the
	// type field client-side.
	// +optional
	SupportsEncryption bool `json:"supportsEncryption,omitempty"`
	// +optional
	SupportsDecryption bool `json:"supportsDecryption,omitempty"`
	// +optional
	SupportsSigning bool `json:"supportsSigning,omitempty"`
	// +optional
	SupportsDerivation bool `json:"supportsDerivation,omitempty"`
}

func (k *OpenBaoTransitKey) GetConditions() []metav1.Condition {
	return k.Status.Conditions
}

func (k *OpenBaoTransitKey) SetConditions(conditions []metav1.Condition) {
	k.Status.Conditions = conditions
}

func (k *OpenBaoTransitKey) IsBaoWritten() bool { return k.Status.BaoWritten }
func (k *OpenBaoTransitKey) MarkBaoWritten()    { k.Status.BaoWritten = true }

func (k *OpenBaoTransitKey) LastWrittenBaoName() string {
	return k.Status.LastWrittenBaoName
}

func (k *OpenBaoTransitKey) LastWrittenOpenBaoNamespace() string {
	return k.Status.LastWrittenOpenBaoNamespace
}

func (k *OpenBaoTransitKey) SetLastWrittenBaoIdentity(name, namespace string) {
	k.Status.LastWrittenBaoName = name
	k.Status.LastWrittenOpenBaoNamespace = namespace
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,shortName=obtk

// OpenBaoTransitKey is the Schema for the openbaotransitkeys API.
type OpenBaoTransitKey struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   OpenBaoTransitKeySpec   `json:"spec,omitempty"`
	Status OpenBaoTransitKeyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OpenBaoTransitKeyList contains a list of OpenBaoTransitKey.
type OpenBaoTransitKeyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []OpenBaoTransitKey `json:"items"`
}

func init() {
	SchemeBuilder.Register(&OpenBaoTransitKey{}, &OpenBaoTransitKeyList{})
}
