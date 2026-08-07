package openbaotransitkey

import (
	"context"
	"errors"
	"fmt"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	v1alpha1 "github.com/stakater-ab/mto-extension-openbao/api/v1alpha1"
	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
	"github.com/stakater-ab/mto-extension-openbao/internal/vaultobject/resource"
)

// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaotransitkeys,verbs=get;list;watch;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaotransitkeys/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=security.mto.stakater.com,resources=openbaotransitkeys/finalizers,verbs=update

const OpenBaoTransitKeyFinalizer = "openbaotransitkey.security.mto.stakater.com/finalizer"

type OpenBaoTransitKeyReconciler struct {
	*resource.VaultResource[*v1alpha1.OpenBaoTransitKey]
}

func NewOpenBaoTransitKeyReconcilerWithClient(mgr ctrl.Manager, bao baoclient.Client) *OpenBaoTransitKeyReconciler {
	return &OpenBaoTransitKeyReconciler{
		VaultResource: resource.New[*v1alpha1.OpenBaoTransitKey](
			mgr, OpenBaoTransitKeyFinalizer,
			OpenBaoTransitKeyHandlers(mgr.GetClient(), bao)),
	}
}

// OpenBaoTransitKeyHandlers wires the bao-I/O callbacks. The two-phase
// write (create then config) is hidden behind BaoWrite; the shared base
// drives drift correction by calling BaoGet → IsEquivalentToDesiredState
// → BaoWrite when the comparator sees mutable-field divergence. Type
// immutability is enforced inside BaoWrite via ImmutableMismatch — the
// only place that has both the spec and the bao read shape in scope.
func OpenBaoTransitKeyHandlers(cl client.Client, bao baoclient.Client) resource.Handlers[*v1alpha1.OpenBaoTransitKey] {
	return resource.Handlers[*v1alpha1.OpenBaoTransitKey]{
		NewInstance: func() *v1alpha1.OpenBaoTransitKey { return &v1alpha1.OpenBaoTransitKey{} },

		BaoGet: func(ctx context.Context, k *v1alpha1.OpenBaoTransitKey) (map[string]any, error) {
			ns := baoclient.WithNamespace(k.OpenBaoNamespace())
			info, err := bao.ReadTransitKey(ctx, k.MountPath(), k.BaoName(), ns)
			if errors.Is(err, baoclient.ErrNotFound) {
				return nil, resource.ErrBaoNotFound
			}
			if err != nil {
				return nil, err
			}
			return v1alpha1.PayloadFromTransitKeyInfo(info), nil
		},

		BaoWrite: func(ctx context.Context, k *v1alpha1.OpenBaoTransitKey) (resource.StatusMutator[*v1alpha1.OpenBaoTransitKey], error) {
			if err := checkTransitKeyCollision(ctx, cl, k); err != nil {
				return nil, err
			}
			ns := baoclient.WithNamespace(k.OpenBaoNamespace())

			// Read first to decide create-vs-config and to enforce
			// post-create immutability. This adds one round-trip per
			// BaoWrite call on both the create and update paths. Cost
			// is bounded because the base only enters BaoWrite when
			// BaoGet returned NotFound OR the comparator saw drift —
			// not on every reconcile. The read is the only place spec
			// + bao state coexist for the immutability check.
			info, err := bao.ReadTransitKey(ctx, k.MountPath(), k.BaoName(), ns)
			switch {
			case errors.Is(err, baoclient.ErrNotFound):
				// Create path.
				if err := bao.WriteTransitKey(ctx, k.MountPath(), k.BaoName(), k.ToCreateSpec(), ns); err != nil {
					return nil, err
				}
			case err != nil:
				return nil, err
			default:
				// Update path: enforce immutability before any write.
				if msg, mismatched := k.ImmutableMismatch(info); mismatched {
					return nil, fmt.Errorf("%w: %s (delete the CR and recreate to change immutable fields)",
						resource.ErrInvalidSpec, msg)
				}
			}

			// Always converge the mutable subset. Bao's idempotent
			// behaviour means a no-op call when current==desired is
			// cheap; the comparator on the CR side suppresses calls
			// when current matches, so this only fires on the create
			// or drift paths anyway.
			if err := bao.UpdateTransitKeyConfig(ctx, k.MountPath(), k.BaoName(), k.ToConfigSpec(), ns); err != nil {
				return nil, err
			}

			// Re-read so the post-write status reflects bao's observed
			// state (LatestVersion, CreationTime, capability bools)
			// atomically with Ready=True. The path snapshot is captured
			// here so a simultaneous spec.name + spec.path edit can
			// clean the previous (path, name) tuple — the base's
			// rename tracker carries name+namespace only.
			fresh, err := bao.ReadTransitKey(ctx, k.MountPath(), k.BaoName(), ns)
			if err != nil {
				return nil, err
			}
			pathSnapshot := k.MountPath()
			return func(cur *v1alpha1.OpenBaoTransitKey) {
				cur.SetObservedStatus(fresh)
				cur.Status.LastWrittenPath = pathSnapshot
			}, nil
		},

		BaoDelete: func(ctx context.Context, _ *v1alpha1.OpenBaoTransitKey) error {
			// Never reached: IsDeletable=false short-circuits this in the
			// base. Wired as a safety in case a future spec change flips
			// IsDeletable to true — deleting a transit key destroys the only
			// material that decrypts its ciphertext, so the no-op has to be
			// explicit rather than inherited from whatever the wrapper does.
			return nil
		},

		BaoDeleteIdentity: func(ctx context.Context, _ *v1alpha1.OpenBaoTransitKey, _, _ string) error {
			// Never reached: the base's rename-cleanup path skips
			// BaoDeleteIdentity when IsDeletable=false. A rename leaves the
			// key at the previous (path, name) in bao rather than destroying
			// it. See the type comment for the orphan-by-design rationale.
			return nil
		},

		CheckCollision: func(ctx context.Context, k *v1alpha1.OpenBaoTransitKey) error {
			return checkTransitKeyCollision(ctx, cl, k)
		},

		Backfill: func(k *v1alpha1.OpenBaoTransitKey, current map[string]any) resource.StatusMutator[*v1alpha1.OpenBaoTransitKey] {
			info, _ := current["info"].(*baoclient.TransitKeyInfo)
			pathSnapshot := k.MountPath()
			return func(cur *v1alpha1.OpenBaoTransitKey) {
				cur.SetObservedStatus(info)
				cur.Status.LastWrittenPath = pathSnapshot
			}
		},
	}
}

// checkTransitKeyCollision returns ErrNameCollision when another
// OpenBaoTransitKey CR (different UID) targets the same bao identity.
// Tuple is (openbaoNamespace, mount path, key name); two CRs in
// different OpenBao namespaces don't collide because bao isolates them
// via X-Vault-Namespace, and two CRs at the same key name on different
// mounts don't collide because the bao path differs.
//
// Tie-break: older CreationTimestamp wins; on tie, lex order of
// <namespace>/<name> wins. Mirrors the PKI / Policy collision logic.
func checkTransitKeyCollision(ctx context.Context, cl client.Client, k *v1alpha1.OpenBaoTransitKey) error {
	var all v1alpha1.OpenBaoTransitKeyList
	if err := cl.List(ctx, &all); err != nil {
		return fmt.Errorf("%w: listing OpenBaoTransitKeys for collision check: %v",
			resource.ErrInternal, err)
	}
	targetMount := k.MountPath()
	targetName := k.BaoName()
	targetNS := k.OpenBaoNamespace()
	mineKey := k.Namespace + "/" + k.Name
	for i := range all.Items {
		other := &all.Items[i]
		if other.UID == k.UID {
			continue
		}
		if other.MountPath() != targetMount {
			continue
		}
		if other.BaoName() != targetName {
			continue
		}
		if other.OpenBaoNamespace() != targetNS {
			continue
		}
		var otherWins bool
		switch {
		case other.CreationTimestamp.Before(&k.CreationTimestamp):
			otherWins = true
		case k.CreationTimestamp.Before(&other.CreationTimestamp):
			otherWins = false
		default:
			otherKey := other.Namespace + "/" + other.Name
			otherWins = otherKey < mineKey
		}
		if otherWins {
			return fmt.Errorf("%w: transit key %q (mount=%q, ns=%q) already owned by OpenBaoTransitKey %s/%s",
				resource.ErrNameCollision, targetName, targetMount, targetNS, other.Namespace, other.Name)
		}
	}
	return nil
}

// SetupWithManager registers the controller with a
// GenerationChangedPredicate so status writes do not trigger
// re-reconciles.
func (r *OpenBaoTransitKeyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.OpenBaoTransitKey{}).
		WithEventFilter(predicate.GenerationChangedPredicate{}).
		Complete(r)
}
