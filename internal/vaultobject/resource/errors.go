package resource

import (
	"errors"
	"net/http"

	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
)

// Reason values surfaced in the Ready status condition. These are stable
// strings that dashboards, alerts, and user automation can match against.
const (
	ReasonReconciled    = "Reconciled"
	ReasonInvalid       = "Invalid"
	ReasonForbidden     = "Forbidden"
	ReasonNotFound      = "NotFound"
	ReasonBaoError      = "BaoError"
	ReasonNameCollision = "NameCollision"
	// ReasonInternalError covers controller-side preparation failures (accessor
	// resolution, TLS config setup, k8s lookups during PrepareInternalValues)
	// that have nothing to do with bao itself. Lumping them under BaoError
	// would mislead an operator paging on a Ready=False with reason=BaoError
	// into checking the bao server when the fault is in our preparation step.
	ReasonInternalError = "InternalError"
	// ReasonDeleteBlocked covers the case where bao refuses a delete because
	// a server-side flag forbids it. Surfaced as its own reason so dashboards
	// distinguish "a gate on the bao object must be flipped" from a generic
	// BaoError or a controller-side bug.
	ReasonDeleteBlocked = "DeleteBlocked"
	// ReasonAwaitingExternalSignature covers an intermediate-CA config that has
	// generated and exported its CSR and is waiting for the externally-signed
	// cert to land in its referenced Secret. It is not a failure — the
	// reconcile requeues until the signed cert appears.
	ReasonAwaitingExternalSignature = "AwaitingExternalSignature"
)

// ErrNameCollision is returned by a primitive's BaoWrite callback when it
// detects another CR (different UID) targeting the same bao-side name.
// Bao identifiers (policy names, role names, mount paths) are global within
// a bao namespace; our CRDs are k8s-namespace-scoped. Without this guard,
// two CRs in different k8s namespaces with the same metadata.name (or the
// same spec.name) would silently overwrite each other on every reconcile.
//
// Wrap with fmt.Errorf("%w: ...", ErrNameCollision, ...) so callers can
// errors.Is-detect it; ClassifyErr maps it to ReasonNameCollision.
var ErrNameCollision = errors.New("bao name collision")

// ErrInternal marks failures that are controller-side (k8s apiserver List,
// in-process state resolution) rather than bao-side. Wrap with
// fmt.Errorf("%w: ...", ErrInternal, ...) at the BaoWrite callsite so
// ClassifyErr maps the error to ReasonInternalError instead of misleading
// operators into checking the bao server.
var ErrInternal = errors.New("controller internal error")

// ErrInvalidSpec marks user-spec violations detected after IsValid() — i.e.
// a check that needs bao-state context (post-create immutability, mount-shape
// mismatch). IsValid() runs before any bao read and produces ReasonInvalid
// directly via the base; BaoWrite cannot, so it wraps with ErrInvalidSpec
// to route through ClassifyErr.
var ErrInvalidSpec = errors.New("invalid spec")

// ErrDeleteBlocked marks a delete that bao refused because of a server-side
// flag on the object. Wrap with fmt.Errorf("%w: ...", ErrDeleteBlocked, ...)
// so ClassifyErr produces ReasonDeleteBlocked. The base's handleDelete keeps
// the finalizer in place when BaoDelete returns this, so the CR stays
// Terminating until the gate is flipped — a primitive whose bao object must
// outlive its CR should return IsDeletable=false instead of this, because a
// gate the operator cannot reach on the delete path never clears.
var ErrDeleteBlocked = errors.New("bao delete blocked")

// ErrAwaitingExternalSignature is returned by a primitive's BaoWrite when it
// is waiting on an out-of-band action (e.g. an offline root signing an
// intermediate CSR). It is NOT a failure: the base's error path surfaces
// ReasonAwaitingExternalSignature on Ready=False and requeues at ErrorBackoff,
// while the durable state (the CSR Secret) persists across reconciles. Wrap
// with fmt.Errorf("%w: ...", ErrAwaitingExternalSignature, ...) for context.
var ErrAwaitingExternalSignature = errors.New("awaiting external signature")

// ClassifyErr maps a bao client error to a Reason. Detection is structured:
// the wrapper at internal/client tags every SDK error with HTTP status via
// *baoclient.StatusError, so we never have to string-match an error
// message and risk misclassifying a 500 whose body happens to mention
// "not found".
func ClassifyErr(err error) string {
	if err == nil {
		return ReasonReconciled
	}
	if errors.Is(err, ErrAwaitingExternalSignature) {
		return ReasonAwaitingExternalSignature
	}
	if errors.Is(err, ErrNameCollision) {
		return ReasonNameCollision
	}
	// ErrInvalidSpec and ErrDeleteBlocked precede ErrInternal because a
	// caller may wrap the same underlying cause with whichever sentinel
	// best describes the failure; the more specific reason wins.
	if errors.Is(err, ErrInvalidSpec) {
		return ReasonInvalid
	}
	if errors.Is(err, ErrDeleteBlocked) {
		return ReasonDeleteBlocked
	}
	if errors.Is(err, ErrInternal) {
		return ReasonInternalError
	}
	var se *baoclient.StatusError
	if errors.As(err, &se) {
		switch se.StatusCode {
		case http.StatusForbidden:
			return ReasonForbidden
		case http.StatusNotFound:
			return ReasonNotFound
		default:
			return ReasonBaoError
		}
	}
	// Non-status errors: network failures, context cancellations, etc.
	return ReasonBaoError
}
