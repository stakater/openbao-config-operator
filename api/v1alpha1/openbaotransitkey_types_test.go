package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"

	baoclient "github.com/stakater-ab/mto-extension-openbao/internal/client"
)

const (
	transitMount   = "transit"
	transitKeyName = "app-key"
	transitTypeAES = "aes256-gcm96"
	transit720h    = "720h"
)

func TestTransitKey_BaoName_PrefersSpecNameAndLowerTrims(t *testing.T) {
	t.Parallel()
	t.Run("spec.name wins over metadata.name", func(t *testing.T) {
		k := &OpenBaoTransitKey{}
		k.Name = "metadata-name"
		k.Spec.Name = "spec-name"
		require.Equal(t, "spec-name", k.BaoName())
	})
	t.Run("metadata.name fallback when spec.name empty", func(t *testing.T) {
		k := &OpenBaoTransitKey{}
		k.Name = "fallback"
		require.Equal(t, "fallback", k.BaoName())
	})
	t.Run("normalization", func(t *testing.T) {
		k := &OpenBaoTransitKey{}
		k.Spec.Name = "  Mixed-Case  "
		require.Equal(t, "mixed-case", k.BaoName())
	})
}

// IsDeletable returns false unconditionally: a transit key holds the only
// material that decrypts its ciphertext, so CR deletion orphans the bao
// key instead of destroying it. spec.deletionAllowed configures bao's own
// gate and must not change this answer.
func TestTransitKey_IsDeletable_IsFalse(t *testing.T) {
	t.Parallel()
	k := &OpenBaoTransitKey{}
	require.False(t, k.IsDeletable())

	k.Spec.DeletionAllowed = ptrBool(true)
	require.False(t, k.IsDeletable(),
		"spec.deletionAllowed is a bao-side flag, not an instruction to delete the key")
}

func TestTransitKey_GetPath_IncludesMountAndName(t *testing.T) {
	t.Parallel()
	k := &OpenBaoTransitKey{}
	k.Spec.Name = transitKeyName
	k.Spec.Path = transitMount
	require.Equal(t, "transit/keys/app-key", k.GetPath())
}

func TestTransitKey_MountPath_TrimsSlashes(t *testing.T) {
	t.Parallel()
	k := &OpenBaoTransitKey{}
	k.Spec.Path = "/transit/"
	require.Equal(t, "transit", k.MountPath())
}

func TestTransitKey_IsValid(t *testing.T) {
	t.Parallel()
	base := func() *OpenBaoTransitKey {
		k := &OpenBaoTransitKey{}
		k.Spec.Path = transitMount
		k.Spec.Name = transitKeyName
		k.Spec.Type = transitTypeAES
		return k
	}
	t.Run("happy path", func(t *testing.T) {
		ok, err := base().IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})
	t.Run("empty path rejected", func(t *testing.T) {
		k := base()
		k.Spec.Path = ""
		ok, err := k.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "spec.path")
	})
	t.Run("empty name rejected", func(t *testing.T) {
		k := base()
		k.Name = ""
		k.Spec.Name = ""
		ok, err := k.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "spec.name")
	})
	t.Run("empty type rejected", func(t *testing.T) {
		k := base()
		k.Spec.Type = ""
		ok, err := k.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "spec.type")
	})
	t.Run("convergent without derived rejected", func(t *testing.T) {
		k := base()
		k.Spec.ConvergentEncryption = ptrBool(true)
		ok, err := k.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "spec.derived")
	})
	t.Run("convergent with derived accepted", func(t *testing.T) {
		k := base()
		k.Spec.ConvergentEncryption = ptrBool(true)
		k.Spec.Derived = ptrBool(true)
		ok, err := k.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})
	// Pattern admit / ParseDuration reject case: pre-marker CRs and
	// API-direct writes can smuggle in a non-Go-duration value. Without
	// this check the controller would loop in ReasonBaoError; surface
	// it as terminal ReasonInvalid instead.
	t.Run("autoRotatePeriod unparseable rejected", func(t *testing.T) {
		k := base()
		k.Spec.AutoRotatePeriod = "30d" // Go duration doesn't accept "d"
		ok, err := k.IsValid()
		require.False(t, ok)
		require.ErrorContains(t, err, "spec.autoRotatePeriod")
	})
	t.Run("autoRotatePeriod empty accepted", func(t *testing.T) {
		k := base()
		k.Spec.AutoRotatePeriod = ""
		ok, err := k.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})
	t.Run("autoRotatePeriod valid duration accepted", func(t *testing.T) {
		k := base()
		k.Spec.AutoRotatePeriod = "720h"
		ok, err := k.IsValid()
		require.True(t, ok)
		require.NoError(t, err)
	})
}

// IsEquivalentToDesiredState returns true only when every spec-pinned
// mutable field matches bao's read shape. Immutable + observed-only
// fields are excluded.
func TestTransitKey_IsEquivalentToDesiredState(t *testing.T) {
	t.Parallel()

	makeInfo := func() *baoclient.TransitKeyInfo {
		return &baoclient.TransitKeyInfo{
			Type:                 transitTypeAES,
			Exportable:           false,
			AllowPlaintextBackup: false,
			AutoRotatePeriod:     2592000, // 720h in seconds
			DeletionAllowed:      true,
			MinDecryptionVersion: 0,
			MinEncryptionVersion: 0,
			LatestVersion:        3, // observed-only — must not affect compare
			SupportsEncryption:   true,
		}
	}

	makeSpec := func() *OpenBaoTransitKey {
		k := &OpenBaoTransitKey{}
		k.Spec.Path = transitMount
		k.Spec.Name = transitKeyName
		k.Spec.Type = transitTypeAES
		k.Spec.Exportable = ptrBool(false)
		k.Spec.AllowPlaintextBackup = ptrBool(false)
		k.Spec.AutoRotatePeriod = transit720h
		k.Spec.DeletionAllowed = ptrBool(true)
		k.Spec.MinDecryptionVersion = ptrInt(0)
		k.Spec.MinEncryptionVersion = ptrInt(0)
		return k
	}

	t.Run("identical state matches", func(t *testing.T) {
		require.True(t, makeSpec().IsEquivalentToDesiredState(PayloadFromTransitKeyInfo(makeInfo())))
	})

	t.Run("auto_rotate_period int↔string normalized", func(t *testing.T) {
		k := makeSpec()
		k.Spec.AutoRotatePeriod = transit720h
		info := makeInfo()
		info.AutoRotatePeriod = 2592000
		require.True(t, k.IsEquivalentToDesiredState(PayloadFromTransitKeyInfo(info)))
	})

	t.Run("auto_rotate_period zero forms equivalent", func(t *testing.T) {
		for _, s := range []string{"", "0"} {
			k := makeSpec()
			k.Spec.AutoRotatePeriod = s
			info := makeInfo()
			info.AutoRotatePeriod = 0
			require.True(t, k.IsEquivalentToDesiredState(PayloadFromTransitKeyInfo(info)),
				"empty/zero auto_rotate_period must map to 0 (got %q)", s)
		}
	})

	t.Run("min_decryption_version drift", func(t *testing.T) {
		k := makeSpec()
		k.Spec.MinDecryptionVersion = ptrInt(2)
		require.False(t, k.IsEquivalentToDesiredState(PayloadFromTransitKeyInfo(makeInfo())))
	})

	t.Run("deletion_allowed drift", func(t *testing.T) {
		k := makeSpec()
		k.Spec.DeletionAllowed = ptrBool(false)
		require.False(t, k.IsEquivalentToDesiredState(PayloadFromTransitKeyInfo(makeInfo())))
	})

	t.Run("observed-only fields excluded — different latestVersion still matches", func(t *testing.T) {
		k := makeSpec()
		info := makeInfo()
		info.LatestVersion = 99
		info.CreationTime = "different"
		info.SupportsSigning = true
		require.True(t, k.IsEquivalentToDesiredState(PayloadFromTransitKeyInfo(info)))
	})

	t.Run("payload missing info returns false (defensive)", func(t *testing.T) {
		require.False(t, makeSpec().IsEquivalentToDesiredState(map[string]any{}))
	})

	t.Run("nil payload returns false", func(t *testing.T) {
		require.False(t, makeSpec().IsEquivalentToDesiredState(nil))
	})

	t.Run("unset spec field doesn't drift against bao default", func(t *testing.T) {
		// Spec leaves Exportable, MinDecryptionVersion, etc. unset (nil).
		// Bao read shows their defaults. The comparator should not
		// trigger drift on fields the spec doesn't pin.
		k := &OpenBaoTransitKey{}
		k.Spec.Path = transitMount
		k.Spec.Name = transitKeyName
		k.Spec.Type = transitTypeAES
		// AutoRotatePeriod left empty — must equal bao's 0.
		info := &baoclient.TransitKeyInfo{
			Type:                 transitTypeAES,
			Exportable:           true, // bao default after enable, still ignored
			AllowPlaintextBackup: true,
			AutoRotatePeriod:     0,
			MinDecryptionVersion: 0,
			MinEncryptionVersion: 0,
		}
		require.True(t, k.IsEquivalentToDesiredState(PayloadFromTransitKeyInfo(info)),
			"unset spec field must adopt bao's value, not appear as drift")
	})
}

func TestTransitKey_ImmutableMismatch(t *testing.T) {
	t.Parallel()
	base := func() *OpenBaoTransitKey {
		k := &OpenBaoTransitKey{}
		k.Spec.Type = transitTypeAES
		k.Spec.Derived = ptrBool(true)
		k.Spec.ConvergentEncryption = ptrBool(true)
		k.Spec.KeySize = ptrInt(32)
		return k
	}
	matchingInfo := func() *baoclient.TransitKeyInfo {
		return &baoclient.TransitKeyInfo{
			Type:                 transitTypeAES,
			Derived:              true,
			ConvergentEncryption: true,
			KeySize:              32,
		}
	}

	t.Run("matching state — no mismatch", func(t *testing.T) {
		_, ok := base().ImmutableMismatch(matchingInfo())
		require.False(t, ok)
	})
	t.Run("type change", func(t *testing.T) {
		info := matchingInfo()
		info.Type = "ed25519"
		msg, ok := base().ImmutableMismatch(info)
		require.True(t, ok)
		require.Contains(t, msg, "spec.type")
	})
	t.Run("derived change", func(t *testing.T) {
		info := matchingInfo()
		info.Derived = false
		msg, ok := base().ImmutableMismatch(info)
		require.True(t, ok)
		require.Contains(t, msg, "spec.derived")
	})
	t.Run("convergent_encryption change", func(t *testing.T) {
		info := matchingInfo()
		info.ConvergentEncryption = false
		msg, ok := base().ImmutableMismatch(info)
		require.True(t, ok)
		require.Contains(t, msg, "convergentEncryption")
	})
	t.Run("key_size change", func(t *testing.T) {
		info := matchingInfo()
		info.KeySize = 64
		msg, ok := base().ImmutableMismatch(info)
		require.True(t, ok)
		require.Contains(t, msg, "keySize")
	})
	t.Run("unset spec field doesn't trigger mismatch", func(t *testing.T) {
		// Spec doesn't pin Derived; bao defaulted it to false. Must
		// not be flagged as mismatch — the user simply didn't pin it.
		k := &OpenBaoTransitKey{}
		k.Spec.Type = transitTypeAES
		info := matchingInfo()
		info.Derived = false
		info.ConvergentEncryption = false
		_, ok := k.ImmutableMismatch(info)
		require.False(t, ok)
	})
	t.Run("nil info returns false", func(t *testing.T) {
		_, ok := base().ImmutableMismatch(nil)
		require.False(t, ok)
	})
}

func TestTransitKey_ToCreateSpec_OmitsConfigOnlyFields(t *testing.T) {
	t.Parallel()
	k := &OpenBaoTransitKey{}
	k.Spec.Type = transitTypeAES
	k.Spec.Derived = ptrBool(true)
	k.Spec.AutoRotatePeriod = transit720h
	k.Spec.MinDecryptionVersion = ptrInt(2) // config-only
	k.Spec.MinEncryptionVersion = ptrInt(1) // config-only
	k.Spec.DeletionAllowed = ptrBool(true)  // config-only
	out := k.ToCreateSpec()
	require.Equal(t, transitTypeAES, out.Type)
	require.Equal(t, transit720h, out.AutoRotatePeriod)
	require.NotNil(t, out.Derived)
	require.True(t, *out.Derived)
	require.Nil(t, out.MinDecryptionVersion)
	require.Nil(t, out.MinEncryptionVersion)
	require.Nil(t, out.DeletionAllowed)
}

func TestTransitKey_ToConfigSpec_OmitsCreateOnlyFields(t *testing.T) {
	t.Parallel()
	k := &OpenBaoTransitKey{}
	k.Spec.Type = transitTypeAES
	k.Spec.Derived = ptrBool(true)              // create-only
	k.Spec.ConvergentEncryption = ptrBool(true) // create-only
	k.Spec.KeySize = ptrInt(32)                 // create-only
	k.Spec.MinDecryptionVersion = ptrInt(2)
	k.Spec.DeletionAllowed = ptrBool(true)
	out := k.ToConfigSpec()
	require.Empty(t, out.Type)
	require.Nil(t, out.Derived)
	require.Nil(t, out.ConvergentEncryption)
	require.Nil(t, out.KeySize)
	require.NotNil(t, out.MinDecryptionVersion)
	require.Equal(t, 2, *out.MinDecryptionVersion)
	require.NotNil(t, out.DeletionAllowed)
	require.True(t, *out.DeletionAllowed)
}

func TestTransitKey_SetObservedStatus(t *testing.T) {
	t.Parallel()
	k := &OpenBaoTransitKey{}
	k.SetObservedStatus(&baoclient.TransitKeyInfo{
		LatestVersion:      4,
		CreationTime:       "2026-05-04T00:00:00Z",
		SupportsEncryption: true,
		SupportsSigning:    true,
	})
	require.Equal(t, 4, k.Status.LatestVersion)
	require.Equal(t, "2026-05-04T00:00:00Z", k.Status.CreationTime)
	require.True(t, k.Status.SupportsEncryption)
	require.True(t, k.Status.SupportsSigning)
	require.False(t, k.Status.SupportsDecryption)
}

func TestTransitKey_SetObservedStatus_NilNoOp(t *testing.T) {
	t.Parallel()
	k := &OpenBaoTransitKey{}
	k.Status.LatestVersion = 7 // pre-existing value
	k.SetObservedStatus(nil)
	require.Equal(t, 7, k.Status.LatestVersion, "nil info must not clobber prior status")
}
