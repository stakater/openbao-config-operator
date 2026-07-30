package v1alpha1

import (
	"testing"

	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/runtime"
)

func TestAddToScheme_RegistersEveryKindInGroup(t *testing.T) {
	t.Parallel()

	s := runtime.NewScheme()
	require.NoError(t, AddToScheme(s))

	kinds := []string{
		"OpenBaoAuthMethod",
		"OpenBaoCertAuthEngineConfig",
		"OpenBaoCertAuthEngineRole",
		"OpenBaoGroup",
		"OpenBaoGroupAlias",
		"OpenBaoIdentityTokenRole",
		"OpenBaoJWTOIDCAuthEngineConfig",
		"OpenBaoJWTOIDCAuthEngineRole",
		"OpenBaoKubernetesAuthEngineConfig",
		"OpenBaoKubernetesAuthRole",
		"OpenBaoNamespace",
		"OpenBaoPKISecretEngineConfig",
		"OpenBaoPKISecretEngineRole",
		"OpenBaoPolicy",
		"OpenBaoSecretEngine",
		"OpenBaoTransitKey",
	}

	for _, kind := range kinds {
		for _, k := range []string{kind, kind + "List"} {
			_, err := s.New(GroupVersion.WithKind(k))
			require.NoErrorf(t, err, "kind %s is not registered in the scheme", k)
		}
	}
}

func TestAddToScheme_AddsMetaV1ToGroupVersion(t *testing.T) {
	t.Parallel()

	s := runtime.NewScheme()
	require.NoError(t, AddToScheme(s))

	_, err := s.New(GroupVersion.WithKind("ListOptions"))
	require.NoError(t, err)

	require.True(t, s.Recognizes(GroupVersion.WithKind("OpenBaoPolicy")))
	require.Equal(t, "security.mto.stakater.com", GroupVersion.Group)
	require.Equal(t, "v1alpha1", GroupVersion.Version)

	gvks, unversioned, err := s.ObjectKinds(&OpenBaoPolicy{})
	require.NoError(t, err)
	require.False(t, unversioned)
	require.Contains(t, gvks, GroupVersion.WithKind("OpenBaoPolicy"))
}
