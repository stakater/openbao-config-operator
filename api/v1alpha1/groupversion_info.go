package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var (
	GroupVersion  = schema.GroupVersion{Group: "security.mto.stakater.com", Version: "v1alpha1"}
	SchemeBuilder = &Builder{GroupVersion: GroupVersion}
	AddToScheme   = SchemeBuilder.AddToScheme
)

// +kubebuilder:object:generate=false
type Builder struct {
	GroupVersion schema.GroupVersion
	runtime.SchemeBuilder
}

func (bld *Builder) Register(object ...runtime.Object) *Builder {
	bld.SchemeBuilder.Register(func(scheme *runtime.Scheme) error {
		scheme.AddKnownTypes(bld.GroupVersion, object...)
		metav1.AddToGroupVersion(scheme, bld.GroupVersion)
		return nil
	})
	return bld
}

func (bld *Builder) AddToScheme(s *runtime.Scheme) error {
	return bld.SchemeBuilder.AddToScheme(s)
}
