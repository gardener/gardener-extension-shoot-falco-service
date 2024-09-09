package utils

import (
	"fmt"
	"os"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	serviceinstall "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/install"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/validation"
)

var (
	decoder runtime.Decoder
)

func init() {
	rc := &rest.Config{}
	op := manager.Options{}
	mgr, err := manager.New(rc, op)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not instantiate manager: %v\n", err)
		os.Exit(1)
	}
	if err := serviceinstall.AddToScheme(mgr.GetScheme()); err != nil {
		fmt.Fprintf(os.Stderr, "could not add Falco service scheme: %v\n", err)
		os.Exit(1)
	}
	decoder = serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder()
}

func ExtractFalcoServiceConfig(ex *extensionsv1alpha1.Extension) (*apisservice.FalcoServiceConfig, error) {
	falcoServiceConfig := &apisservice.FalcoServiceConfig{}

	if ex.Spec.ProviderConfig != nil {
		if _, _, err := decoder.Decode(ex.Spec.ProviderConfig.Raw, nil, falcoServiceConfig); err != nil {
			return nil, fmt.Errorf("could not decode Falco service config: %w", err)
		}
		if errs := validation.ValidateFalcoServiceConfig(falcoServiceConfig); len(errs) > 0 {
			return nil, errs.ToAggregate()
		}
	}
	return falcoServiceConfig, nil
}
