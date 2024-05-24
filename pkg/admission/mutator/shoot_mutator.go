// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package mutator

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	pkgversion "github.com/hashicorp/go-version"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	servicev1alpha1 "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/v1alpha1"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/utils/falcoversions"
)

// NewShootMutator returns a new instance of a shoot mutator.
func NewShootMutator(mgr manager.Manager) extensionswebhook.Mutator {
	return &shoot{
		decoder: serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder(),
		scheme:  mgr.GetScheme(),
	}
}

// shoot mutates shoots
type shoot struct {
	decoder runtime.Decoder
	scheme  *runtime.Scheme
	lock    sync.Mutex
	encoder runtime.Encoder
}

// Mutate implements extensionswebhook.Mutator.Mutate
func (s *shoot) Mutate(ctx context.Context, new, _ client.Object) error {
	fmt.Println("I am the mutator")

	shoot, ok := new.(*gardencorev1beta1.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T", new)
	}
	return s.mutateShoot(ctx, shoot)
}

// func setAutoUpdate(falcoConf *service.FalcoServiceConfig) error {
// 	if falcoConf.AutoUpdate != nil {
// 		return nil
// 	}
// 	autoUpdateVal := true
// 	falcoConf.AutoUpdate = *autoUpdateVal
// 	return nil
// }

func setFalcoVersion(falcoConf *service.FalcoServiceConfig) error {
	if falcoConf.FalcoVersion != nil {
		return nil
	}
	versions := falco.FalcoVersions().Falco

	version, err := chooseHighestVersion(versions, "supported")
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	falcoConf.FalcoVersion = &version
	return nil
}

func chooseHighestVersion(versions *falcoversions.FalcoVersions, classification string) (string, error) {
	highest, err := pkgversion.NewVersion("0") // does not allow empty string
	if err != nil {
		return "", fmt.Errorf("could not parse version: %s", err)
	}
	for _, v := range versions.FalcoVersions {
		if v.Classification != classification {
			continue
		}
		incumbent, err := pkgversion.NewVersion(v.Version)

		if err != nil {
			return "", fmt.Errorf("could not parse version: %s", err)
		}

		if incumbent.GreaterThan(highest) {
			highest = incumbent
		}
	}
	return highest.String(), nil
}

func (s *shoot) mutateShoot(_ context.Context, new *gardencorev1beta1.Shoot) error {
	if s.isDisabled(new) {
		return nil
	}
	falcoConf, err := s.extractFalcoConfig(new)
	if err != nil {
		return err
	}
	// Need to handle empty falco conf

	// Set faclo version
	fmt.Println(falcoConf.FalcoVersion)
	setFalcoVersion(falcoConf)
	fmt.Println(*falcoConf.FalcoVersion)

	// Set auto update
	fmt.Println(falcoConf.AutoUpdate)
	// setAutoUpdate(falcoConf)
	fmt.Println(falcoConf.AutoUpdate)

	return s.updateFalcoConfig(new, falcoConf)

	// syncProviders := dnsConfig == nil || dnsConfig.Providers == nil
	// if dnsConfig != nil && dnsConfig.SyncProvidersFromShootSpecDNS != nil {
	// 	syncProviders = *dnsConfig.SyncProvidersFromShootSpecDNS
	// }
	// if !syncProviders {
	// 	return nil
	// }

	// if dnsConfig == nil {
	// 	dnsConfig = &servicev1alpha1.DNSConfig{}
	// }
	// dnsConfig.SyncProvidersFromShootSpecDNS = &syncProviders

	// oldNamedResources := map[string]int{}
	// for i, r := range new.Spec.Resources {
	// 	oldNamedResources[r.Name] = i
	// }
	// newNamedResources := map[string]struct{}{}

	// dnsConfig.Providers = nil
	// for _, p := range new.Spec.DNS.Providers {
	// 	np := servicev1alpha1.DNSProvider{Type: p.Type}
	// 	if p.Domains != nil {
	// 		np.Domains = &servicev1alpha1.DNSIncludeExclude{
	// 			Include: p.Domains.Include,
	// 			Exclude: p.Domains.Exclude,
	// 		}
	// 	}
	// 	if p.Zones != nil {
	// 		np.Zones = &servicev1alpha1.DNSIncludeExclude{
	// 			Include: p.Zones.Include,
	// 			Exclude: p.Zones.Exclude,
	// 		}
	// 	}
	// 	if p.Primary != nil && *p.Primary && p.Domains == nil && p.Zones == nil && new.Spec.DNS.Domain != nil {
	// 		np.Domains = &servicev1alpha1.DNSIncludeExclude{
	// 			Include: []string{*new.Spec.DNS.Domain},
	// 		}
	// 	}
	// 	if p.SecretName != nil {
	// 		secretName := pkgservice.ExtensionType + "-" + *p.SecretName
	// 		np.SecretName = &secretName
	// 		resource := gardencorev1beta1.NamedResourceReference{
	// 			Name: secretName,
	// 			ResourceRef: autoscalingv1.CrossVersionObjectReference{
	// 				Kind:       "Secret",
	// 				Name:       *p.SecretName,
	// 				APIVersion: "v1",
	// 			},
	// 		}
	// 		newNamedResources[secretName] = struct{}{}
	// 		if index, ok := oldNamedResources[secretName]; ok {
	// 			new.Spec.Resources[index].ResourceRef = resource.ResourceRef
	// 		} else {
	// 			new.Spec.Resources = append(new.Spec.Resources, resource)
	// 		}
	// 	}
	// 	dnsConfig.Providers = append(dnsConfig.Providers, np)
	// }

	// outdated := map[string]struct{}{}
	// for key := range oldNamedResources {
	// 	if !strings.HasPrefix(key, pkgservice.ExtensionType+"-") {
	// 		continue
	// 	}
	// 	if _, ok := newNamedResources[key]; !ok {
	// 		outdated[key] = struct{}{}
	// 	}
	// }
	// if len(outdated) > 0 {
	// 	newResources := []gardencorev1beta1.NamedResourceReference{}
	// 	for _, resource := range new.Spec.Resources {
	// 		if _, ok := outdated[resource.Name]; !ok {
	// 			newResources = append(newResources, resource)
	// 		}
	// 	}
	// 	new.Spec.Resources = newResources
	// }

	// return s.updateDNSConfig(new, dnsConfig)
}

// isDisabled returns true if extension is explicitly disabled.
func (s *shoot) isDisabled(shoot *gardencorev1beta1.Shoot) bool {
	if shoot.Spec.DNS == nil {
		return true
	}
	if shoot.DeletionTimestamp != nil {
		// don't mutate shoots in deletion
		return true
	}
	if shoot.Status.LastOperation != nil &&
		shoot.Status.LastOperation.Type != gardencorev1beta1.LastOperationTypeReconcile &&
		shoot.Status.LastOperation.State != gardencorev1beta1.LastOperationStateProcessing {
		// don't mutate shoots if not in reconcile processing state
		return true
	}

	ext := s.findExtension(shoot)
	if ext == nil {
		return false
	}
	if ext.Disabled != nil {
		return *ext.Disabled
	}
	return false
}

// findExtension returns shoot-falco-service extension.
func (s *shoot) findExtension(shoot *gardencorev1beta1.Shoot) *gardencorev1beta1.Extension {
	extensionType := "shoot-falco-service"
	for i, ext := range shoot.Spec.Extensions {
		if ext.Type == extensionType {
			fmt.Println(string(shoot.Spec.Extensions[i].ProviderConfig.Raw))
			return &shoot.Spec.Extensions[i]
		}
	}
	return nil
}

func (s *shoot) extractFalcoConfig(shoot *gardencorev1beta1.Shoot) (*service.FalcoServiceConfig, error) {
	ext := s.findExtension(shoot)
	if ext != nil && ext.ProviderConfig != nil {
		// dnsConfig := &apisservice.DNSConfig{}
		falcoConfig := &service.FalcoServiceConfig{}
		if _, _, err := s.decoder.Decode(ext.ProviderConfig.Raw, nil, falcoConfig); err != nil {
			return nil, fmt.Errorf("failed to decode %s provider config: %w", ext.Type, err)
		}
		return falcoConfig, nil
	}
	return nil, nil
}

// // extractDNSConfig extracts DNSConfig from providerConfig.
// func (s *shoot) extractDNSConfig(shoot *gardencorev1beta1.Shoot) (*servicev1alpha1.DNSConfig, error) {
// 	ext := s.findExtension(shoot)
// 	if ext != nil && ext.ProviderConfig != nil && ext.ProviderConfig.Raw != nil {
// 		dnsConfig := &servicev1alpha1.DNSConfig{}
// 		if _, _, err := s.decoder.Decode(ext.ProviderConfig.Raw, nil, dnsConfig); err != nil {
// 			return nil, fmt.Errorf("failed to decode %s provider config: %w", ext.Type, err)
// 		}
// 		return dnsConfig, nil
// 	}

// 	return nil, nil
// }

func (s *shoot) updateFalcoConfig(shoot *gardencorev1beta1.Shoot, config *service.FalcoServiceConfig) error {
	raw, err := s.toRaw(config)
	if err != nil {
		return err
	}

	extensionType := "shoot-falco-service"
	index := -1
	for i, ext := range shoot.Spec.Extensions {
		if ext.Type == extensionType {
			index = i
			break
		}
	}

	if index == -1 {
		index = len(shoot.Spec.Extensions)
		shoot.Spec.Extensions = append(shoot.Spec.Extensions, gardencorev1beta1.Extension{
			Type: extensionType,
		})
	}
	shoot.Spec.Extensions[index].ProviderConfig = &runtime.RawExtension{Raw: raw}
	return nil
}

func (s *shoot) toRaw(config *service.FalcoServiceConfig) ([]byte, error) {
	encoder, err := s.getEncoder()
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	if err := encoder.Encode(config, &b); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func (s *shoot) getEncoder() (runtime.Encoder, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.encoder != nil {
		return s.encoder, nil
	}

	codec := serializer.NewCodecFactory(s.scheme)
	si, ok := runtime.SerializerInfoForMediaType(codec.SupportedMediaTypes(), runtime.ContentTypeJSON)
	if !ok {
		return nil, fmt.Errorf("could not find encoder for media type %q", runtime.ContentTypeJSON)
	}
	s.encoder = codec.EncoderForVersion(si.Serializer, servicev1alpha1.SchemeGroupVersion)
	return s.encoder, nil
}
