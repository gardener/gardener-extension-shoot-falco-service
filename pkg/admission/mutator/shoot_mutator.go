// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package mutator

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"sync"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	pkgversion "github.com/hashicorp/go-version"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	servicev1alpha1 "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/v1alpha1"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
)

// NewShootMutator returns a new instance of a shoot mutator.
func NewShootMutator(mgr manager.Manager) extensionswebhook.Mutator {
	return NewShoot(mgr)
}

func NewShoot(mgr manager.Manager) *Shoot {
	return &Shoot{
		decoder: serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder(),
		scheme:  mgr.GetScheme(),
	}
}

// shoot mutates shoots
type Shoot struct {
	decoder runtime.Decoder
	scheme  *runtime.Scheme
	lock    sync.Mutex
	encoder runtime.Encoder
}

// Mutate implements extensionswebhook.Mutator.Mutate
func (s *Shoot) Mutate(ctx context.Context, new, _ client.Object) error {
	shoot, ok := new.(*gardencorev1beta1.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T", new)
	}
	return s.mutateShoot(ctx, shoot)
}

func setCustomWebhook(falcoConf *service.FalcoServiceConfig) {
	if falcoConf.CustomWebhook == nil {
		enabledWebhook := false
		falcoConf.CustomWebhook = &service.Webhook{Enabled: &enabledWebhook}
	}
}

func setFalcoCtl(falcoConf *service.FalcoServiceConfig) {
	if falcoConf.FalcoCtl == nil {
		falcoConf.FalcoCtl = &service.FalcoCtl{}
	}
}

func setGardenerRules(falcoConf *service.FalcoServiceConfig) {
	if falcoConf.Gardener == nil {
		falcoConf.Gardener = &service.Gardener{}
	}

	if falcoConf.Gardener.UseFalcoRules == nil {
		defaultRules := true
		falcoConf.Gardener.UseFalcoRules = &defaultRules
	}

	if falcoConf.Gardener.UseFalcoIncubatingRules == nil {
		defaultIncRules := false
		falcoConf.Gardener.UseFalcoIncubatingRules = &defaultIncRules
	}

	if falcoConf.Gardener.UseFalcoSandboxRules == nil {
		defaultSandRules := false
		falcoConf.Gardener.UseFalcoSandboxRules = &defaultSandRules
	}

	if falcoConf.Gardener.RuleRefs == nil {
		falcoConf.Gardener.RuleRefs = []service.Rule{}
	}
}

func setResources(falcoConf *service.FalcoServiceConfig) {
	if falcoConf.Resources == nil {
		defaultResource := "gardener"
		falcoConf.Resources = &defaultResource
	}
}

func setAutoUpdate(falcoConf *service.FalcoServiceConfig) {
	if falcoConf.AutoUpdate == nil {
		autoUpdateVal := true
		falcoConf.AutoUpdate = &autoUpdateVal
	}
}

func setFalcoVersion(falcoConf *service.FalcoServiceConfig) error {
	if falcoConf.FalcoVersion != nil {
		return nil
	}

	versions := profile.FalcoProfileManagerInstance.GetFalcoVersions()
	version, err := ChooseHighestVersion(versions, "supported")
	if err != nil {
		return err
	}
	falcoConf.FalcoVersion = version
	return nil
}

func sortVersionsWithClassification(versions *map[string]profile.Version, classification string) (pkgversion.Collection, error) {
	var sortedVersions pkgversion.Collection
	for _, v := range *versions {
		if v.Classification != classification {
			continue
		}

		ver, err := pkgversion.NewVersion(v.Version)
		if err != nil {
			return nil, fmt.Errorf("could not parse version: %s", err)
		}
		sortedVersions = append(sortedVersions, ver)
	}

	sort.Sort(sortedVersions)
	return sortedVersions, nil
}

func ChooseLowestVersionHigherThanCurrent(version *string, versions *map[string]profile.Version, classification string) (*string, error) {
	sortedVersions, err := sortVersionsWithClassification(versions, classification)
	if err != nil {
		return nil, err
	}
	if len(sortedVersions) == 0 {
		return nil, fmt.Errorf("no version with classification %s was found", classification)
	}

	currentVersion, err := pkgversion.NewVersion(*version)
	if err != nil {
		return nil, fmt.Errorf("could not parse current version %s", *version)
	}

	// if possible return the lowest supported version greater than the current one
	for _, lowest := range sortedVersions {
		if lowest.GreaterThan(currentVersion) {
			newVersionString := lowest.String()
			return &newVersionString, nil
		}
	}

	// otherwise return the lowest supported version
	lowest := sortedVersions[0].String()
	return &lowest, nil
}

func ChooseHighestVersion(versions *map[string]profile.Version, classification string) (*string, error) {
	sortedVersions, err := sortVersionsWithClassification(versions, classification)
	if err != nil {
		return nil, err
	}
	if len(sortedVersions) == 0 {
		return nil, fmt.Errorf("no version with classification %s was found", classification)
	}

	highest := sortedVersions[len(sortedVersions)-1].String()
	return &highest, nil
}

func (s *Shoot) mutateShoot(_ context.Context, new *gardencorev1beta1.Shoot) error {
	if s.isDisabled(new) {
		return nil
	}
	falcoConf, err := s.ExtractFalcoConfig(new)
	if err != nil {
		return err
	}

	if err = setFalcoVersion(falcoConf); err != nil {
		return err
	}

	setAutoUpdate(falcoConf)

	setResources(falcoConf)

	setFalcoCtl(falcoConf)

	setGardenerRules(falcoConf)

	setCustomWebhook(falcoConf)

	return s.UpdateFalcoConfig(new, falcoConf)
}

// isDisabled returns true if extension is explicitly disabled.
func (s *Shoot) isDisabled(shoot *gardencorev1beta1.Shoot) bool {
	if shoot.DeletionTimestamp != nil {
		// don't mutate shoots in deletion
		return true
	}

	ext := s.findExtension(shoot)
	if ext == nil {
		return true
	}
	if ext.Disabled != nil {
		return *ext.Disabled
	}
	return false
}

// findExtension returns shoot-falco-service extension.
func (s *Shoot) findExtension(shoot *gardencorev1beta1.Shoot) *gardencorev1beta1.Extension {
	for i, ext := range shoot.Spec.Extensions {
		if ext.Type == constants.ExtensionType {
			return &shoot.Spec.Extensions[i]
		}
	}
	return nil
}

func (s *Shoot) ExtractFalcoConfig(shoot *gardencorev1beta1.Shoot) (*service.FalcoServiceConfig, error) {
	ext := s.findExtension(shoot)
	if ext != nil && ext.ProviderConfig != nil {
		falcoConfig := &service.FalcoServiceConfig{}
		if _, _, err := s.decoder.Decode(ext.ProviderConfig.Raw, nil, falcoConfig); err != nil {
			return nil, fmt.Errorf("failed to decode %s provider config: %w", ext.Type, err)
		}
		return falcoConfig, nil
	}
	return nil, fmt.Errorf("no Falco config found")
}

func (s *Shoot) UpdateFalcoConfig(shoot *gardencorev1beta1.Shoot, config *service.FalcoServiceConfig) error {
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

func (s *Shoot) toRaw(config *service.FalcoServiceConfig) ([]byte, error) {
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

func (s *Shoot) getEncoder() (runtime.Encoder, error) {
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
