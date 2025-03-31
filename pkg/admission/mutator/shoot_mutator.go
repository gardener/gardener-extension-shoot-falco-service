// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package mutator

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/go-logr/logr"
	pkgversion "github.com/hashicorp/go-version"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	servicev1alpha1 "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/v1alpha1"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/migration"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
)

// NewShootMutator returns a new instance of a shoot mutator.
func NewShootMutator(mgr manager.Manager) extensionswebhook.Mutator {
	return NewShoot(mgr)
}

func NewShoot(mgr manager.Manager) *Shoot {
	return &Shoot{
		decoder: serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
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

	if falcoConf.Gardener.CustomRules == nil {
		falcoConf.Gardener.CustomRules = []string{}
	}
}

func setResources(falcoConf *service.FalcoServiceConfig) {
	if falcoConf.Resources == nil {
		defaultResource := "gardener"
		falcoConf.Resources = &defaultResource
	}
	if *falcoConf.Resources == "gardener" {
		setGardenerRules(falcoConf)
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
	version, err := chooseHighestVersion(*versions, "supported")
	if err != nil {
		return err
	}
	falcoConf.FalcoVersion = version
	return nil
}

func sortVersionsWithClassification(versions map[string]profile.FalcoVersion, classifications []string) (pkgversion.Collection, error) {
	now := time.Now()
	var sortedVersions pkgversion.Collection
	for _, v := range versions {
		if !slices.Contains(classifications, v.Classification) {
			continue
		}

		if v.ExpirationDate != nil && v.ExpirationDate.Before(now) {
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

func chooseHighestVersionLowerThanCurrent(version string, versions map[string]profile.FalcoVersion) (*string, error) {
	sortedVersions, err := sortVersionsWithClassification(versions, []string{"supported", "deprecated"})
	if err != nil {
		return nil, err
	}

	if len(sortedVersions) == 0 {
		return nil, fmt.Errorf("no non-expired version was found")
	}

	currentVersion, err := pkgversion.NewVersion(version)
	if err != nil {
		return nil, fmt.Errorf("could not parse current version %s", version)
	}

	// if possible return higest version lower than current
	incumbent := sortedVersions[0]
	for _, lowest := range sortedVersions[1:] {
		if lowest.GreaterThan(currentVersion) {
			newVersionString := incumbent.String()
			return &newVersionString, nil
		}
		incumbent = lowest
	}

	incumbentStr := incumbent.String()
	return &incumbentStr, nil
}

func chooseLowestVersionHigherThanCurrent(version string, versions map[string]profile.FalcoVersion, classifications []string) (*string, error) {
	sortedVersions, err := sortVersionsWithClassification(versions, classifications)
	if err != nil {
		return nil, err
	}
	if len(sortedVersions) == 0 {
		return nil, fmt.Errorf("no version with classification %s was found", classifications)
	}

	currentVersion, err := pkgversion.NewVersion(version)
	if err != nil {
		return nil, fmt.Errorf("could not parse current version %s", version)
	}

	// if possible return the lowest supported version greater than the current one
	for _, lowest := range sortedVersions {
		if lowest.GreaterThan(currentVersion) {
			newVersionString := lowest.String()
			return &newVersionString, nil
		}
	}

	return nil, fmt.Errorf("no higher version than current version found")
}

func chooseHighestVersion(versions map[string]profile.FalcoVersion, classification string) (*string, error) {

	sortedVersions, err := sortVersionsWithClassification(versions, []string{classification})
	if err != nil {
		return nil, err
	}
	if len(sortedVersions) == 0 {
		return nil, fmt.Errorf("no version with classification %s was found", classification)
	}

	highest := sortedVersions[len(sortedVersions)-1].String()
	return &highest, nil
}

func GetAutoUpdateVersion(versions map[string]profile.FalcoVersion) (*string, error) {
	vers, err := chooseHighestVersion(versions, "supported")
	return vers, err
}

func GetForceUpdateVersion(version string, versions map[string]profile.FalcoVersion) (*string, error) {
	vers, err := chooseLowestVersionHigherThanCurrent(version, versions, []string{"deprecated", "supported"})
	if err == nil {
		return vers, nil
	}

	// Last chance find any version that not expired
	vers, err = chooseHighestVersionLowerThanCurrent(version, versions)
	if err == nil {
		return vers, nil
	}
	return nil, fmt.Errorf("no version was found to force update expired version %s", version)
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

	log := logr.New(nil)

	migration.MigrateIssue215(log, falcoConf)

	setRules(falcoConf)

	setDestinations(falcoConf)

	return s.UpdateFalcoConfig(new, falcoConf)
}

func setRules(falcoConf *service.FalcoServiceConfig) {
	if falcoConf.Rules == nil {
		standardRules := []string{constants.ConfigFalcoRules}
		falcoConf.Rules = &service.Rules{
			StandardRules: &standardRules,
		}
	}
}

func setDestinations(falcoConf *service.FalcoServiceConfig) {
	if falcoConf.Destinations == nil || len(*falcoConf.Destinations) == 0 {
		defaultDestination := []service.Destination{
			{
				Name: constants.FalcoEventDestinationLogging,
			},
		}
		falcoConf.Destinations = &defaultDestination
	}
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
	return nil, nil
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
