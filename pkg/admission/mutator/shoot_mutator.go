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
	gardenerutils "github.com/gardener/gardener/pkg/utils/gardener"
	pkgversion "github.com/hashicorp/go-version"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	servicev1alpha1 "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service/v1alpha1"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
)

// NewShootMutator returns a new instance of a shoot mutator.
func NewShootMutator(mgr manager.Manager, globalDefaults []config.GlobalDefaultDestination) extensionswebhook.Mutator {
	return NewShoot(mgr, globalDefaults)
}

func NewShoot(mgr manager.Manager, globalDefaults []config.GlobalDefaultDestination) *Shoot {
	return &Shoot{
		decoder:        serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		scheme:         mgr.GetScheme(),
		reader:         mgr.GetClient(),
		globalDefaults: globalDefaults,
	}
}

// shoot mutates shoots
type Shoot struct {
	decoder        runtime.Decoder
	scheme         *runtime.Scheme
	reader         client.Reader
	once           sync.Once
	encoder        runtime.Encoder
	encoderErr     error
	globalDefaults []config.GlobalDefaultDestination
}

// Mutate implements extensionswebhook.Mutator.Mutate
func (s *Shoot) Mutate(ctx context.Context, newObj, oldObj client.Object) error {

	switch obj := newObj.(type) {
	case *gardencorev1beta1.Shoot:
		var oldShoot *gardencorev1beta1.Shoot
		if oldObj != nil {
			oldShoot, _ = oldObj.(*gardencorev1beta1.Shoot)
		}
		return s.mutateShoot(ctx, obj, oldShoot)
	case *gardencorev1beta1.Seed:
		var oldSeed *gardencorev1beta1.Seed
		if oldObj != nil {
			oldSeed, _ = oldObj.(*gardencorev1beta1.Seed)
		}
		return s.mutateSeed(ctx, obj, oldSeed)
	default:
		return fmt.Errorf("unsupported object type %T", newObj)
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

	// if possible return highest version lower than current
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

func (s *Shoot) mutateShoot(ctx context.Context, new *gardencorev1beta1.Shoot, old *gardencorev1beta1.Shoot) error {
	if s.isDisabled(new) {
		return nil
	}
	falcoConf, err := s.ExtractFalcoConfig(new)
	if err != nil {
		return err
	}

	if falcoConf == nil {
		falcoConf = &service.FalcoServiceConfig{}
	}

	var oldFalcoConf *service.FalcoServiceConfig
	if old != nil {
		oldFalcoConf, err = s.ExtractFalcoConfig(old)
		if err != nil {
			return err
		}
	}

	newConfig, err := s.mutate(ctx, falcoConf, oldFalcoConf, new.Namespace)
	if err != nil {
		return err
	}

	return s.UpdateFalcoConfigShoot(new, newConfig)
}

func (s *Shoot) mutateSeed(ctx context.Context, new *gardencorev1beta1.Seed, old *gardencorev1beta1.Seed) error {
	falcoConf, err := s.ExtractFalcoConfig(new)
	if err != nil {
		return err
	}
	if falcoConf == nil {
		falcoConf = &service.FalcoServiceConfig{}
	}

	var oldFalcoConf *service.FalcoServiceConfig
	if old != nil {
		oldFalcoConf, err = s.ExtractFalcoConfig(old)
		if err != nil {
			return err
		}
	}

	newConfig, err := s.mutate(ctx, falcoConf, oldFalcoConf, "")
	if err != nil {
		return err
	}
	return s.UpdateFalcoConfigSeed(new, newConfig)
}

func (s *Shoot) mutate(ctx context.Context, falcoConf *service.FalcoServiceConfig, oldFalcoConf *service.FalcoServiceConfig, namespace string) (*service.FalcoServiceConfig, error) {

	if falcoConf == nil {
		falcoConf = &service.FalcoServiceConfig{}
	}

	if err := setFalcoVersion(falcoConf); err != nil {
		return nil, err
	}

	setAutoUpdate(falcoConf)

	setRules(falcoConf)

	setDestinations(falcoConf)

	if err := s.injectGlobalDefaults(ctx, falcoConf, oldFalcoConf, namespace); err != nil {
		return nil, err
	}

	return falcoConf, nil
}

func setRules(falcoConf *service.FalcoServiceConfig) {
	if falcoConf.Rules == nil {
		standardRules := []string{constants.ConfigFalcoRules}
		falcoConf.Rules = &service.Rules{
			StandardRules: standardRules,
		}
	}
}

func setDestinations(falcoConf *service.FalcoServiceConfig) {
	if len(falcoConf.Destinations) == 0 {
		defaultDestination := []service.Destination{
			{
				Name: constants.FalcoEventDestinationLogging,
			},
		}
		falcoConf.Destinations = defaultDestination
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

func (s *Shoot) findExtension(obj client.Object) *gardencorev1beta1.Extension {
	var extensions []gardencorev1beta1.Extension
	switch o := obj.(type) {
	case *gardencorev1beta1.Shoot:
		extensions = o.Spec.Extensions
	case *gardencorev1beta1.Seed:
		extensions = o.Spec.Extensions
	default:
		return nil
	}
	for _, ext := range extensions {
		if ext.Type == constants.ExtensionType {
			return &ext
		}
	}
	return nil
}

func (s *Shoot) ExtractFalcoConfig(obj client.Object) (*service.FalcoServiceConfig, error) {
	ext := s.findExtension(obj)
	if ext != nil && ext.ProviderConfig != nil {
		falcoConfig := &service.FalcoServiceConfig{}
		if _, _, err := s.decoder.Decode(ext.ProviderConfig.Raw, nil, falcoConfig); err != nil {
			return nil, fmt.Errorf("failed to decode %s provider config: %w", ext.Type, err)
		}
		return falcoConfig, nil
	}
	return nil, nil
}

func (s *Shoot) UpdateFalcoConfigShoot(shoot *gardencorev1beta1.Shoot, config *service.FalcoServiceConfig) error {
	raw, err := s.toRaw(config)
	if err != nil {
		return err
	}

	extensionType := constants.ExtensionType
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

func (s *Shoot) UpdateFalcoConfigSeed(seed *gardencorev1beta1.Seed, config *service.FalcoServiceConfig) error {
	raw, err := s.toRaw(config)
	if err != nil {
		return err
	}

	extensionType := constants.ExtensionType
	index := -1
	for i, ext := range seed.Spec.Extensions {
		if ext.Type == extensionType {
			index = i
			break
		}
	}

	if index == -1 {
		index = len(seed.Spec.Extensions)
		seed.Spec.Extensions = append(seed.Spec.Extensions, gardencorev1beta1.Extension{
			Type: extensionType,
		})
	}
	seed.Spec.Extensions[index].ProviderConfig = &runtime.RawExtension{Raw: raw}
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
	s.once.Do(func() {
		codec := serializer.NewCodecFactory(s.scheme)
		si, ok := runtime.SerializerInfoForMediaType(codec.SupportedMediaTypes(), runtime.ContentTypeJSON)
		if !ok {
			s.encoderErr = fmt.Errorf("could not find encoder for media type %q", runtime.ContentTypeJSON)
			return
		}
		s.encoder = codec.EncoderForVersion(si.Serializer, servicev1alpha1.SchemeGroupVersion)
	})

	if s.encoderErr != nil {
		return nil, s.encoderErr
	}
	return s.encoder, nil
}

func (s *Shoot) injectGlobalDefaults(ctx context.Context, falcoConf *service.FalcoServiceConfig, oldFalcoConf *service.FalcoServiceConfig, namespace string) error {
	// Clean up stale global defaults on UPDATE
	if oldFalcoConf != nil {
		s.removeStaleGlobalDefaults(falcoConf, oldFalcoConf)
	}

	if len(s.globalDefaults) == 0 {
		return nil
	}

	// Check project-level opt-out annotation
	if len(namespace) != 0 {
		project, err := gardenerutils.ProjectForNamespaceFromReader(ctx, s.reader, namespace)
		if err != nil {
			return fmt.Errorf("failed to get project for namespace %s: %w", namespace, err)
		}
		if project != nil {
			if v, ok := project.Annotations[constants.SkipDefaultDestinationsAnnotation]; ok && v == "true" {
				return nil
			}
		}
	}

	// On UPDATE: only inject if old config did not exist
	if oldFalcoConf != nil {
		return nil
	}

	// Build set of output keys already used by enabled destinations
	usedOutputKeys := make(map[string]struct{})
	for _, dest := range falcoConf.Destinations {
		if dest.Enabled != nil && !*dest.Enabled {
			continue
		}
		if key, ok := constants.DestinationOutputKeys[dest.Name]; ok {
			usedOutputKeys[key] = struct{}{}
		}
	}

	for _, gd := range s.globalDefaults {
		// Check if this global default is already listed by name
		alreadyListed := false
		for _, dest := range falcoConf.Destinations {
			if dest.Name == gd.Name {
				alreadyListed = true
				break
			}
		}
		if alreadyListed {
			continue
		}

		dest := service.Destination{
			Name: gd.Name,
		}

		// Inject as disabled if output key conflict
		if _, ok := usedOutputKeys[gd.Key]; ok {
			dest.Enabled = ptr.To(false)
		}

		falcoConf.Destinations = append(falcoConf.Destinations, dest)
	}
	return nil
}

// removeStaleGlobalDefaults removes destinations that were previously injected as global defaults
// but are no longer present in the operator config.
func (s *Shoot) removeStaleGlobalDefaults(falcoConf *service.FalcoServiceConfig, oldFalcoConf *service.FalcoServiceConfig) {
	// Build set of names that are currently valid (standard + current global defaults)
	validNames := make(map[string]struct{})
	for _, name := range constants.AllowedDestinations {
		validNames[name] = struct{}{}
	}
	for _, gd := range s.globalDefaults {
		validNames[gd.Name] = struct{}{}
	}

	// Build set of destination names from the old shoot
	oldDestNames := make(map[string]struct{})
	for _, dest := range oldFalcoConf.Destinations {
		oldDestNames[dest.Name] = struct{}{}
	}

	// Remove destinations that: are not valid, existed in old shoot, and have no resourceSecretName
	filtered := falcoConf.Destinations[:0]
	for _, dest := range falcoConf.Destinations {
		_, isValid := validNames[dest.Name]
		_, wasInOld := oldDestNames[dest.Name]
		if !isValid && wasInOld && dest.ResourceSecretName == nil {
			continue
		}
		filtered = append(filtered, dest)
	}
	falcoConf.Destinations = filtered
}
