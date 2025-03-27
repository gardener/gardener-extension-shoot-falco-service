// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"time"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/profile"
)

// extra Falco options
type FalcoWebhookOptions struct {
	// if set to true, projects must be annotated with falco.gardener.cloud/enabled=true to
	// deploy Falco in their shoot clusters
	RestrictedUsage bool

	// if set to true, project must be annotated with falco.gardener.cloud/centralized-logging=true
	// to use the Gardener manged centralized logging solution
	RestrictedCentralizedLogging bool
}

var DefautltFalcoWebhookOptions = FalcoWebhookOptions{}

// Complete implements Completer.Complete.
func (o *FalcoWebhookOptions) Complete() error {
	return nil
}

// Completed returns the completed Config. Only call this if `Complete` was successful.
func (c *FalcoWebhookOptions) Completed() *FalcoWebhookOptions {
	return c
}

// AddFlags implements Flagger.AddFlags.
func (c *FalcoWebhookOptions) AddFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&c.RestrictedUsage, "restricted-usage", false, "if set to true, projects must be annotated with falco.gardener.cloud/enabled=true to deploy Falco in their shoot clusters")
	fs.BoolVar(&c.RestrictedCentralizedLogging, "restricted-centralized-logging", false, "if set to true, project must be annotated with falco.gardener.cloud/centralized-logging=true to use the Gardener manged centralized logging solution")
}

// Apply sets the values of this Config in the given config.ControllerConfiguration.
func (c *FalcoWebhookOptions) Apply(config *FalcoWebhookOptions) {
	config.RestrictedCentralizedLogging = c.RestrictedCentralizedLogging
	config.RestrictedUsage = c.RestrictedUsage
}

// NewShootValidator returns a new instance of a shoot validator.
func NewShootValidator(mgr manager.Manager) extensionswebhook.Validator {
	return NewShootValidatorWithOption(mgr, &DefautltFalcoWebhookOptions)
}

func NewShootValidatorWithOption(mgr manager.Manager, options *FalcoWebhookOptions) extensionswebhook.Validator {

	restrictedUsage := options.RestrictedUsage
	// environment overwrites command line option
	if val, exists := os.LookupEnv("RESTRICTED_USAGE"); exists {
		if envOverwrite, err := strconv.ParseBool(val); err == nil {
			restrictedUsage = envOverwrite
		}
	}
	return &shoot{
		decoder:                  serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		restrictedUsage:          restrictedUsage,
		restrictedCentralLogging: options.RestrictedCentralizedLogging,
	}
}

// shoot validates shoots
type shoot struct {
	decoder                  runtime.Decoder
	restrictedUsage          bool
	restrictedCentralLogging bool
}

// Validate implements extensionswebhook.Validator.Validate
func (s *shoot) Validate(ctx context.Context, new, old client.Object) error {
	oldShoot, ok := old.(*core.Shoot)
	if !ok {
		oldShoot = nil
	}

	shoot, ok := new.(*core.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T", new)
	}
	return s.validateShoot(ctx, shoot, oldShoot)
}

func (s *shoot) validateShoot(_ context.Context, shoot *core.Shoot, oldShoot *core.Shoot) error {
	// Need check here
	if s.isDisabled(shoot) {
		return nil
	}

	falcoConf, err := s.extractFalcoConfig(shoot)
	if err != nil {
		return err
	}

	oldFalcoConf, oldFalcoConfErr := s.extractFalcoConfig(oldShoot)

	if s.restrictedUsage {
		if oldFalcoConfErr != nil || oldFalcoConf == nil { // only verify elegibility if we can not read old shoot falco config or falco was not enabled before
			if ok := verifyProjectEligibility(shoot.Namespace); !ok {
				return fmt.Errorf("project is not eligible for Falco extension")
			}
		}
	}
	if s.restrictedCentralLogging && centralLoggingNewlyEnabled(falcoConf, oldFalcoConf) {
		if ok := verifyProjectEligibilityForCentralLogging(shoot.Namespace); !ok {
			return fmt.Errorf("project is not eligible for centralized logging")
		}
	}

	allErrs := []error{}

	if err := verifyFalcoVersion(falcoConf, oldFalcoConf); err != nil {
		allErrs = append(allErrs, err)
	}

	if err := verifyRules(falcoConf, shoot); err != nil {
		allErrs = append(allErrs, err)
	}

	if err := verifyEvents(falcoConf, shoot); err != nil {
		allErrs = append(allErrs, err)
	}

	if len(allErrs) > 0 {
		return errors.Join(allErrs...)
	}

	return nil
}

func unique(slice []string) bool {
	unique := make(map[string]bool, len(slice))
	for _, elem := range slice {
		if _, ok := unique[elem]; ok {
			return false
		} else {
			unique[elem] = true
		}
	}
	return true
}

func verifyRules(falcoConf *service.FalcoServiceConfig, shoot *core.Shoot) error {

	if (falcoConf.StandardRules == nil || len(*falcoConf.StandardRules) == 0) &&
		(falcoConf.CustomRules == nil || len(*falcoConf.CustomRules) == 0) {
		return fmt.Errorf("falco deployment wihtout any rules is not allowed")
	}

	// check for allowed standard rules
	if falcoConf.StandardRules != nil {
		for _, rule := range *falcoConf.StandardRules {
			if !slices.Contains(constants.AllowedStandardRules, rule) {
				return fmt.Errorf("unknwon standard rule %s ", rule)
			}
		}
	}

	// check for double entries in standard rules
	if falcoConf.StandardRules != nil && len(*falcoConf.StandardRules) > 0 {
		if !unique(*falcoConf.StandardRules) {
			return fmt.Errorf("double entry in standard rules")
		}
	}

	// check for double entries in custom rules
	if falcoConf.CustomRules != nil && len(*falcoConf.CustomRules) > 0 {
		if !unique(*falcoConf.CustomRules) {
			return fmt.Errorf("double entry in custom rules")
		}
	}

	// check that resource references to custon rule configmaps are valid
	if falcoConf.CustomRules != nil && len(*falcoConf.CustomRules) > 0 {
		allConfigMaps := make(map[string]string)
		for _, r := range shoot.Spec.Resources {
			if r.ResourceRef.Kind == "ConfigMap" && r.ResourceRef.APIVersion == "v1" {
				allConfigMaps[r.Name] = r.ResourceRef.Name
			}
		}
		for _, rule := range *falcoConf.CustomRules {
			if _, ok := allConfigMaps[rule]; !ok {
				return fmt.Errorf("custom rule %s not found in resources", rule)
			}
		}
	}
	return nil
}

func verifyEvents(falcoConf *service.FalcoServiceConfig, shoot *core.Shoot) error {
	events := falcoConf.Events
	if events == nil {
		return fmt.Errorf("events property is not defined")
	}

	if len(events.Destinations) == 0 {
		return fmt.Errorf("no event destination are set")
	}

	for _, dest := range events.Destinations {
		if !slices.Contains(constants.AllowedDestinations, dest) {
			return fmt.Errorf("unknown event destination %s", dest)
		}
	}

	if !unique(events.Destinations) {
		return fmt.Errorf("double entry in event destinations")
	}

	if len(events.Destinations) > 1 {
		if len(events.Destinations) > 2 {
			return fmt.Errorf("more than two event destinations are not allowed")
		}

		if !slices.Contains(events.Destinations, constants.FalcoEventDestinationStdout) {
			return fmt.Errorf("output destination can only be paired with stdout")
		}
	}

	if slices.Contains(events.Destinations, constants.FalcoEventDestinationCustom) {
		if events.CustomConfig == nil {
			return fmt.Errorf("custom event destination is set but no custom config is defined")
		}

		found := false
		for _, s := range shoot.Spec.Resources {
			if s.ResourceRef.Kind == "Secret" && s.Name == *events.CustomConfig {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("custom event destination config %s not found in resources", *events.CustomConfig)
		}
	}
	return nil
}

func verifyFalcoVersion(falcoConf *service.FalcoServiceConfig, oldFalcoConf *service.FalcoServiceConfig) error {
	if oldFalcoConf != nil && *oldFalcoConf.FalcoVersion == *falcoConf.FalcoVersion { // no version change
		return nil
	}

	versions := profile.FalcoProfileManagerInstance.GetFalcoVersions()
	if err := verifyFalcoVersionInVersions(falcoConf, versions); err != nil {
		return err
	}
	return nil
}

func verifyFalcoVersionInVersions(falcoConf *service.FalcoServiceConfig, versions *map[string]profile.FalcoVersion) error {
	chosenVersion := falcoConf.FalcoVersion
	if chosenVersion == nil {
		return fmt.Errorf("falcoVersion is nil")
	}

	for _, ver := range *versions {
		if *chosenVersion == ver.Version {
			if ver.Classification == "deprecated" &&
				ver.ExpirationDate != nil &&
				ver.ExpirationDate.Before(time.Now()) {
				return fmt.Errorf("chosen version is marked as deprecated")
			}
			return nil
		}
	}
	return fmt.Errorf("version not found in possible versions")
}

// isDisabled returns true if extension is explicitly disabled.
func (s *shoot) isDisabled(shoot *core.Shoot) bool {
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
func (s *shoot) findExtension(shoot *core.Shoot) *core.Extension {
	for i, ext := range shoot.Spec.Extensions {
		if ext.Type == constants.ExtensionType {
			return &shoot.Spec.Extensions[i]
		}
	}
	return nil
}

func (s *shoot) extractFalcoConfig(shoot *core.Shoot) (*service.FalcoServiceConfig, error) {
	if shoot == nil {
		return nil, fmt.Errorf("shoot pointer was nil")
	}

	ext := s.findExtension(shoot)
	if ext != nil && ext.ProviderConfig != nil {
		falcoConfig := &service.FalcoServiceConfig{}
		if _, _, err := s.decoder.Decode(ext.ProviderConfig.Raw, nil, falcoConfig); err != nil {
			return nil, fmt.Errorf("failed to decode %s provider config: %w", ext.Type, err)
		}
		return falcoConfig, nil
	}
	return nil, fmt.Errorf("no FalcoConfig found in extensions")
}

func verifyProjectEligibility(namespace string) bool {
	project, ok := ProjectsInstance.projects[namespace]
	if !ok {
		return false
	}

	always := slices.Contains(constants.AlwaysEnabledProjects[:], project.Name)
	if always {
		return true
	}

	val, ok := project.Annotations[constants.ProjectEnableAnnotation]
	if !ok {
		return false
	}

	enabled, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return enabled
}

func verifyProjectEligibilityForCentralLogging(namespace string) bool {
	project, ok := ProjectsInstance.projects[namespace]
	if !ok {
		return false
	}

	always := slices.Contains(constants.CentralLoggingAllowedProjects[:], project.Name)
	if always {
		return true
	}

	val, ok := project.Annotations[constants.ProjectCentralLoggingAnnotation]
	if !ok {
		return false
	}

	enabled, err := strconv.ParseBool(val)
	if err != nil {
		return false
	}
	return enabled
}

// returns true if central loggging was newly enabled or this is a new cluster
func centralLoggingNewlyEnabled(falcoConfigNew, falcoConfigOld *service.FalcoServiceConfig) bool {

	if falcoConfigNew.Output != nil && falcoConfigNew.Output.EventCollector != nil && *falcoConfigNew.Output.EventCollector == "central" {

		if falcoConfigOld == nil {
			// new cluster
			return true
		}
		if falcoConfigOld.Output != nil && falcoConfigOld.Output.EventCollector != nil && *falcoConfigOld.Output.EventCollector != "central" {
			// cluster did exist but central logging was not enabled
			fmt.Println("central logging was not enabled (but it now)")
			return true
		}
	}
	return false
}
