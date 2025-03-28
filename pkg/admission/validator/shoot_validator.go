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

	if err := verifyEventDestinations(falcoConf, shoot); err != nil {
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
	if falcoConf.Rules == nil {
		return fmt.Errorf("rules property is not defined")
	}

	if falcoConf.Rules.StandardRules != nil {
		if standardRulesErr := verifyStandardRules(*falcoConf.Rules.StandardRules); standardRulesErr != nil {
			return standardRulesErr
		}
	}

	if falcoConf.Rules.CustomRules != nil {
		if customRulesErr := verifyCustomRules(*falcoConf.Rules.CustomRules, shoot); customRulesErr != nil {
			return customRulesErr
		}
	}

	if falcoConf.Rules.StandardRules == nil && falcoConf.Rules.CustomRules == nil {
		return fmt.Errorf("falco deployment without any rules is not allowed")
	}

	return nil
}

func verifyStandardRules(standardRules []string) error {
	if len(standardRules) == 0 {
		return fmt.Errorf("standard rules are empty")
	}

	for _, rule := range standardRules {
		if !slices.Contains(constants.AllowedStandardRules, rule) {
			return fmt.Errorf("unknown standard rule %s", rule)
		}
	}

	if !unique(standardRules) {
		return fmt.Errorf("double entry in standard rules")
	}
	return nil
}

func verifyCustomRules(customRules []service.CustomRule, shoot *core.Shoot) error {
	if len(customRules) == 0 {
		return fmt.Errorf("custom rules are empty")
	}

	customRulesNames := make([]string, 0)
	for _, rule := range customRules {
		if rule.ResourceRef == "" {
			return fmt.Errorf("found custom rule with empty resource referece")
		}
		customRulesNames = append(customRulesNames, rule.ResourceRef)
	}

	if !unique(customRulesNames) {
		return fmt.Errorf("double entry in custom rules")
	}

	for _, ruleName := range customRulesNames {
		found := false
		for _, r := range shoot.Spec.Resources {
			if r.ResourceRef.Kind == "ConfigMap" && r.Name == ruleName {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("custom rule %s not found in resources", ruleName)
		}
	}
	return nil
}

func verifyEventDestinations(falcoConf *service.FalcoServiceConfig, shoot *core.Shoot) error {
	if falcoConf.Destinations == nil {
		return fmt.Errorf("event destination property is not defined")
	}

	if len(*falcoConf.Destinations) == 0 {
		return fmt.Errorf("no event destination is set")
	}

	if len(*falcoConf.Destinations) > 2 {
		return fmt.Errorf("more than two event destinations are not allowed")
	}

	eventDestinationNames := make([]string, 0)
	for _, dest := range *falcoConf.Destinations {
		if !slices.Contains(constants.AllowedDestinations, dest.Name) {
			return fmt.Errorf("unknown event destination %s", dest.Name)
		}
		eventDestinationNames = append(eventDestinationNames, dest.Name)
	}

	if !unique(eventDestinationNames) {
		return fmt.Errorf("double entry in event destinations")
	}

	if len(eventDestinationNames) > 1 {
		if !slices.Contains(eventDestinationNames, constants.FalcoEventDestinationStdout) {
			return fmt.Errorf("output destinations can only be paired with stdout")
		}
	}

	idxCustom := slices.IndexFunc(*falcoConf.Destinations, func(dest service.Destination) bool {
		return dest.Name == constants.FalcoEventDestinationCustom
	})

	if idxCustom != -1 { // custom event destination is set
		return verifyCustomDestination((*falcoConf.Destinations)[idxCustom], shoot)
	}

	return nil
}

func verifyCustomDestination(customDest service.Destination, shoot *core.Shoot) error {
	if customDest.ResourceSecretRef == nil {
		return fmt.Errorf("custom event destination is set but no custom config is defined")
	}

	found := false
	for _, s := range shoot.Spec.Resources {
		if s.ResourceRef.Kind == "Secret" && s.Name == *customDest.ResourceSecretRef {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("custom event destination config %s not found in resources", *customDest.ResourceSecretRef)
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
			return true
		}
	}
	return false
}
