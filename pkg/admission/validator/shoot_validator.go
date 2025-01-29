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
	"strings"
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
	return &shoot{
		decoder: serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		restrictedUsage:          options.RestrictedUsage,
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

	alphaUsage, err := strconv.ParseBool(os.Getenv("RESTRICTED_USAGE"))
	if err == nil && alphaUsage {
		if oldFalcoConfErr != nil || oldFalcoConf == nil { // only verify elegibility if we can not read old shoot falco config or falco was not enabled before
			if ok := verifyProjectEligibility(shoot.Namespace); !ok {
				return fmt.Errorf("project is not eligible for Falco extension")
			}
		}
	}

	allErrs := []error{}

	if err := verifyFalcoVersion(falcoConf, oldFalcoConf); err != nil {
		allErrs = append(allErrs, err)
	}

	if err := verifyResources(falcoConf); err != nil {
		allErrs = append(allErrs, err)
	}

	if err := verifyOutput(falcoConf); err != nil {
		allErrs = append(allErrs, err)
	}

	if len(allErrs) > 0 {
		return errors.Join(allErrs...)
	}

	return nil
}

func verifyFalcoCtl(falcoConf *service.FalcoServiceConfig) error {

	ctl := falcoConf.FalcoCtl
	if len(ctl.Indexes) == 0 {
		return fmt.Errorf("no falcoctl index are is set")
	}
	return nil
}

func verifyGardenerSet(falcoConf *service.FalcoServiceConfig) error {
	gardenerManager := falcoConf.Gardener
	if gardenerManager == nil {
		return fmt.Errorf("gardener managing configuration not set")
	}
	if gardenerManager.UseFalcoRules == nil || gardenerManager.UseFalcoIncubatingRules == nil || gardenerManager.UseFalcoSandboxRules == nil {
		return fmt.Errorf("gardener rules not set")
	}
	// RulesRef will be set to default val as not a pointer
	return nil
}

func verifyWebhook(webhook *service.Webhook) error {
	if webhook.Address == nil {
		return fmt.Errorf("webhook address is not set")
	}
	return nil
}

func verifyOutput(falcoConf *service.FalcoServiceConfig) error {
	output := falcoConf.Output
	if output == nil {
		return fmt.Errorf("event ouptut is not defined")
	}
	if output.EventCollector == nil || !slices.Contains(constants.AllowedOutputs, *output.EventCollector) {
		return fmt.Errorf("output.eventCollector needs to be set to a value in %s", strings.Join(constants.AllowedOutputs, ", "))
	}
	if *output.EventCollector == "custom" {
		if output.CustomWebhook == nil {
			return fmt.Errorf("output.eventCollector is set to custom but customWebhook is not defined")
		}
		return verifyWebhook(falcoConf.Output.CustomWebhook)
	}
	if *output.EventCollector == "none" && !*output.LogFalcoEvents {
		return fmt.Errorf("output.eventCollector is set to none and logFalcoEvents is false - no output would be generated")
	}
	return nil
}

func verifyResources(falcoConf *service.FalcoServiceConfig) error {
	resource := falcoConf.Resources
	if resource == nil {
		return fmt.Errorf("resources property is not defined")
	}
	if *resource != "gardener" && *resource != "falcoctl" {
		return fmt.Errorf("resource needs to be either gardener or falcoctl")
	}

	if *resource == "gardener" {
		if falcoConf.Gardener == nil {
			return fmt.Errorf("gardener is set as resource but gardener property is not defined")
		}
		err := verifyGardenerSet(falcoConf)
		if err != nil {
			return err
		}
	}
	if *resource == "falcoctl" {
		if falcoConf.FalcoCtl == nil {
			return fmt.Errorf("falcoctl is set as resource but falcoctl property is not defined")
		}
		err := verifyFalcoCtl(falcoConf)
		if err != nil {
			return err
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
