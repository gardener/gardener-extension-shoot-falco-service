// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"os"

	healthcheckconfig "github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	apisconfig "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config/v1alpha1"
	controllerconfig "github.com/gardener/gardener-extension-shoot-falco-service/pkg/controller/config"
)

var (
	scheme  *runtime.Scheme
	decoder runtime.Decoder
)

func init() {
	scheme = runtime.NewScheme()
	utilruntime.Must(apisconfig.AddToScheme(scheme))
	utilruntime.Must(v1alpha1.AddToScheme(scheme))

	decoder = serializer.NewCodecFactory(scheme).UniversalDecoder()
}

// ConfigOptions are command line options that can be set for config.ControllerConfiguration.
type FalcoOptions struct {
	ConfigLocation string
	config         *FalcoConfig
}

type FalcoConfig struct {
	config apisconfig.Configuration
}

// Complete implements Completer.Complete.
func (o *FalcoOptions) Complete() error {
	if o.ConfigLocation == "" {
		return errors.New("config location is not set")
	}
	data, err := os.ReadFile(o.ConfigLocation)
	if err != nil {
		return err
	}

	config := apisconfig.Configuration{}
	_, _, err = decoder.Decode(data, nil, &config)
	if err != nil {
		return err
	}

	o.config = &FalcoConfig{
		config: config,
	}

	return nil
}

// Completed returns the completed Config. Only call this if `Complete` was successful.
func (c *FalcoOptions) Completed() *FalcoConfig {
	return c.config
}

// AddFlags implements Flagger.AddFlags.
func (c *FalcoOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&c.ConfigLocation, "config-file", "", "path to the controller manager configuration file")
}

// Apply sets the values of this Config in the given config.ControllerConfiguration.
func (c *FalcoConfig) Apply(config *controllerconfig.Config) {
	config.Configuration = c.config
}

// ApplyHealthCheckConfig applies the HealthCheckConfig to the config.
func (c *FalcoConfig) ApplyHealthCheckConfig(config *healthcheckconfig.HealthCheckConfig) {
	if c.config.HealthCheckConfig != nil {
		*config = *c.config.HealthCheckConfig
	}
}
