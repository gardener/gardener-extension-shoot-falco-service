package falcovalues

import (
	"testing"

	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/extensions"
	autoscalingv1 "k8s.io/api/autoscaling/v1"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
	apisservice "github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/service"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/utils/falcoversions"
)

var (
	c1 falco.Falco = falco.Falco{
		Falco: &falcoversions.FalcoVersions{
			FalcoVersions: []falcoversions.FalcoVersion{
				{
					Version:        "0.29.0",
					Classification: "supported",
				},
				{
					Version:        "0.29.1",
					Classification: "supported",
				},
				{
					Version:        "0.29.2",
					Classification: "preview",
				},
			},
		},
	}
	c2 falco.Falco = falco.Falco{
		Falco: &falcoversions.FalcoVersions{
			FalcoVersions: []falcoversions.FalcoVersion{
				{
					Version:        "0.29.0",
					Classification: "supported",
				},
				{
					Version:        "0.29.1",
					Classification: "supported",
				},
				{
					Version:        "0.29.2",
					Classification: "preview",
				},
				{
					Version:        "0.29.3",
					Classification: "deprecated",
				},
				{
					Version:        "0.30.3",
					Classification: "supported",
				},
			},
		},
	}
)

func TestGetFalcoVersion(t *testing.T) {

	cb := NewConfigBuilder(nil, nil, nil, &c1)
	version, err := cb.getDefaultFalcoVersion()
	if err != nil {
		t.Errorf("Error while getting default falco version: %v", err)
	}
	if version != "0.29.1" {
		t.Errorf("Expected version 0.29.1, but got %s", version)
	}
	cb = NewConfigBuilder(nil, nil, nil, &c2)
	version, err = cb.getDefaultFalcoVersion()
	if err != nil {
		t.Errorf("Error while getting default falco version: %v", err)
	}
	if version != "0.30.3" {
		t.Errorf("Expected version 0.30.3, but got %s", version)
	}
}

func TestCustomRulesInShootSpec(t *testing.T) {
	shootSpec := &extensions.Cluster{
		Shoot: &gardencorev1beta1.Shoot{
			Spec: gardencorev1beta1.ShootSpec{
				Resources: []gardencorev1beta1.NamedResourceReference{
					{
						Name: "rules1",
						ResourceRef: autoscalingv1.CrossVersionObjectReference{
							Kind:       "ConfigMap",
							Name:       "myrules1",
							APIVersion: "v1",
						},
					},
					{
						Name: "rules2",
						ResourceRef: autoscalingv1.CrossVersionObjectReference{
							Kind:       "ConfigMap",
							Name:       "myrules2",
							APIVersion: "v1",
						},
					},
				},
			},
		},
	}
	resources := "gardener"
	falcoServiceConfig := &apisservice.FalcoServiceConfig{
		Resources: &resources,
		Gardener: &apisservice.Gardener{
			RuleRefs: []apisservice.Rule{
				{
					Ref: "rules1",
				},
				{
					Ref: "rules2",
				},
			},
		},
	}
	falcoServiceConfigBad := &apisservice.FalcoServiceConfig{
		Resources: &resources,
		Gardener: &apisservice.Gardener{
			RuleRefs: []apisservice.Rule{
				{
					Ref: "rules1",
				},
				{
					Ref: "rules3",
				},
			},
		},
	}

	configBuilder := ConfigBuilder{}
	res, err := configBuilder.extractCustomRules(shootSpec, falcoServiceConfig)
	if err != nil {
		t.Errorf("should not get an error here: %v", err)
		t.FailNow()

	}
	if len(res) != 2 {
		t.Errorf("expected 2 results")
	}
	if _, ok := (res)["rules1"]; !ok {
		t.Errorf("expected result to contain \"rules1\"")
	}
	if _, ok := (res)["rules2"]; !ok {
		t.Errorf("expected result to contain \"rules2\"")
	}
	_, err = configBuilder.extractCustomRules(shootSpec, falcoServiceConfigBad)
	if err == nil {
		t.Errorf("should get an error as configuration is not consistent")
	}
}
