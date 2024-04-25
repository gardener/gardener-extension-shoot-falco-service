package falcovalues

import (
	"testing"

	"github.com/gardener/gardener-extension-shoot-falco-service/falco"
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
