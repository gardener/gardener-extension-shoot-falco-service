// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package imagevector

import (
	_ "embed"
	"os"

	"github.com/gardener/gardener/pkg/utils/imagevector"
	"k8s.io/apimachinery/pkg/util/runtime"
)

const (
	// OverrideEnv is the name of the image vector override environment variable.
	OverrideEnv = "IMAGEVECTOR_OVERWRITE"
)

var (
	//go:embed images.yaml
	imagesYAML  string
	imageVector imagevector.ImageVector
)

func init() {

	var err error
	imageVector, err = imagevector.Read([]byte(imagesYAML))
	runtime.Must(err)

	imageVector, err = withEnvOverride(imageVector)
	runtime.Must(err)
}

// ImageVector is the image vector that contains all the needed images.
func ImageVector() imagevector.ImageVector {
	return imageVector
}

// Note: the code below should be replaced by the code in the
// Gardener imagevector class. Currently this does not handle
// multiple version of a component

type imageSourceKey struct {
	Name           string
	Version        string
	RuntimeVersion string
	TargetVersion  string
}

func computeKey(source *imagevector.ImageSource) imageSourceKey {
	var (
		runtimeVersion, targetVersion, version string
	)

	if source.RuntimeVersion != nil {
		runtimeVersion = *source.RuntimeVersion
	}

	if source.TargetVersion != nil {
		targetVersion = *source.TargetVersion
	}

	if source.Version != nil {
		version = *source.Version
	}

	return imageSourceKey{
		Name:           source.Name,
		Version:        version,
		RuntimeVersion: runtimeVersion,
		TargetVersion:  targetVersion,
	}
}

// The gardener imagevector.Merge function only allows for one version
// per name.
func merge(vectors ...imagevector.ImageVector) imagevector.ImageVector {
	var (
		out        imagevector.ImageVector
		keyToIndex = make(map[imageSourceKey]int)
	)

	for _, vector := range vectors {
		for _, image := range vector {
			key := computeKey(image)

			if idx, ok := keyToIndex[key]; ok {
				out[idx] = mergeImageSources(out[idx], image)
				continue
			}

			keyToIndex[key] = len(out)
			out = append(out, image)
		}
	}

	return out
}

// mergeImageSources merges the two given ImageSources.
//
// If the tag of the override is non-empty, it immediately returns the override.
// Otherwise, the override is copied, gets the tag of the old source and is returned.
func mergeImageSources(old, override *imagevector.ImageSource) *imagevector.ImageSource {
	tag := override.Tag
	if tag == nil {
		tag = old.Tag
	}

	version := override.Version
	if version == nil {
		version = old.Version
	}
	if version == nil && tag != nil {
		version = old.Tag
	}

	runtimeVersion := override.RuntimeVersion
	if runtimeVersion == nil {
		runtimeVersion = old.RuntimeVersion
	}

	targetVersion := override.TargetVersion
	if targetVersion == nil {
		targetVersion = old.TargetVersion
	}

	return &imagevector.ImageSource{
		Name:           override.Name,
		RuntimeVersion: runtimeVersion,
		TargetVersion:  targetVersion,
		Repository:     override.Repository,
		Tag:            tag,
		Version:        version,
	}
}

func withEnvOverride(vector imagevector.ImageVector) (imagevector.ImageVector, error) {
	overwritePath := os.Getenv(OverrideEnv)
	if len(overwritePath) == 0 {
		return vector, nil
	}

	override, err := imagevector.ReadFile(overwritePath)
	if err != nil {
		return nil, err
	}

	return merge(vector, override), nil
}
