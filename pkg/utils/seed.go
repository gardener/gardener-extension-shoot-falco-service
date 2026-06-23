// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"

	gardenerv1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
)

// GetSeed fetches the Seed object for the given name from the garden cluster.
func GetSeed(ctx context.Context, client *dynamic.DynamicClient, seedName string) (*gardenerv1beta1.Seed, error) {
	seedResource, err := client.Resource(gardenerv1beta1.SchemeGroupVersion.WithResource("seeds")).Get(ctx, seedName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	var seed gardenerv1beta1.Seed
	err = runtime.DefaultUnstructuredConverter.FromUnstructured(seedResource.Object, &seed)
	if err != nil {
		return nil, err
	}
	return &seed, nil
}
