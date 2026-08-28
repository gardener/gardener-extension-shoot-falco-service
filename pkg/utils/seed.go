// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package utils

import (
	"context"
	"fmt"

	gardenerv1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	operatorv1alpha1 "github.com/gardener/gardener/pkg/apis/operator/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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

var gardenGVR = schema.GroupVersionResource{
	Group:    "operator.gardener.cloud",
	Version:  "v1alpha1",
	Resource: "gardens",
}

// GetGarden fetches the (single) Garden object from the runtime cluster.
func GetGarden(ctx context.Context, client *dynamic.DynamicClient) (*operatorv1alpha1.Garden, error) {
	list, err := client.Resource(gardenGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	if len(list.Items) == 0 {
		return nil, fmt.Errorf("no Garden object found on runtime cluster")
	}
	var garden operatorv1alpha1.Garden
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(list.Items[0].Object, &garden); err != nil {
		return nil, err
	}
	return &garden, nil
}
