// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package profile

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gardener/gardener/pkg/logger"
	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/profile/v1alpha1"
)

type Image struct {
	Repository   string
	Tag          string
	Architectrue string
	Version      string
}

type Version struct {
	Classification string
	ExpirationDate *time.Time
	Version        string
}

type FalcoProfileManager struct {
	client                *dynamic.DynamicClient
	falcoProfiles         map[string]*v1alpha1.FalcoProfile
	falcoImages           map[string]Image
	falcosidekickImages   map[string]Image
	falcoVersions         map[string]Version
	falcosidekickVersions map[string]Version
	mutex                 sync.Mutex
	logger                logr.Logger
}

func NewFalcoProfileManager(client *dynamic.DynamicClient) *FalcoProfileManager {
	lg, _ := logger.NewZapLogger(logger.InfoLevel, logger.FormatJSON)
	return &FalcoProfileManager{
		client:                client,
		falcoProfiles:         make(map[string]*v1alpha1.FalcoProfile),
		falcoImages:           make(map[string]Image),
		falcosidekickImages:   make(map[string]Image),
		falcoVersions:         make(map[string]Version),
		falcosidekickVersions: make(map[string]Version),
		mutex:                 sync.Mutex{},
		logger:                lg,
	}
}

func (p *FalcoProfileManager) GetFalcoImageForVersion(version string) *Image {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	i := p.falcoImages[version]
	return &i
}

func (p *FalcoProfileManager) StartWatch() {
	for {
		err := p.watch()
		if err != nil {
			p.logger.Error(err, "cannot initialize FalcoProfile watcher, retrying ...")
		}
		time.Sleep(time.Second)
	}
}

func (p *FalcoProfileManager) watch() error {
	p.logger.Info("Starting watches for FalcoProfile custom resources")
	watcher, err := p.client.Resource(schema.GroupVersionResource{
		Group:    v1alpha1.GroupName,
		Version:  v1alpha1.GroupVersion,
		Resource: "falcoprofiles",
	}).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for event := range watcher.ResultChan() {
		switch event.Type {
		case watch.Added, watch.Modified:
			fe, err := decodeEvent(event.Object)
			if err != nil {
				p.logger.Error(err, "error decoding FalcoProfile event")
			} else {
				p.updateEvent(fe)
			}
		case watch.Deleted:
			fe, err := decodeEvent(event.Object)
			if err != nil {
				p.logger.Error(err, "error decoding FalcoProfile event")
			} else {
				p.deleteEvent(fe.ObjectMeta.Name)
			}
		}
	}
	return nil
}

func (p *FalcoProfileManager) rebuild() {
	p.logger.Info("Rebuilding FalcoProfile data structures")
	clear(p.falcoImages)
	clear(p.falcosidekickImages)
	for _, profile := range p.falcoProfiles {
		for _, q := range profile.Spec.Images.Falco {
			im := Image{
				Repository:   q.Repository,
				Tag:          q.Tag,
				Architectrue: q.Architecture,
				Version:      q.Version,
			}
			p.falcoImages[q.Version] = im
		}
		for _, q := range profile.Spec.Versions.Falco {
			v := Version{
				Classification: q.Classification,
				//ExpirationDate: q.ExpirationDate,
				Version: q.Version,
			}
			p.falcoVersions[q.Version] = v
		}
		for _, q := range profile.Spec.Images.Falcosidekick {
			im := Image{
				Repository:   q.Repository,
				Tag:          q.Tag,
				Architectrue: q.Architecture,
				Version:      q.Version,
			}
			p.falcosidekickImages[q.Version] = im
		}
		for _, q := range profile.Spec.Versions.Falcosidekick {
			v := Version{
				Classification: q.Classification,
				//ExpirationDate: q.ExpirationDate,
				Version: q.Version,
			}
			p.falcosidekickVersions[q.Version] = v
		}
	}
}

func (p *FalcoProfileManager) updateEvent(profile *v1alpha1.FalcoProfile) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.falcoProfiles[profile.ObjectMeta.Name] = profile
	p.rebuild()
}

func (p *FalcoProfileManager) deleteEvent(name string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	delete(p.falcoProfiles, name)
	p.rebuild()
}

func decodeEvent(obj runtime.Object) (*v1alpha1.FalcoProfile, error) {
	var fe v1alpha1.FalcoProfile
	un, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("event object of wrong type")
	}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.Object, &fe)
	if err != nil {
		return nil, fmt.Errorf("cannot convert from unstructured: %w", err)
	}
	return &fe, nil
}
