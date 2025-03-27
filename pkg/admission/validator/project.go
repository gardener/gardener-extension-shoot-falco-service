// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/logger"
	"github.com/go-logr/logr"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
)

type Namespaces struct {
	logger   logr.Logger
	client   *dynamic.DynamicClient
	projects map[string]*v1.Namespace
	mutex    *sync.Mutex
}

var NamespacesInstance *Namespaces

func NewProjects(client *dynamic.DynamicClient) {
	lg, _ := logger.NewZapLogger(logger.InfoLevel, logger.FormatJSON)
	NamespacesInstance = &Namespaces{
		logger:     lg,
		client:     client,
		mutex:      &sync.Mutex{},
		namespaces: make(map[string]*v1.Namespace),
	}
}

func (p *Projects) StartProjectWatch() {
	for {
		err := p.watch()
		if err != nil {
			p.logger.Error(err, "watch on projects failed")
		}
		time.Sleep(time.Second)
	}
}

func (p *Projects) watch() error {
	watcher, err := p.client.Resource(schema.GroupVersionResource{
		Group:    "core.gardener.cloud",
		Version:  "v1beta1",
		Resource: "projects",
	}).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for event := range watcher.ResultChan() {
		switch event.Type {
		case watch.Added, watch.Modified:
			fe, err := p.decodeEvent(event.Object)
			if err != nil {
				p.logger.Error(err, "error decoding project event")
			} else {
				p.updateEvent(fe)
			}
		case watch.Deleted:
			fe, err := p.decodeEvent(event.Object)
			if err != nil {
				p.logger.Error(err, "error decoding project event")
			} else {
				p.deleteEvent(*fe.Spec.Namespace)
			}
		}
	}
	return nil
}

func (p *Projects) GetProject(namespace string) *v1beta1.Project {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	project := p.projects[namespace]
	if project == nil {
		return nil
	}
	return project.DeepCopy()
}

func (p *Projects) deleteEvent(namespace string) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	delete(p.projects, namespace)
	p.logger.Info("project deleted", "namespace", namespace)
}

func (p *Projects) updateEvent(fe *v1beta1.Project) {
	p.mutex.Lock()
	defer p.mutex.Unlock()
	p.projects[*fe.Spec.Namespace] = fe
	p.logger.Info("project updated", "name", fe.Name)
}

func (p *Projects) decodeEvent(obj runtime.Object) (*v1beta1.Project, error) {
	var fe v1beta1.Project
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
