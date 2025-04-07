// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"fmt"
	"sync"
	"time"

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
	logger     logr.Logger
	client     *dynamic.DynamicClient
	namespaces map[string]*v1.Namespace
	mutex      *sync.Mutex
}

var NamespacesInstance *Namespaces

func NewNamespaces(client *dynamic.DynamicClient) {
	lg, _ := logger.NewZapLogger(logger.InfoLevel, logger.FormatJSON)
	NamespacesInstance = &Namespaces{
		logger:     lg,
		client:     client,
		mutex:      &sync.Mutex{},
		namespaces: make(map[string]*v1.Namespace),
	}
}

func (n *Namespaces) StartNamespaceWatch() {
	for {
		err := n.watch()
		if err != nil {
			n.logger.Error(err, "watch on namespaces failed")
		}
		time.Sleep(time.Second)
	}
}

func (n *Namespaces) watch() error {
	watcher, err := n.client.Resource(schema.GroupVersionResource{
		Group:    "",
		Version:  "v1",
		Resource: "namespaces",
	}).Watch(context.Background(), metav1.ListOptions{})
	if err != nil {
		return err
	}
	for event := range watcher.ResultChan() {
		switch event.Type {
		case watch.Added, watch.Modified:
			ns, err := n.decodeEvent(event.Object)
			if err != nil {
				n.logger.Error(err, "error decoding namespace event")
			} else {
				n.updateEvent(ns)
			}
		case watch.Deleted:
			ns, err := n.decodeEvent(event.Object)
			if err != nil {
				n.logger.Error(err, "error decoding namespace event")
			} else {
				n.deleteEvent(ns.Name)
			}
		}
	}
	return nil
}

func (n *Namespaces) GetNamespace(name string) *v1.Namespace {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	namespace := n.namespaces[name]
	if namespace == nil {
		return nil
	}
	return namespace.DeepCopy()
}

func (n *Namespaces) deleteEvent(name string) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	delete(n.namespaces, name)
	n.logger.Info("namespace deleted", "name", name)
}

func (n *Namespaces) updateEvent(ns *v1.Namespace) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.namespaces[ns.Name] = ns
	n.logger.Info("namespace updated", "name", ns.Name)
}

func (n *Namespaces) decodeEvent(obj runtime.Object) (*v1.Namespace, error) {
	var ns v1.Namespace
	un, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("event object of wrong type")
	}
	err := runtime.DefaultUnstructuredConverter.FromUnstructured(un.Object, &ns)
	if err != nil {
		return nil, fmt.Errorf("cannot convert from unstructured: %w", err)
	}
	return &ns, nil
}
