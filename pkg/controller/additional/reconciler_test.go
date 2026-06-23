// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package additional_test

import (
	"bytes"
	"context"
	"io"
	"strings"
	"time"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
	crfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/controller/additional"
)

var _ = Describe("Reconciler", func() {
	var (
		ctx       context.Context
		scheme    *runtime.Scheme
		namespace string
	)

	BeforeEach(func() {
		ctx = context.Background()
		namespace = "garden"
		scheme = runtime.NewScheme()
		Expect(resourcesv1alpha1.AddToScheme(scheme)).To(Succeed())
		Expect(corev1.AddToScheme(scheme)).To(Succeed())
	})

	Describe("Reconcile", func() {
		It("should requeue after the reconcile interval on success", func() {
			fakeClient := crfake.NewClientBuilder().WithScheme(scheme).Build()
			r, err := additional.NewReconciler(fakeClient, nil, namespace, nil, "", zap.New(zap.WriteTo(GinkgoWriter)))
			Expect(err).NotTo(HaveOccurred())

			result, reconcileErr := r.Reconcile(ctx, reconcile.Request{})
			Expect(reconcileErr).NotTo(HaveOccurred())
			Expect(result.RequeueAfter).To(Equal(1 * time.Minute))
		})
	})

	Describe("Cleanup", func() {
		var (
			fakeClient client.Client
			r          *additional.Reconciler
		)

		staleMR := func(name string) *resourcesv1alpha1.ManagedResource {
			return &resourcesv1alpha1.ManagedResource{
				ObjectMeta: metav1.ObjectMeta{
					Name:      name,
					Namespace: namespace,
					Labels:    map[string]string{constants.AdditionalManagedResourceLabel: "true"},
				},
			}
		}

		BeforeEach(func() {
			fakeClient = crfake.NewClientBuilder().WithScheme(scheme).Build()
			var err error
			r, err = additional.NewReconciler(fakeClient, nil, namespace, nil, "", zap.New(zap.WriteTo(GinkgoWriter)))
			Expect(err).NotTo(HaveOccurred())
		})

		It("should delete stale resources not in config", func() {
			Expect(fakeClient.Create(ctx, staleMR(constants.AdditionalManagedResourcePrefix+"old-nginx"))).To(Succeed())
			Expect(fakeClient.Create(ctx, staleMR(constants.AdditionalManagedResourcePrefix+"old-redis"))).To(Succeed())

			var err error
			r, err = additional.NewReconciler(fakeClient, nil, namespace, &config.AdditionalConfig{
				SeedManagedResources: []config.AdditionalSeedManagedResource{
					{Name: "old-nginx"},
				},
			}, "", zap.New(zap.WriteTo(GinkgoWriter)))
			Expect(err).NotTo(HaveOccurred())

			Expect(r.Cleanup(ctx)).To(Succeed())

			mrList := &resourcesv1alpha1.ManagedResourceList{}
			Expect(fakeClient.List(ctx, mrList, client.InNamespace(namespace))).To(Succeed())
			Expect(mrList.Items).To(HaveLen(1))
			Expect(mrList.Items[0].Name).To(Equal(constants.AdditionalManagedResourcePrefix + "old-nginx"))
		})

		It("should delete all labeled resources when config is nil", func() {
			Expect(fakeClient.Create(ctx, staleMR(constants.AdditionalManagedResourcePrefix+"orphan"))).To(Succeed())

			Expect(r.Cleanup(ctx)).To(Succeed())

			mrList := &resourcesv1alpha1.ManagedResourceList{}
			Expect(fakeClient.List(ctx, mrList, client.InNamespace(namespace))).To(Succeed())
			Expect(mrList.Items).To(BeEmpty())
		})

		It("should not delete resources without the label", func() {
			unlabeled := &resourcesv1alpha1.ManagedResource{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "some-other-mr",
					Namespace: namespace,
				},
			}
			Expect(fakeClient.Create(ctx, unlabeled)).To(Succeed())

			Expect(r.Cleanup(ctx)).To(Succeed())

			mrList := &resourcesv1alpha1.ManagedResourceList{}
			Expect(fakeClient.List(ctx, mrList, client.InNamespace(namespace))).To(Succeed())
			Expect(mrList.Items).To(HaveLen(1))
		})
	})

	Describe("Deploy", func() {
		It("should return nil when additional config is nil", func() {
			r, err := additional.NewReconciler(nil, nil, namespace, nil, "", zap.New(zap.WriteTo(GinkgoWriter)))
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Deploy(ctx)).To(Succeed())
		})

		It("should return nil when seed managed resources list is empty", func() {
			r, err := additional.NewReconciler(nil, nil, namespace, &config.AdditionalConfig{}, "", zap.New(zap.WriteTo(GinkgoWriter)))
			Expect(err).NotTo(HaveOccurred())
			Expect(r.Deploy(ctx)).To(Succeed())
		})
	})
})

var _ = Describe("InjectNamespace", func() {
	const targetNS = "extension-shoot-falco-abc123"

	decodeAll := func(data []byte) []*unstructured.Unstructured {
		var objects []*unstructured.Unstructured
		decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(data), 1024)
		for {
			var raw map[string]interface{}
			if err := decoder.Decode(&raw); err != nil {
				if err == io.EOF {
					break
				}
				Fail("unexpected decode error: " + err.Error())
			}
			if raw == nil {
				continue
			}
			objects = append(objects, &unstructured.Unstructured{Object: raw})
		}
		return objects
	}

	It("should inject namespace into a resource without one", func() {
		manifest := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
data:
  key: value
`)
		result, err := additional.InjectNamespace(manifest, targetNS)
		Expect(err).NotTo(HaveOccurred())

		objects := decodeAll(result)
		Expect(objects).To(HaveLen(1))
		Expect(objects[0].GetNamespace()).To(Equal(targetNS))
		Expect(objects[0].GetName()).To(Equal("my-config"))
	})

	It("should not overwrite an existing namespace", func() {
		manifest := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: my-config
  namespace: kube-system
data:
  key: value
`)
		result, err := additional.InjectNamespace(manifest, targetNS)
		Expect(err).NotTo(HaveOccurred())

		objects := decodeAll(result)
		Expect(objects).To(HaveLen(1))
		Expect(objects[0].GetNamespace()).To(Equal("kube-system"))
	})

	It("should not inject namespace into a Namespace resource", func() {
		manifest := []byte(`apiVersion: v1
kind: Namespace
metadata:
  name: my-namespace
`)
		result, err := additional.InjectNamespace(manifest, targetNS)
		Expect(err).NotTo(HaveOccurred())

		objects := decodeAll(result)
		Expect(objects).To(HaveLen(1))
		Expect(objects[0].GetNamespace()).To(Equal(""))
		Expect(objects[0].GetKind()).To(Equal("Namespace"))
	})

	It("should handle multiple documents separated by ---", func() {
		manifest := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: config-one
---
apiVersion: v1
kind: Service
metadata:
  name: my-service
spec:
  ports:
  - port: 80
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
spec:
  replicas: 1
`)
		result, err := additional.InjectNamespace(manifest, targetNS)
		Expect(err).NotTo(HaveOccurred())

		objects := decodeAll(result)
		Expect(objects).To(HaveLen(3))
		Expect(objects[0].GetName()).To(Equal("config-one"))
		Expect(objects[0].GetNamespace()).To(Equal(targetNS))
		Expect(objects[1].GetName()).To(Equal("my-service"))
		Expect(objects[1].GetNamespace()).To(Equal(targetNS))
		Expect(objects[2].GetName()).To(Equal("my-deploy"))
		Expect(objects[2].GetNamespace()).To(Equal(targetNS))
	})

	It("should handle mixed namespaced and cluster-scoped resources", func() {
		manifest := []byte(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: my-role
rules: []
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-sa
`)
		result, err := additional.InjectNamespace(manifest, targetNS)
		Expect(err).NotTo(HaveOccurred())

		objects := decodeAll(result)
		Expect(objects).To(HaveLen(2))
		// ClusterRole has no namespace set, and InjectNamespace doesn't know it's cluster-scoped
		// (it doesn't have a REST mapper), so it sets the namespace. This is safe: the
		// resource-manager will unset it for non-namespaced kinds based on its REST mapping.
		Expect(objects[0].GetName()).To(Equal("my-role"))
		Expect(objects[1].GetName()).To(Equal("my-sa"))
		Expect(objects[1].GetNamespace()).To(Equal(targetNS))
	})

	It("should handle empty manifest", func() {
		result, err := additional.InjectNamespace([]byte(""), targetNS)
		Expect(err).NotTo(HaveOccurred())
		Expect(result).To(BeEmpty())
	})

	It("should skip empty YAML documents", func() {
		manifest := []byte(`---
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: real-config
---
`)
		result, err := additional.InjectNamespace(manifest, targetNS)
		Expect(err).NotTo(HaveOccurred())

		objects := decodeAll(result)
		Expect(objects).To(HaveLen(1))
		Expect(objects[0].GetName()).To(Equal("real-config"))
		Expect(objects[0].GetNamespace()).To(Equal(targetNS))
	})

	It("should preserve all fields of the original resource", func() {
		manifest := []byte(`apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-deploy
  labels:
    app: test
  annotations:
    note: important
spec:
  replicas: 3
  selector:
    matchLabels:
      app: test
  template:
    metadata:
      labels:
        app: test
    spec:
      containers:
      - name: main
        image: nginx:latest
        ports:
        - containerPort: 80
`)
		result, err := additional.InjectNamespace(manifest, targetNS)
		Expect(err).NotTo(HaveOccurred())

		objects := decodeAll(result)
		Expect(objects).To(HaveLen(1))
		obj := objects[0]
		Expect(obj.GetNamespace()).To(Equal(targetNS))
		Expect(obj.GetLabels()).To(HaveKeyWithValue("app", "test"))
		Expect(obj.GetAnnotations()).To(HaveKeyWithValue("note", "important"))

		replicas, found, err := unstructured.NestedFloat64(obj.Object, "spec", "replicas")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(replicas).To(Equal(float64(3)))

		containers, found, err := unstructured.NestedSlice(obj.Object, "spec", "template", "spec", "containers")
		Expect(err).NotTo(HaveOccurred())
		Expect(found).To(BeTrue())
		Expect(containers).To(HaveLen(1))
	})

	It("should return error for invalid YAML", func() {
		manifest := []byte(`not: valid: yaml: [[[`)
		_, err := additional.InjectNamespace(manifest, targetNS)
		Expect(err).To(HaveOccurred())
	})

	It("should produce valid multi-doc YAML output", func() {
		manifest := []byte(`apiVersion: v1
kind: ConfigMap
metadata:
  name: first
---
apiVersion: v1
kind: Secret
metadata:
  name: second
type: Opaque
`)
		result, err := additional.InjectNamespace(manifest, targetNS)
		Expect(err).NotTo(HaveOccurred())

		// Verify the output is valid YAML that can be re-parsed
		parts := strings.Split(string(result), "---\n")
		validDocs := 0
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			var obj map[string]interface{}
			Expect(yaml.Unmarshal([]byte(part), &obj)).To(Succeed())
			validDocs++
		}
		Expect(validDocs).To(Equal(2))
	})
})
