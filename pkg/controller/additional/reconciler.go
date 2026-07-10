// SPDX-FileCopyrightText: 2026 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package additional

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"text/template"
	"time"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"github.com/gardener/gardener/pkg/chartrenderer"
	managedresources "github.com/gardener/gardener/pkg/utils/managedresources"
	"github.com/gardener/gardener/pkg/utils/oci"
	"github.com/go-logr/logr"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"

	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/apis/config"
	"github.com/gardener/gardener-extension-shoot-falco-service/pkg/constants"
)

const reconcileInterval = 1 * time.Minute

// Reconciler periodically deploys additional seed ManagedResources from OCI Helm charts
// and cleans up stale ones that are no longer in the config.
type Reconciler struct {
	client                      client.Client
	namespace                   string
	additional                  *config.AdditionalConfig
	log                         logr.Logger
	helmRegistry                *oci.HelmRegistry
	renderer                    chartrenderer.Interface
	seedIngressDomain           string
	ingressWildcardCertificateName string
}

// NewReconciler creates a new Reconciler for additional seed resources.
func NewReconciler(c client.Client, restConfig *rest.Config, namespace string, additional *config.AdditionalConfig, seedIngressDomain string, ingressWildcardCertificateName string, log logr.Logger) (*Reconciler, error) {
	r := &Reconciler{
		client:                         c,
		namespace:                      namespace,
		additional:                     additional,
		seedIngressDomain:              seedIngressDomain,
		ingressWildcardCertificateName: ingressWildcardCertificateName,
		log:                            log,
	}

	if restConfig != nil {
		renderer, err := chartrenderer.NewForConfig(restConfig)
		if err != nil {
			return nil, fmt.Errorf("could not create chart renderer: %w", err)
		}
		r.helmRegistry = oci.NewHelmRegistry(c)
		r.renderer = renderer
	}

	return r, nil
}

// Reconcile deploys configured resources and cleans up stale ones, then requeues.
func (r *Reconciler) Reconcile(ctx context.Context, _ reconcile.Request) (reconcile.Result, error) {
	var errs []error

	if err := r.Deploy(ctx); err != nil {
		r.log.Error(err, "Failed to deploy additional seed resources")
		errs = append(errs, err)
	}
	if err := r.Cleanup(ctx); err != nil {
		r.log.Error(err, "Failed to clean up stale additional seed resources")
		errs = append(errs, err)
	}

	return reconcile.Result{RequeueAfter: reconcileInterval}, errors.Join(errs...)
}

// Deploy creates or updates ManagedResources for all configured Helm charts.
func (r *Reconciler) Deploy(ctx context.Context) error {
	if r.additional == nil || len(r.additional.SeedManagedResources) == 0 {
		return nil
	}

	if r.renderer == nil {
		return fmt.Errorf("chart renderer not initialized — restConfig was nil at construction time")
	}

	labels := map[string]string{constants.AdditionalManagedResourceLabel: "true"}
	var errs []error

	for _, res := range r.additional.SeedManagedResources {
		mrName := constants.AdditionalManagedResourcePrefix + res.Name

		if err := r.deployResource(ctx, res, mrName, labels); err != nil {
			r.log.Error(err, "Failed to deploy resource", "name", mrName)
			errs = append(errs, fmt.Errorf("resource %s: %w", res.Name, err))
			continue
		}
	}

	return errors.Join(errs...)
}

func (r *Reconciler) deployResource(ctx context.Context, res config.AdditionalSeedManagedResource, mrName string, labels map[string]string) error {
	var archive []byte
	var err error

	switch {
	case res.Helm.Chart != nil && *res.Helm.Chart != "":
		archive, err = base64.StdEncoding.DecodeString(*res.Helm.Chart)
		if err != nil {
			return fmt.Errorf("failed to decode inline chart: %w", err)
		}
	case res.Helm.OCIRepository != nil:
		if r.helmRegistry == nil {
			return fmt.Errorf("helm registry not initialized — restConfig was nil at construction time")
		}
		pullCtx := context.WithValue(ctx, oci.ContextKeySecretNamespace, r.namespace)
		archive, err = r.helmRegistry.Pull(pullCtx, res.Helm.OCIRepository)
		if err != nil {
			return fmt.Errorf("failed to pull chart: %w", err)
		}
	default:
		return fmt.Errorf("neither chart nor ociRepository set for resource %s", res.Name)
	}

	var values map[string]interface{}
	if res.Helm.Values != nil && res.Helm.Values.Raw != nil {
		raw, err := r.substituteTemplateVariables(res.Helm.Values.Raw)
		if err != nil {
			return fmt.Errorf("failed to substitute template variables in helm values: %w", err)
		}
		if err := json.Unmarshal(raw, &values); err != nil {
			return fmt.Errorf("failed to unmarshal helm values: %w", err)
		}
	}

	if values == nil {
		values = make(map[string]interface{})
	}
	values["ingressWildcardCertificateName"] = r.ingressWildcardCertificateName

	release, err := r.renderer.RenderArchive(archive, res.Name, r.namespace, values)
	if err != nil {
		return fmt.Errorf("failed to render chart: %w", err)
	}

	manifests, err := InjectNamespace(release.Manifest(), r.namespace)
	if err != nil {
		return fmt.Errorf("failed to inject namespace into manifests: %w", err)
	}

	var (
		isNew          = !r.managedResourceExists(ctx, mrName)
		data           = map[string][]byte{"manifests.yaml": manifests}
		keepObjects    = false
		forceOverwrite = false
	)

	if err := managedresources.Create(ctx, r.client, r.namespace, mrName, labels, false, "seed", data, &keepObjects, nil, &forceOverwrite); err != nil {
		return fmt.Errorf("failed to create or update managed resource: %w", err)
	}

	if isNew {
		r.log.Info("Created additional seed managed resource", "name", mrName)
	}
	return nil
}

func (r *Reconciler) managedResourceExists(ctx context.Context, mrName string) bool {
	mr := &resourcesv1alpha1.ManagedResource{}
	err := r.client.Get(ctx, types.NamespacedName{Namespace: r.namespace, Name: mrName}, mr)
	return err == nil || !apierrors.IsNotFound(err)
}

// substituteTemplateVariables replaces <<.VarName>> placeholders in raw JSON values
// with runtime values (same pattern as global default destinations in falcovalues.go).
// Go's json.Marshal escapes < and > as < / >, which prevents the
// text/template parser from recognizing << >> delimiters. We convert to YAML first
// (which does not escape these characters), perform substitution, then convert back.
func (r *Reconciler) substituteTemplateVariables(raw []byte) ([]byte, error) {
	var rawObj interface{}
	if err := yaml.Unmarshal(raw, &rawObj); err != nil {
		return nil, fmt.Errorf("failed to unmarshal values: %w", err)
	}
	yamlBytes, err := yaml.Marshal(rawObj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal values to YAML: %w", err)
	}

	data := map[string]string{
		"SeedIngressDomain": r.seedIngressDomain,
	}

	tmpl, err := template.New("").Delims("<<", ">>").Parse(string(yamlBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to parse template: %w", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, fmt.Errorf("failed to execute template: %w", err)
	}

	var result interface{}
	if err := yaml.Unmarshal(buf.Bytes(), &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal substituted values: %w", err)
	}
	return json.Marshal(result)
}

// Cleanup removes ManagedResources that are labeled as additional but no longer in the config.
func (r *Reconciler) Cleanup(ctx context.Context) error {
	desiredNames := sets.New[string]()
	if r.additional != nil {
		for _, res := range r.additional.SeedManagedResources {
			desiredNames.Insert(constants.AdditionalManagedResourcePrefix + res.Name)
		}
	}

	mrList := &resourcesv1alpha1.ManagedResourceList{}
	if err := r.client.List(ctx, mrList, client.InNamespace(r.namespace), client.MatchingLabels{constants.AdditionalManagedResourceLabel: "true"}); err != nil {
		return fmt.Errorf("failed to list additional managed resources: %w", err)
	}

	var errs []error
	for _, mr := range mrList.Items {
		if desiredNames.Has(mr.Name) {
			continue
		}
		r.log.Info("Deleting stale additional seed managed resource", "name", mr.Name)
		if err := managedresources.Delete(ctx, r.client, r.namespace, mr.Name, false); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete stale managed resource %s: %w", mr.Name, err))
		}
	}

	return errors.Join(errs...)
}

// InjectNamespace sets the namespace on all namespaced resources in the manifest
// that don't already have one. The resource-manager defaults namespace-less resources
// to "default", so we must inject the target namespace explicitly.
func InjectNamespace(manifest []byte, namespace string) ([]byte, error) {
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(manifest), 1024)
	var out bytes.Buffer

	for {
		var rawObj map[string]interface{}
		if err := decoder.Decode(&rawObj); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to decode YAML document: %w", err)
		}
		if rawObj == nil {
			continue
		}

		obj := &unstructured.Unstructured{Object: rawObj}
		if obj.GetNamespace() == "" && obj.GetKind() != "Namespace" {
			obj.SetNamespace(namespace)
		}

		patched, err := yaml.Marshal(obj.Object)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal patched object: %w", err)
		}

		if out.Len() > 0 {
			out.WriteString("---\n")
		}
		out.Write(patched)
	}

	return out.Bytes(), nil
}
