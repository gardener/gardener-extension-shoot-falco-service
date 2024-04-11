<p>Packages:</p>
<ul>
<li>
<a href="#falco.extensions.config.gardener.cloud%2fv1alpha1">falco.extensions.config.gardener.cloud/v1alpha1</a>
</li>
</ul>
<h2 id="falco.extensions.config.gardener.cloud/v1alpha1">falco.extensions.config.gardener.cloud/v1alpha1</h2>
<p>
<p>Package v1alpha1 contains the falco extension configuration.</p>
</p>
Resource Types:
<ul><li>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Configuration">Configuration</a>
</li></ul>
<h3 id="falco.extensions.config.gardener.cloud/v1alpha1.Configuration">Configuration
</h3>
<p>
<p>Configuration contains information about the falco extension configuration</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>apiVersion</code></br>
string</td>
<td>
<code>
falco.extensions.config.gardener.cloud/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>Configuration</code></td>
</tr>
<tr>
<td>
<code>falco</code></br>
<em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Falco">
Falco
</a>
</em>
</td>
<td>
<p>Falco extension configuration</p>
</td>
</tr>
<tr>
<td>
<code>healthCheckConfig</code></br>
<em>
<a href="https://github.com/gardener/gardener/extensions/pkg/apis/config">
github.com/gardener/gardener/extensions/pkg/apis/config/v1alpha1.HealthCheckConfig
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>HealthCheckConfig is the config for the health check controller.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="falco.extensions.config.gardener.cloud/v1alpha1.Falco">Falco
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Configuration">Configuration</a>)
</p>
<p>
<p>Falco extension configuration</p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>priorityClassName</code></br>
<em>
string
</em>
</td>
<td>
<p>PriorityClass to use for Falco shoot deployment</p>
</td>
</tr>
<tr>
<td>
<code>certificateLifetime</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#duration-v1-meta">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Lifetime of the CA certificates</p>
</td>
</tr>
<tr>
<td>
<code>certificateRenewAfter</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#duration-v1-meta">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Renew CA certificates after this duration</p>
</td>
</tr>
<tr>
<td>
<code>tokenLifetime</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#duration-v1-meta">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Token lifetime</p>
</td>
</tr>
<tr>
<td>
<code>tokenIssuerPrivateKey</code></br>
<em>
string
</em>
</td>
<td>
<p>Private key for token issuer</p>
</td>
</tr>
<tr>
<td>
<code>ingestorURL</code></br>
<em>
string
</em>
</td>
<td>
<p>Ingestor URL</p>
</td>
</tr>
<tr>
<td>
<code>falcoVersions</code></br>
<em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.FalcoVersions">
[]FalcoVersions
</a>
</em>
</td>
<td>
<p>Falco versions</p>
</td>
</tr>
<tr>
<td>
<code>falcoImages</code></br>
<em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.FalcoImages">
[]FalcoImages
</a>
</em>
</td>
<td>
<p>Falco images</p>
</td>
</tr>
</tbody>
</table>
<h3 id="falco.extensions.config.gardener.cloud/v1alpha1.FalcoImages">FalcoImages
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Falco">Falco</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
<p>Falco version</p>
</td>
</tr>
<tr>
<td>
<code>architectures</code></br>
<em>
[]string
</em>
</td>
<td>
<p>supported architectures (amd64, arm64)</p>
</td>
</tr>
<tr>
<td>
<code>falcoImage</code></br>
<em>
string
</em>
</td>
<td>
<p>Falco image for that version</p>
</td>
</tr>
<tr>
<td>
<code>falcosidekickImage</code></br>
<em>
string
</em>
</td>
<td>
<p>Falcosidekick image for that version</p>
</td>
</tr>
</tbody>
</table>
<h3 id="falco.extensions.config.gardener.cloud/v1alpha1.FalcoVersions">FalcoVersions
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Falco">Falco</a>)
</p>
<p>
</p>
<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>
<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
<p>Falco version</p>
</td>
</tr>
<tr>
<td>
<code>classification</code></br>
<em>
string
</em>
</td>
<td>
<p>Classification: [preview|supported|deprecated]</p>
</td>
</tr>
<tr>
<td>
<code>expiryDate</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#time-v1-meta">
Kubernetes meta/v1.Time
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>date when Falco version is going to expire</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <a href="https://github.com/ahmetb/gen-crd-api-reference-docs">gen-crd-api-reference-docs</a>
</em></p>
