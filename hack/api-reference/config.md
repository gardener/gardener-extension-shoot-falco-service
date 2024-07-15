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
<ul></ul>
<h3 id="falco.extensions.config.gardener.cloud/v1alpha1.FalcoProfile">FalcoProfile
</h3>
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
<code>metadata</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#objectmeta-v1-meta">
Kubernetes meta/v1.ObjectMeta
</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the
<code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code></br>
<em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Spec">
Spec
</a>
</em>
</td>
<td>
<br/>
<br/>
<table>
<tr>
<td>
<code>versions</code></br>
<em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Versions">
Versions
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>images</code></br>
<em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Images">
Images
</a>
</em>
</td>
<td>
</td>
</tr>
</table>
</td>
</tr>
</tbody>
</table>
<h3 id="falco.extensions.config.gardener.cloud/v1alpha1.FalcoVersion">FalcoVersion
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Versions">Versions</a>)
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
<code>classification</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>expirationDate</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>rulesVersion</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="falco.extensions.config.gardener.cloud/v1alpha1.FalcosidekickVersion">FalcosidekickVersion
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Versions">Versions</a>)
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
<code>classification</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>expirationDate</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="falco.extensions.config.gardener.cloud/v1alpha1.ImageSpec">ImageSpec
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Images">Images</a>)
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
</td>
</tr>
<tr>
<td>
<code>architecture</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>repository</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>tag</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="falco.extensions.config.gardener.cloud/v1alpha1.Images">Images
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Spec">Spec</a>)
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
<code>falco</code></br>
<em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.ImageSpec">
[]ImageSpec
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>falcosidekick</code></br>
<em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.ImageSpec">
[]ImageSpec
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="falco.extensions.config.gardener.cloud/v1alpha1.Spec">Spec
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.FalcoProfile">FalcoProfile</a>)
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
<code>versions</code></br>
<em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Versions">
Versions
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>images</code></br>
<em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Images">
Images
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="falco.extensions.config.gardener.cloud/v1alpha1.Versions">Versions
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.Spec">Spec</a>)
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
<code>falco</code></br>
<em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.FalcoVersion">
[]FalcoVersion
</a>
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>falcosidekick</code></br>
<em>
<a href="#falco.extensions.config.gardener.cloud/v1alpha1.FalcosidekickVersion">
[]FalcosidekickVersion
</a>
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <a href="https://github.com/ahmetb/gen-crd-api-reference-docs">gen-crd-api-reference-docs</a>
</em></p>
