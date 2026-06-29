<p>Packages:</p>
<ul>
<li>
<a href="#falco.gardener.cloud%2fv1alpha1">falco.gardener.cloud/v1alpha1</a>
</li>
</ul>

<h2 id="falco.gardener.cloud/v1alpha1">falco.gardener.cloud/v1alpha1</h2>
<p>

</p>
Resource Types:
<ul>
<li>
<a href="#falcoprofile">FalcoProfile</a>
</li>
</ul>

<h3 id="falcoprofile">FalcoProfile
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
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#objectmeta-v1-meta">ObjectMeta</a>
</em>
</td>
<td>
Refer to the Kubernetes API documentation for the fields of the <code>metadata</code> field.
</td>
</tr>
<tr>
<td>
<code>spec</code></br>
<em>
<a href="#spec">Spec</a>
</em>
</td>
<td>
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="falcoversion">FalcoVersion
</h3>


<p>
(<em>Appears on:</em><a href="#versions">Versions</a>)
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
<p></p>
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
<p></p>
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
<p></p>
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
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="falcoctlversion">FalcoctlVersion
</h3>


<p>
(<em>Appears on:</em><a href="#versions">Versions</a>)
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
<p></p>
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
<p></p>
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
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="falcosidekickversion">FalcosidekickVersion
</h3>


<p>
(<em>Appears on:</em><a href="#versions">Versions</a>)
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
<p></p>
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
<p></p>
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
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="imagespec">ImageSpec
</h3>


<p>
(<em>Appears on:</em><a href="#images">Images</a>)
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
<p></p>
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
<p></p>
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
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="images">Images
</h3>


<p>
(<em>Appears on:</em><a href="#spec">Spec</a>)
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
<a href="#imagespec">ImageSpec</a> array
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>falcosidekick</code></br>
<em>
<a href="#imagespec">ImageSpec</a> array
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>falcoctl</code></br>
<em>
<a href="#imagespec">ImageSpec</a> array
</em>
</td>
<td>
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="spec">Spec
</h3>


<p>
(<em>Appears on:</em><a href="#falcoprofile">FalcoProfile</a>)
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
<a href="#versions">Versions</a>
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>images</code></br>
<em>
<a href="#images">Images</a>
</em>
</td>
<td>
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="version">Version
</h3>
<p><em>Underlying type: interface{GetClassification() string; GetExpirationDate() *string; GetVersion() string}</em></p>


<p>

</p>


<h3 id="versions">Versions
</h3>


<p>
(<em>Appears on:</em><a href="#spec">Spec</a>)
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
<a href="#falcoversion">FalcoVersion</a> array
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>falcosidekick</code></br>
<em>
<a href="#falcosidekickversion">FalcosidekickVersion</a> array
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>falcoctl</code></br>
<em>
<a href="#falcoctlversion">FalcoctlVersion</a> array
</em>
</td>
<td>
<p></p>
</td>
</tr>

</tbody>
</table>


