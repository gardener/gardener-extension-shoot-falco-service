<p>Packages:</p>
<ul>
<li>
<a href="#falco.extensions.gardener.cloud%2fv1alpha1">falco.extensions.gardener.cloud/v1alpha1</a>
</li>
</ul>
<h2 id="falco.extensions.gardener.cloud/v1alpha1">falco.extensions.gardener.cloud/v1alpha1</h2>
<p>
<p>Package v1alpha1 contains the Falco extension.</p>
</p>
Resource Types:
<ul><li>
<a href="#falco.extensions.gardener.cloud/v1alpha1.FalcoServiceConfig">FalcoServiceConfig</a>
</li></ul>
<h3 id="falco.extensions.gardener.cloud/v1alpha1.FalcoServiceConfig">FalcoServiceConfig
</h3>
<p>
<p>Falco cluster configuration resource</p>
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
falco.extensions.gardener.cloud/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>FalcoServiceConfig</code></td>
</tr>
<tr>
<td>
<code>falcoVersion</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Falco version to use</p>
</td>
</tr>
<tr>
<td>
<code>useFalcoIncubatingRules</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>use Falco incubating rules from correspoonging rules release</p>
</td>
</tr>
<tr>
<td>
<code>useFalcoSandboxRules</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>use Falco sandbox rules from corresponding rules release</p>
</td>
</tr>
<tr>
<td>
<code>ruleRefs</code></br>
<em>
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>References to custom rules files</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <a href="https://github.com/ahmetb/gen-crd-api-reference-docs">gen-crd-api-reference-docs</a>
</em></p>
