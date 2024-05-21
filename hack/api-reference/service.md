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
<code>autoUpdate</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>Automatically update Falco</p>
</td>
</tr>
<tr>
<td>
<code>resources</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>use &ldquo;gardener&rdquo; or &ldquo;falcoctl&rdquo;, defaults to &ldquo;gardener&rdquo;</p>
</td>
</tr>
<tr>
<td>
<code>falcoCtl</code></br>
<em>
<a href="#falco.extensions.gardener.cloud/v1alpha1.FalcoCtl">
FalcoCtl
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Falcoctl configuration</p>
</td>
</tr>
<tr>
<td>
<code>gardener</code></br>
<em>
<a href="#falco.extensions.gardener.cloud/v1alpha1.Gardener">
Gardener
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Configuration for Gardener managed Falco</p>
</td>
</tr>
<tr>
<td>
<code>webhook</code></br>
<em>
<a href="#falco.extensions.gardener.cloud/v1alpha1.Webhook">
Webhook
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Configuration for custom webhook</p>
</td>
</tr>
</tbody>
</table>
<h3 id="falco.extensions.gardener.cloud/v1alpha1.FalcoCtl">FalcoCtl
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.gardener.cloud/v1alpha1.FalcoServiceConfig">FalcoServiceConfig</a>)
</p>
<p>
</p>
<h3 id="falco.extensions.gardener.cloud/v1alpha1.Gardener">Gardener
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.gardener.cloud/v1alpha1.FalcoServiceConfig">FalcoServiceConfig</a>)
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
<code>useFalcoRules</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>use Falco rules from correspoonging rules release, defaults to true</p>
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
<a href="#falco.extensions.gardener.cloud/v1alpha1.Rule">
[]Rule
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>References to custom rules files</p>
</td>
</tr>
</tbody>
</table>
<h3 id="falco.extensions.gardener.cloud/v1alpha1.Rule">Rule
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.gardener.cloud/v1alpha1.Gardener">Gardener</a>)
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
<code>ref</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="falco.extensions.gardener.cloud/v1alpha1.Webhook">Webhook
</h3>
<p>
(<em>Appears on:</em>
<a href="#falco.extensions.gardener.cloud/v1alpha1.FalcoServiceConfig">FalcoServiceConfig</a>)
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
<code>enabled</code></br>
<em>
bool
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>address</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>customHeaders</code></br>
<em>
string
</em>
</td>
<td>
</td>
</tr>
<tr>
<td>
<code>checkcerts</code></br>
<em>
bool
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
