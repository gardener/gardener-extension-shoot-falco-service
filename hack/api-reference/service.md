<p>Packages:</p>
<ul>
<li>
<a href="#falco.extensions.gardener.cloud%2fv1alpha1">falco.extensions.gardener.cloud/v1alpha1</a>
</li>
</ul>

<h2 id="falco.extensions.gardener.cloud/v1alpha1">falco.extensions.gardener.cloud/v1alpha1</h2>
<p>

</p>

<h3 id="adaptiveresources">AdaptiveResources
</h3>


<p>
(<em>Appears on:</em><a href="#falcoconfig">FalcoConfig</a>)
</p>

<p>
AdaptiveResources configures per-worker-pool dynamic resource sizing for Falco.
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
<code>formulas</code></br>
<em>
<a href="#resourceformulas">ResourceFormulas</a>
</em>
</td>
<td>
<p>Formulas defines arithmetic expressions for each resource field.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="customrule">CustomRule
</h3>


<p>
(<em>Appears on:</em><a href="#rules">Rules</a>)
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
<code>resourceName</code></br>
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
<code>shootConfigMap</code></br>
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


<h3 id="destination">Destination
</h3>


<p>
(<em>Appears on:</em><a href="#falcoserviceconfig">FalcoServiceConfig</a>)
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
<code>name</code></br>
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
<code>enabled</code></br>
<em>
boolean
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>resourceSecretName</code></br>
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


<h3 id="falcoconfig">FalcoConfig
</h3>


<p>
(<em>Appears on:</em><a href="#falcoserviceconfig">FalcoServiceConfig</a>)
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
<code>resources</code></br>
<em>
<a href="#falcoresources">FalcoResources</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Resources configures static resource requests/limits for the Falco container.<br />Mutually exclusive with AdaptiveResources. If neither is set, chart defaults apply.</p>
</td>
</tr>
<tr>
<td>
<code>adaptiveResources</code></br>
<em>
<a href="#adaptiveresources">AdaptiveResources</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>AdaptiveResources enables per-worker-pool dynamic resource sizing.<br />The feature is active when this field is non-nil. Mutually exclusive with Resources.<br />Only available for Gardener-managed shoots with worker pools.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="falcoctl">FalcoCtl
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
<code>indexes</code></br>
<em>
<a href="#falcoctlindex">FalcoCtlIndex</a> array
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>allowedTypes</code></br>
<em>
string array
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>install</code></br>
<em>
<a href="#install">Install</a>
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>follow</code></br>
<em>
<a href="#follow">Follow</a>
</em>
</td>
<td>
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="falcoctlindex">FalcoCtlIndex
</h3>


<p>
(<em>Appears on:</em><a href="#falcoctl">FalcoCtl</a>)
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
<code>name</code></br>
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
<code>url</code></br>
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


<h3 id="falcoresources">FalcoResources
</h3>


<p>
(<em>Appears on:</em><a href="#falcoconfig">FalcoConfig</a>)
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
<code>limits</code></br>
<em>
<a href="#resourcevalues">ResourceValues</a>
</em>
</td>
<td>
<p>limits</p>
</td>
</tr>
<tr>
<td>
<code>requests</code></br>
<em>
<a href="#resourcevalues">ResourceValues</a>
</em>
</td>
<td>
<p>requests</p>
</td>
</tr>

</tbody>
</table>


<h3 id="falcoserviceconfig">FalcoServiceConfig
</h3>


<p>
Falco cluster configuration resource
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
<code>falcoConfig</code></br>
<em>
<a href="#falcoconfig">FalcoConfig</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>additional Falco configuration</p>
</td>
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
boolean
</em>
</td>
<td>
<em>(Optional)</em>
<p>Automatically update Falco</p>
</td>
</tr>
<tr>
<td>
<code>heartbeatEvent</code></br>
<em>
boolean
</em>
</td>
<td>
<em>(Optional)</em>
<p>Enable periodic heartbeat events</p>
</td>
</tr>
<tr>
<td>
<code>nodeSelector</code></br>
<em>
map[string]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>nodeSelector for Falco pods</p>
</td>
</tr>
<tr>
<td>
<code>tolerations</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#toleration-v1-core">Toleration</a> array
</em>
</td>
<td>
<em>(Optional)</em>
<p>tolerations for Falco pods</p>
</td>
</tr>
<tr>
<td>
<code>rules</code></br>
<em>
<a href="#rules">Rules</a>
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>destinations</code></br>
<em>
<a href="#destination">Destination</a> array
</em>
</td>
<td>
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="follow">Follow
</h3>


<p>
(<em>Appears on:</em><a href="#falcoctl">FalcoCtl</a>)
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
<code>refs</code></br>
<em>
string array
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>every</code></br>
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


<h3 id="gardener">Gardener
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
<code>useFalcoRules</code></br>
<em>
boolean
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
boolean
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
boolean
</em>
</td>
<td>
<em>(Optional)</em>
<p>use Falco sandbox rules from corresponding rules release</p>
</td>
</tr>
<tr>
<td>
<code>customRules</code></br>
<em>
string array
</em>
</td>
<td>
<em>(Optional)</em>
<p>References to custom rules files</p>
</td>
</tr>

</tbody>
</table>


<h3 id="install">Install
</h3>


<p>
(<em>Appears on:</em><a href="#falcoctl">FalcoCtl</a>)
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
<code>refs</code></br>
<em>
string array
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>resolveDeps</code></br>
<em>
boolean
</em>
</td>
<td>
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="output">Output
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
<code>logFalcoEvents</code></br>
<em>
boolean
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>eventCollector</code></br>
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
<code>customWebhook</code></br>
<em>
<a href="#webhook">Webhook</a>
</em>
</td>
<td>
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="resourceformulas">ResourceFormulas
</h3>


<p>
(<em>Appears on:</em><a href="#adaptiveresources">AdaptiveResources</a>)
</p>

<p>
ResourceFormulas holds one optional expression per resource field.
Each expression is evaluated against node capacity variables and must produce a number.
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
<code>cpuRequest</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>CPURequest expression. Result unit: millicores (500 → "500m").</p>
</td>
</tr>
<tr>
<td>
<code>cpuLimit</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>CPULimit expression. Result unit: millicores.</p>
</td>
</tr>
<tr>
<td>
<code>memoryRequest</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>MemoryRequest expression. Result unit: MiB (2048 → "2048Mi").</p>
</td>
</tr>
<tr>
<td>
<code>memoryLimit</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>MemoryLimit expression. Result unit: MiB.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="resourcevalues">ResourceValues
</h3>


<p>
(<em>Appears on:</em><a href="#falcoresources">FalcoResources</a>)
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
<code>cpu</code></br>
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
<code>memory</code></br>
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


<h3 id="rules">Rules
</h3>


<p>
(<em>Appears on:</em><a href="#falcoserviceconfig">FalcoServiceConfig</a>)
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
<code>standard</code></br>
<em>
string array
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>custom</code></br>
<em>
<a href="#customrule">CustomRule</a> array
</em>
</td>
<td>
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="webhook">Webhook
</h3>


<p>
(<em>Appears on:</em><a href="#output">Output</a>)
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
boolean
</em>
</td>
<td>
<p></p>
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
<p></p>
</td>
</tr>
<tr>
<td>
<code>method</code></br>
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
<code>customHeaders</code></br>
<em>
map[string]string
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>checkcerts</code></br>
<em>
boolean
</em>
</td>
<td>
<p></p>
</td>
</tr>
<tr>
<td>
<code>secretRef</code></br>
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


