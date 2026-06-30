<p>Packages:</p>
<ul>
<li>
<a href="#falco.extensions.config.gardener.cloud%2fv1alpha1">falco.extensions.config.gardener.cloud/v1alpha1</a>
</li>
</ul>

<h2 id="falco.extensions.config.gardener.cloud/v1alpha1">falco.extensions.config.gardener.cloud/v1alpha1</h2>
<p>

</p>

<h3 id="additionalconfig">AdditionalConfig
</h3>


<p>
(<em>Appears on:</em><a href="#falco">Falco</a>)
</p>

<p>
AdditionalConfig holds configuration for additional seed-level resources.
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
<code>seedManagedResources</code></br>
<em>
<a href="#additionalseedmanagedresource">AdditionalSeedManagedResource</a> array
</em>
</td>
<td>
<em>(Optional)</em>
<p>SeedManagedResources is a list of Helm charts to deploy as ManagedResources on the seed.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="additionalseedmanagedresource">AdditionalSeedManagedResource
</h3>


<p>
(<em>Appears on:</em><a href="#additionalconfig">AdditionalConfig</a>)
</p>

<p>
AdditionalSeedManagedResource describes a Helm chart to deploy as a ManagedResource on the seed.
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
<p>Name is the name of the ManagedResource.</p>
</td>
</tr>
<tr>
<td>
<code>helm</code></br>
<em>
<a href="#helmconfig">HelmConfig</a>
</em>
</td>
<td>
<p>Helm specifies the chart to pull and render.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="centralstorageconfig">CentralStorageConfig
</h3>


<p>
(<em>Appears on:</em><a href="#falco">Falco</a>)
</p>

<p>
Central storage configuration
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
<code>tokenLifetime</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#duration-v1-meta">Duration</a>
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
<em>(Optional)</em>
<p>Private key for token issuer</p>
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
<em>(Optional)</em>
<p>Ingestor URL</p>
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
<em>(Optional)</em>
<p>Central storage configuration enabled</p>
</td>
</tr>

</tbody>
</table>


<h3 id="clusteridentitytokenconfig">ClusterIdentityTokenConfig
</h3>


<p>
(<em>Appears on:</em><a href="#falco">Falco</a>)
</p>

<p>
ClusterIdentityTokenConfig holds configuration for issuing per-shoot JWT tokens
used as template variable in global default destinations
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
<code>tokenIssuerPrivateKey</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Private key (PEM-encoded RSA) for signing cluster identity tokens</p>
</td>
</tr>
<tr>
<td>
<code>tokenLifetime</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#duration-v1-meta">Duration</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Lifetime of the issued token</p>
</td>
</tr>

</tbody>
</table>


<h3 id="configuration">Configuration
</h3>


<p>
Configuration contains information about the falco extension configuration
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
<a href="#falco">Falco</a>
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
<a href="#healthcheckconfig">HealthCheckConfig</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>HealthCheckConfig is the config for the health check controller.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="falco">Falco
</h3>


<p>
(<em>Appears on:</em><a href="#configuration">Configuration</a>)
</p>

<p>
Falco extension configuration
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
<code>centralStorage</code></br>
<em>
<a href="#centralstorageconfig">CentralStorageConfig</a>
</em>
</td>
<td>
<p>Central storage configuration</p>
</td>
</tr>
<tr>
<td>
<code>clusterIdentityToken</code></br>
<em>
<a href="#clusteridentitytokenconfig">ClusterIdentityTokenConfig</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Cluster identity token configuration for global default destinations</p>
</td>
</tr>
<tr>
<td>
<code>certificateLifetime</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#duration-v1-meta">Duration</a>
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
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#duration-v1-meta">Duration</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Renew CA certificates after this duration</p>
</td>
</tr>
<tr>
<td>
<code>defaultEventDestination</code></br>
<em>
string
</em>
</td>
<td>
<p>Default event logger<br />possible values are: "none", "central", "cluster", "webhook"</p>
</td>
</tr>
<tr>
<td>
<code>globalDefaultDestinations</code></br>
<em>
<a href="#globaldefaultdestination">GlobalDefaultDestination</a> array
</em>
</td>
<td>
<em>(Optional)</em>
<p>Global default destinations applied to all shoots unless opted out</p>
</td>
</tr>
<tr>
<td>
<code>additional</code></br>
<em>
<a href="#additionalconfig">AdditionalConfig</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Additional resources to deploy on the seed</p>
</td>
</tr>

</tbody>
</table>


<h3 id="falcosidekickoutput">FalcosidekickOutput
</h3>


<p>
(<em>Appears on:</em><a href="#globaldefaultdestination">GlobalDefaultDestination</a>)
</p>

<p>
FalcosidekickOutput holds the Falcosidekick output key and value configuration
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
<code>key</code></br>
<em>
string
</em>
</td>
<td>
<p>Falcosidekick output key (e.g., "splunk", "webhook", "elasticsearch")</p>
</td>
</tr>
<tr>
<td>
<code>value</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#rawextension-runtime-pkg">RawExtension</a>
</em>
</td>
<td>
<p>Configuration values for the output (may contain template variables)</p>
</td>
</tr>

</tbody>
</table>


<h3 id="globaldefaultdestination">GlobalDefaultDestination
</h3>


<p>
(<em>Appears on:</em><a href="#falco">Falco</a>)
</p>

<p>
GlobalDefaultDestination defines an operator-provided Falcosidekick output destination
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
<p>Unique name for this destination</p>
</td>
</tr>
<tr>
<td>
<code>falcosidekickOutput</code></br>
<em>
<a href="#falcosidekickoutput">FalcosidekickOutput</a>
</em>
</td>
<td>
<p>Falcosidekick output configuration</p>
</td>
</tr>

</tbody>
</table>


<h3 id="helmconfig">HelmConfig
</h3>


<p>
(<em>Appears on:</em><a href="#additionalseedmanagedresource">AdditionalSeedManagedResource</a>)
</p>

<p>
HelmConfig specifies a Helm chart source and render values.
Exactly one of OCIRepository or Chart must be set.
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
<code>ociRepository</code></br>
<em>
<a href="#ocirepository">OCIRepository</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>OCIRepository defines where to pull the chart from.</p>
</td>
</tr>
<tr>
<td>
<code>chart</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Chart is a base64-encoded, gzipped tar archive of the Helm chart.</p>
</td>
</tr>
<tr>
<td>
<code>values</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#rawextension-runtime-pkg">RawExtension</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Values are the Helm values to use when rendering the chart.</p>
</td>
</tr>

</tbody>
</table>


