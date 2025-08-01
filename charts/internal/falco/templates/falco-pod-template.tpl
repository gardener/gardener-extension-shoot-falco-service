{{- define "falco.podTemplate" -}}
metadata:
  name: {{ include "falco.fullname" . }}
  labels:
    {{- if or .Values.falcoctl.artifact.install.enabled .Values.falcoctl.artifact.follow.enabled }}
    networking.gardener.cloud/to-public-networks: allowed
    {{- end }}
    {{- include "falco.selectorLabels" . | nindent 4 }}
    {{- with .Values.podLabels }}
      {{- toYaml . | nindent 4 }}
    {{- end }}
  annotations:
    checksum/config: {{ include (print $.Template.BasePath "/falco-configmap.yaml") . | sha256sum }}
    {{- if .Values.falcoRules }}
    checksum/falcoRules: {{ include (print $.Template.BasePath "/falco-rules.yaml") . | sha256sum }}
    {{- end }}
    {{- if .Values.falcoSandboxRules }}
    checksum/falcoSandboxRules: {{ include (print $.Template.BasePath "/falco-sandbox-rules.yaml") . | sha256sum }}
    {{- end }}
    {{- if .Values.falcoIncubatingRules }}
    checksum/falcoIncubatingRules: {{ include (print $.Template.BasePath "/falco-incubating-rules.yaml") . | sha256sum }}
    {{- end }}
    {{- if .Values.heartbeatRule }}
    checksum/falcoHeartbeatRule: {{ include (print $.Template.BasePath "/falco-heartbeat-rule.yaml") . | sha256sum }}
    {{- end }}
    {{- if .Values.customRules }}
    checksum/customRules: {{ include (print $.Template.BasePath "/falco-custom-rules.yaml") . | sha256sum }}
    {{- end }}
    {{- if and .Values.certs (not .Values.certs.existingSecret) }}
    checksum/certs: {{ include (print $.Template.BasePath "/falco-certs-secret.yaml") . | sha256sum }}
    {{- end }}
    {{- with .Values.podAnnotations }}
      {{- toYaml . | nindent 4 }}
    {{- end }}
spec:
  automountServiceAccountToken: false
  {{- with .Values.podSecurityContext }}
  securityContext:
    {{- toYaml . | nindent 4}}
  {{- end }}
  {{- if .Values.driver.enabled }}
  {{- if and (eq .Values.driver.kind "ebpf") .Values.driver.ebpf.hostNetwork }}
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
  {{- end }}
  {{- end }}
  {{- if .Values.priorityClassName }}
  priorityClassName: {{ .Values.priorityClassName }}
  {{- end }}
  {{- with .Values.nodeSelector }}
  nodeSelector:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.affinity }}
  affinity:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.tolerations }}
  tolerations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.imagePullSecrets }}
  imagePullSecrets: 
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- if .Values.gvisor.enabled }}
  hostNetwork: true
  hostPID: true
  {{- end }}
  containers:
    - name: {{ .Chart.Name }}
      {{- if ne .Values.image.image "" }}
      image: {{ .Values.image.image }}
      {{- else }}
      image: {{ include "falco.image" . }}
      {{- end }}
      imagePullPolicy: {{ .Values.image.pullPolicy }}
      resources:
        {{- toYaml .Values.resources | nindent 8 }}
      securityContext:
        {{- include "falco.securityContext" . | nindent 8 }}
      args:
        - /usr/bin/falco
        - --unbuffered
        {{- if .Values.gvisor.enabled }}
        - --gvisor-config
        - /gvisor-config/pod-init.json
        - --gvisor-root
        - /host{{ .Values.gvisor.runsc.root }}/k8s.io
        {{- end }}
        {{- include "falco.configSyscallSource" . | indent 8 }}
        {{- with .Values.collectors }}
        {{- if .enabled }}
        {{- if .kubernetes.enabled }}
        - -K
        - {{ .kubernetes.apiAuth }}
        - -k
        - {{ .kubernetes.apiUrl }}
        {{- if .kubernetes.enableNodeFilter }}
        - --k8s-node
        - "$(FALCO_K8S_NODE_NAME)"
        {{- end }}
        {{- end }}
        - -pk
        {{- end }}
        {{- end }}
    {{- with .Values.extra.args }}
      {{- toYaml . | nindent 8 }}
    {{- end }}
      env:
        - name: FALCO_HOSTNAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: FALCO_K8S_NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
      {{- if and .Values.driver.enabled (eq .Values.driver.kind "ebpf") }}
        - name: FALCO_BPF_PROBE
          value: {{ .Values.driver.ebpf.path }}
      {{- end }}
      {{- if .Values.extra.env }}
      {{- include "falco.renderTemplate" ( dict "value" .Values.extra.env "context" $) | nindent 8 }}
      {{- end }}
      tty: {{ .Values.tty }}
      {{- if .Values.falco.webserver.enabled }}
      livenessProbe:
        initialDelaySeconds: {{ .Values.healthChecks.livenessProbe.initialDelaySeconds }}
        timeoutSeconds: {{ .Values.healthChecks.livenessProbe.timeoutSeconds }}
        periodSeconds: {{ .Values.healthChecks.livenessProbe.periodSeconds }}
        httpGet:
          path: {{ .Values.falco.webserver.k8s_healthz_endpoint }}
          port: {{ .Values.falco.webserver.listen_port }}
          {{- if .Values.falco.webserver.ssl_enabled }}
          scheme: HTTPS
          {{- end }}
      readinessProbe:
        initialDelaySeconds: {{ .Values.healthChecks.readinessProbe.initialDelaySeconds }}
        timeoutSeconds: {{ .Values.healthChecks.readinessProbe.timeoutSeconds }}
        periodSeconds: {{ .Values.healthChecks.readinessProbe.periodSeconds }}
        httpGet:
          path: {{ .Values.falco.webserver.k8s_healthz_endpoint }}
          port: {{ .Values.falco.webserver.listen_port }}
          {{- if .Values.falco.webserver.ssl_enabled }}
          scheme: HTTPS
          {{- end }}
      {{- end }}
      volumeMounts:
      {{- include "falco.containerPluginVolumeMounts" . | nindent 8 }}
        - mountPath: /etc/falco/certs
          name: certificates
      {{- if or .Values.falcoctl.artifact.install.enabled .Values.falcoctl.artifact.follow.enabled }}
      {{- if has "rulesfile" .Values.falcoctl.config.artifact.allowedTypes }}
        - mountPath: /etc/falco
          name: rulesfiles-install-dir
      {{- end }}
      {{- if has "plugin" .Values.falcoctl.config.artifact.allowedTypes }}
        - mountPath: /usr/share/falco/plugins
          name: plugins-install-dir
      {{- end }}
      {{- end }}
        - mountPath: /root/.falco
          name: root-falco-fs
        {{- if or .Values.driver.enabled .Values.mounts.enforceProcMount }}
        - mountPath: /host/proc
          name: proc-fs
        {{- end }}
        {{- if and .Values.driver.enabled (not .Values.driver.loader.enabled) }}
          readOnly: true
        - mountPath: /host/boot
          name: boot-fs
          readOnly: true
        - mountPath: /host/lib/modules
          name: lib-modules
        - mountPath: /host/usr
          name: usr-fs
          readOnly: true
        - mountPath: /host/etc
          name: etc-fs
          readOnly: true
        {{- end }}
        {{- if and .Values.driver.enabled (eq .Values.driver.kind "module") }}
        - mountPath: /host/dev
          name: dev-fs
          readOnly: true
        - mountPath: /sys/module/falco
          name: sys-fs
        {{- end }}
        {{- if and .Values.driver.enabled (and (eq .Values.driver.kind "ebpf") (contains "falco-no-driver" .Values.image.repository)) }}
        - name: debugfs
          mountPath: /sys/kernel/debug
        {{- end }}
        {{- with .Values.collectors }}
        {{- if .enabled }}
        {{- if .containerd.enabled }}
        - mountPath: /host/run/containerd/containerd.sock
          name: containerd-socket
        {{- end }}
        {{- end }}
        {{- end }}
        - mountPath: /etc/falco/falco.yaml
          name: falco-yaml
          subPath: falco.yaml
        {{- if or .Values.certs.existingSecret (and .Values.certs.server.key .Values.certs.server.crt .Values.certs.ca.crt) }}
        - mountPath: /etc/falco/certs
          name: certs-volume
          readOnly: true
        {{- end }}
        {{- include "falco.unixSocketVolumeMount"  . | nindent 8 -}}
        {{- with .Values.mounts.volumeMounts }}
          {{- toYaml . | nindent 8 }}
        {{- end }}
        {{- if .Values.gvisor.enabled }}
        - mountPath: /usr/local/bin/runsc
          name: runsc-path
          readOnly: true
        - mountPath: /host{{ .Values.gvisor.runsc.root }}
          name: runsc-root
        - mountPath: /host{{ .Values.gvisor.runsc.config }}
          name: runsc-config
        - mountPath: /gvisor-config
          name: falco-gvisor-config
        {{- end }}
        - mountPath: /etc/falco/rules.d
          name: rules-volume
          readOnly: true
        {{- range $rulesConfigMap := $.Values.shoot_custom_rules }}
        - mountPath: {{ printf "/etc/falco/shoot-custom-rules/%s" $rulesConfigMap.name }}
          name: {{ printf "shoot-custom-rules-%s" $rulesConfigMap.name }}
        {{- end }}
  {{- if .Values.heartbeatRule }}
    - name: falco-heartbeat
      image: {{ include "falcoheartbeat.image" . }}
      command: ["sh", "-c"]
      args: 
        - |
          until wget -qO- http://127.0.0.1:8765/versions 2>/dev/null; do
            sleep 10
          done
          while true; do
            export FALCO_VERSION=$(
              wget -qO- http://127.0.0.1:8765/versions 2>/dev/null |
              grep -o '"falco_version":"[^"]*"' |
              sed 's/"falco_version":"//;s/"//'
            )
            export HEARTBEAT_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
            /bin/echo "Falco heartbeat" > /dev/null
            seconds_until_next_hour=$((3600 - $(date +%s) % 3600))
            sleep $seconds_until_next_hour
          done
  {{- end }}
  {{- if .Values.falcoctl.artifact.follow.enabled }}
    {{- include "falcoctl.sidecar" . | nindent 4 }}
  {{- end }}
  initContainers:
  {{- with .Values.extra.initContainers }}
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- if and .Values.gvisor.enabled }}
  {{- include "falco.gvisor.initContainer" . | nindent 4 }}
  {{- end }}
  {{- if and .Values.driver.enabled (ne .Values.driver.kind "modern-bpf") }}
  {{- if.Values.driver.loader.enabled }}
    {{- include "falco.driverLoader.initContainer" . | nindent 4 }}
  {{- end }}
  {{- end }}
  {{- if .Values.falcoctl.artifact.install.enabled }}
    {{- include "falcoctl.initContainer" . | nindent 4 }}
  {{- end }}
  volumes:
    {{- include "falco.containerPluginVolumes" . | nindent 4 }}
    - name: certificates
      secret:
        secretName: falco-certs
    {{- if or .Values.falcoctl.artifact.install.enabled .Values.falcoctl.artifact.follow.enabled }}
    - name: plugins-install-dir
      emptyDir: {}
    - name: rulesfiles-install-dir
      emptyDir: {}
    {{- end }}
    - name: root-falco-fs
      emptyDir: {}
    {{- if .Values.driver.enabled }}  
    - name: boot-fs
      hostPath:
        path: /boot
    - name: lib-modules
      hostPath:
        path: /lib/modules
    - name: usr-fs
      hostPath:
        path: /usr
    - name: etc-fs
      hostPath:
        path: /etc
    {{- end }}
    {{- if and .Values.driver.enabled (eq .Values.driver.kind "module") }}
    - name: dev-fs
      hostPath:
        path: /dev
    - name: sys-fs
      hostPath:
        path: /sys/module/falco
    {{- end }}
    {{- if and .Values.driver.enabled (and (eq .Values.driver.kind "ebpf") (contains "falco-no-driver" .Values.image.repository)) }}
    - name: debugfs
      hostPath:
        path: /sys/kernel/debug
    {{- end }}
    {{- with .Values.collectors }}
    {{- if .enabled }}
    {{- if .containerd.enabled }}
    - name: containerd-socket
      hostPath:
        path: {{ .containerd.socket }}
    {{- end }}
    {{- end }}
    {{- end }}
    {{- if or .Values.driver.enabled .Values.mounts.enforceProcMount }}
    - name: proc-fs
      hostPath:
        path: /proc
    {{- end }}
    {{- if .Values.gvisor.enabled }}
    - name: runsc-path
      hostPath:
        path: {{ .Values.gvisor.runsc.path }}/runsc
        type: File
    - name: runsc-root
      hostPath:
        path: {{ .Values.gvisor.runsc.root }}
    - name: runsc-config
      hostPath:
        path: {{ .Values.gvisor.runsc.config }}
        type: File
    - name: falco-gvisor-config
      emptyDir: {}
    {{- end }}
    - name: falcoctl-config-volume
      configMap: 
        name: {{ include "falco.fullname" . }}-falcoctl
        items:
          - key: falcoctl.yaml
            path: falcoctl.yaml
    - name: falco-yaml
      configMap:
        name: {{ include "falco.fullname" . }}
        items:
        - key: falco.yaml
          path: falco.yaml
    - name: rules-volume
      projected:
        defaultMode: 0644
        sources:
        {{- if .Values.falcoRules }}
        - configMap:
            name: falco-rules
        {{- end }}
        {{- if .Values.falcoIncubatingRules }}
        - configMap:
            name: falco-incubating-rules
        {{- end }}
        {{- if .Values.falcoSandboxRules }}
        - configMap:
            name: falco-sandbox-rules
        {{- end }}
        {{- if .Values.heartbeatRule }}
        - configMap:
            name: falco-heartbeat-rule
        {{- end }}
        {{- if .Values.customRules }}
        - configMap:
            name: falco-custom-rules
        {{- end }}
    {{- range $rulesConfigMap := $.Values.shoot_custom_rules }}
    - name: {{ printf "shoot-custom-rules-%s" $rulesConfigMap.name }}
      projected:
        defaultMode: 0644
        sources:
        - configMap:
            name: {{ $rulesConfigMap.name }}
    {{- end }}
    {{- if or .Values.certs.existingSecret (and .Values.certs.server.key .Values.certs.server.crt .Values.certs.ca.crt) }}
    - name: certs-volume
      secret:
        {{- if .Values.certs.existingSecret }}
        secretName: {{ .Values.certs.existingSecret }}
        {{- else }}
        secretName: {{ include "falco.fullname" . }}-certs
        {{- end }}
    {{- end }}
    {{- include "falco.unixSocketVolume" . | nindent 4 -}}
    {{- with .Values.mounts.volumes }}
      {{- toYaml . | nindent 4 }}
    {{- end }}
    {{- end -}}

{{- define "falco.driverLoader.initContainer" -}}
- name: {{ .Chart.Name }}-driver-loader
  image: {{ include "falco.driverLoader.image" . }}
  imagePullPolicy: {{ .Values.driver.loader.initContainer.image.pullPolicy }}
  {{- with .Values.driver.loader.initContainer.args }}
  args:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  {{- with .Values.driver.loader.initContainer.resources }}
  resources:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  securityContext:
  {{- if .Values.driver.loader.initContainer.securityContext }}
    {{- toYaml .Values.driver.loader.initContainer.securityContext | nindent 4 }}
  {{- else if eq .Values.driver.kind "module" }}
    privileged: true
  {{- end }}
  volumeMounts:
    - mountPath: /root/.falco
      name: root-falco-fs
    - mountPath: /host/proc
      name: proc-fs
      readOnly: true
    - mountPath: /host/boot
      name: boot-fs
      readOnly: true
    - mountPath: /host/lib/modules
      name: lib-modules
    - mountPath: /host/usr
      name: usr-fs
      readOnly: true
    - mountPath: /host/etc
      name: etc-fs
      readOnly: true
  env:
  {{- if eq .Values.driver.kind "ebpf" }}
    - name: FALCO_BPF_PROBE
      value: {{ .Values.driver.ebpf.path }}
  {{- end }}
  {{- if .Values.driver.loader.initContainer.env }}
  {{- include "falco.renderTemplate" ( dict "value" .Values.driver.loader.initContainer.env "context" $) | nindent 4 }}
  {{- end }}
{{- end -}}

{{- define "falco.securityContext" -}}
{{- $securityContext := dict -}}
{{- if .Values.driver.enabled -}}
  {{- if eq .Values.driver.kind "module" -}}
    {{- $securityContext := set $securityContext "privileged" true -}}
  {{- end -}}
  {{- if eq .Values.driver.kind "ebpf" -}}
    {{- if .Values.driver.ebpf.leastPrivileged -}}
      {{- $securityContext := set $securityContext "capabilities" (dict "add" (list "SYS_ADMIN" "SYS_RESOURCE" "SYS_PTRACE")) -}}
    {{- else -}}
      {{- $securityContext := set $securityContext "privileged" true -}}
    {{- end -}}
  {{- end -}}
  {{- if (or (eq .Values.driver.kind "modern_ebpf") (eq .Values.driver.kind "modern-bpf")) -}}
    {{- if .Values.driver.modernEbpf.leastPrivileged -}}
      {{- $securityContext := set $securityContext "capabilities" (dict "add" (list "BPF" "SYS_RESOURCE" "PERFMON" "SYS_PTRACE")) -}}
    {{- else -}}
      {{- $securityContext := set $securityContext "privileged" true -}}
    {{- end -}}
  {{- end -}}
{{- end -}}
{{- if not (empty (.Values.containerSecurityContext)) -}}
  {{-  toYaml .Values.containerSecurityContext }}
{{- else -}}
  {{- toYaml $securityContext }}
{{- end -}}
{{- end -}}


{{- define "falco.unixSocketVolumeMount" -}}
{{- if and .Values.falco.grpc.enabled .Values.falco.grpc.bind_address (hasPrefix "unix://" .Values.falco.grpc.bind_address) }}
- mountPath: {{ include "falco.unixSocketDir" . }}
  name: grpc-socket-dir
{{- end }}
{{- end -}}

{{- define "falco.unixSocketVolume" -}}
{{- if and .Values.falco.grpc.enabled .Values.falco.grpc.bind_address (hasPrefix "unix://" .Values.falco.grpc.bind_address) }}
- name: grpc-socket-dir
  hostPath:
    path: {{ include "falco.unixSocketDir" . }}
{{- end }}
{{- end -}}
