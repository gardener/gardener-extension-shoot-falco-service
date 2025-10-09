{{- define "name" -}}
gardener-extension-admission-shoot-falco-service
{{- end -}}

{{- define "labels.app.key" -}}
app.kubernetes.io/name
{{- end -}}
{{- define "labels.app.value" -}}
{{ include "name" . }}
{{- end -}}

{{- define "labels" -}}
{{ include "labels.app.key" . }}: {{ include "labels.app.value" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{-  define "image" -}}
  {{- if empty .tag }}
    {{- printf "%s" .repository }}
  {{- else }}
    {{- if hasPrefix "sha256:" .tag }}
      {{- printf "%s@%s" .repository .tag }}
    {{- else }}
      {{- printf "%s:%s" .repository .tag }}
    {{- end }}
  {{- end }}
{{- end }}

{{- define "leaderelectionid" -}}
gardener-extension-admission-shoot-falco-service
{{- end -}}