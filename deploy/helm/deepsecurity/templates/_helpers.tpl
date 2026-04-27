{{/*
Common helpers for the deepsecurity chart.
*/}}

{{- define "deepsecurity.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "deepsecurity.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "deepsecurity.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "deepsecurity.labels" -}}
helm.sh/chart: {{ include "deepsecurity.chart" . }}
{{ include "deepsecurity.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "deepsecurity.selectorLabels" -}}
app.kubernetes.io/name: {{ include "deepsecurity.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "deepsecurity.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "deepsecurity.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "deepsecurity.image" -}}
{{- $tag := default .Chart.AppVersion .Values.image.tag -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}
