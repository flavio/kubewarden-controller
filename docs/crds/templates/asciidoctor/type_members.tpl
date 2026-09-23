{{- define "type_members" -}}
{{- $field := . -}}
{{- if eq $field.Name "metadata" -}}
Refer to Kubernetes API documentation for fields of `metadata`.
{{ else -}}
{{- $doc := replace "|" "\\|" $field.Doc -}}
{{- $doc = replace "```json" "[source,json]\n----" $doc -}}
{{- $doc = replace "```" "----" $doc -}}
{{ $doc }}
{{- end -}}
{{- end -}}
