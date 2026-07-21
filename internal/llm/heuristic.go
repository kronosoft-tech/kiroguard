package llm

import (
	"bytes"
	"context"
	"strings"
	"text/template"
)

const templatePrefix = "template:"

// HeuristicProvider is a template-based LLM backend that generates explanations
// using Go's text/template. No network calls are made.
type HeuristicProvider struct {
	templates *template.Template
}

// NewHeuristicProvider creates a HeuristicProvider with the default set of
// registered templates for each module's explanation needs.
func NewHeuristicProvider() *HeuristicProvider {
	tmpl := template.New("root")

	// Vulnerability explanation template
	template.Must(tmpl.New("vuln_explanation").Parse(
		`Vulnerability {{.CVE}} (severity {{.Severity}}) affects versions {{.AffectedRange}}.` +
			` Upgrade to {{.FixedVersion}} to resolve this issue.`))

	// FinOps cost explanation template
	template.Must(tmpl.New("finops_explanation").Parse(
		`Pattern "{{.PatternType}}" detected at {{.FilePath}}:{{.LineNumber}}.` +
			` Estimated monthly cost: ${{.EstimatedCost}} based on {{.RequestsPerHour}} requests/hour.`))

	// Secret explanation template
	template.Must(tmpl.New("secret_explanation").Parse(
		`A {{.SecretType}} secret was detected at {{.FilePath}}:{{.LineNumber}}.` +
			` Rotate this credential immediately and use a secrets manager reference instead.`))

	return &HeuristicProvider{templates: tmpl}
}

// Complete extracts a template name from p.System (format "template:<name>") and
// executes the matching template with p.User as data. If no template matches,
// it falls back to returning p.User as-is.
func (h *HeuristicProvider) Complete(_ context.Context, p Prompt) (*LLMResponse, error) {
	metadata := make(map[string]string)

	// Check if System specifies a template name.
	if strings.HasPrefix(p.System, templatePrefix) {
		name := strings.TrimPrefix(p.System, templatePrefix)
		t := h.templates.Lookup(name)
		if t != nil {
			// Parse the User field as a map for template data.
			data := parseTemplateData(p.User)
			var buf bytes.Buffer
			if err := t.Execute(&buf, data); err == nil {
				return &LLMResponse{
					Text:     buf.String(),
					Metadata: metadata,
				}, nil
			}
			// On template execution error, fall through to passthrough.
		}
	}

	// Fallback: return the User prompt as-is.
	return &LLMResponse{
		Text:     p.User,
		Metadata: metadata,
	}, nil
}

// parseTemplateData converts a key=value line-separated string into a map
// suitable for template execution. Each line should be in the format "Key=Value".
func parseTemplateData(input string) map[string]string {
	data := make(map[string]string)
	for _, line := range strings.Split(input, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			data[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return data
}
