package vulnscanner

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Feature: vulnscanner, Property 8: Manifest parsing completeness
// For any valid package.json or requirements.txt built from a known set of
// dependencies, every dependency appears in the parser output with its version.
func TestProperty_ManifestParsingCompleteness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		names := rapid.SliceOfNDistinct(
			rapid.StringMatching(`[a-z][a-z0-9]{0,7}`),
			1, 8,
			func(s string) string { return s },
		).Draw(t, "names")

		want := make(map[string]string, len(names))
		for _, n := range names {
			want[n] = rapid.StringMatching(`[0-9]\.[0-9]\.[0-9]`).Draw(t, "v_"+n)
		}

		ecosystem := rapid.SampledFrom([]string{"npm", "pip"}).Draw(t, "ecosystem")

		var content string
		if ecosystem == "npm" {
			b, err := json.Marshal(map[string]map[string]string{"dependencies": want})
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			content = string(b)
		} else {
			var sb strings.Builder
			for n, v := range want {
				fmt.Fprintf(&sb, "%s==%s\n", n, v)
			}
			content = sb.String()
		}

		deps, err := ParseManifest(content, ecosystem)
		if err != nil {
			t.Fatalf("ParseManifest(%q) error: %v", ecosystem, err)
		}

		got := make(map[string]string, len(deps))
		for _, d := range deps {
			got[d.Name] = d.Version
		}
		for n, v := range want {
			gv, ok := got[n]
			if !ok {
				t.Errorf("dependency %q missing from parser output", n)
				continue
			}
			if gv != v {
				t.Errorf("dependency %q version = %q, want %q", n, gv, v)
			}
		}
	})
}
