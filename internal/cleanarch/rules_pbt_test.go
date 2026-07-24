package cleanarch

import (
	"testing"

	"pgregory.net/rapid"
)

// Feature: cleanarch, Property 11: Architecture violation detection correctness
// For any set of edges and rules, Evaluate must report a violation for an edge
// if and only if the first rule matching that edge (by From/To glob) is a deny
// rule. An allow rule matching first suppresses the edge. This asserts no false
// positives and no false negatives relative to the documented first-match
// semantics.
func TestProperty_ViolationDetectionCorrectness(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		segGen := rapid.SampledFrom([]string{
			"domain", "infrastructure", "presentation", "shared", "app",
		})

		edgeGen := rapid.Custom(func(t *rapid.T) ImportEdge {
			return ImportEdge{
				FromFile:   "file.go",
				FromPkg:    "myapp/" + segGen.Draw(t, "fromSeg"),
				ImportPath: "myapp/" + segGen.Draw(t, "toSeg"),
				LineNumber: 1,
			}
		})
		edges := rapid.SliceOfN(edgeGen, 0, 10).Draw(t, "edges")

		patGen := rapid.SampledFrom([]string{
			"**/domain/**", "**/infrastructure/**", "**/presentation/**",
			"**/shared/**", "**/app/**", "myapp/domain", "**",
		})
		ruleGen := rapid.Custom(func(t *rapid.T) Rule {
			return Rule{
				From:  patGen.Draw(t, "ruleFrom"),
				To:    patGen.Draw(t, "ruleTo"),
				Allow: rapid.Bool().Draw(t, "allow"),
				Desc:  "generated rule",
			}
		})
		rules := rapid.SliceOfN(ruleGen, 0, 6).Draw(t, "rules")

		got := Evaluate(edges, rules)

		// Independent oracle: first matching rule wins.
		var want []ArchViolation
		for _, e := range edges {
			for _, r := range rules {
				if matchGlob(r.From, e.FromPkg) && matchGlob(r.To, e.ImportPath) {
					if !r.Allow {
						want = append(want, ArchViolation{
							FilePath:    e.FromFile,
							LineNumber:  e.LineNumber,
							FromPkg:     e.FromPkg,
							Import:      e.ImportPath,
							RuleName:    r.From + " -> " + r.To,
							Description: r.Desc,
						})
					}
					break
				}
			}
		}

		if len(got) != len(want) {
			t.Fatalf("violation count mismatch: got %d, want %d\nedges=%+v\nrules=%+v",
				len(got), len(want), edges, rules)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("violation[%d] mismatch:\n got=%+v\nwant=%+v", i, got[i], want[i])
			}
		}
	})
}
