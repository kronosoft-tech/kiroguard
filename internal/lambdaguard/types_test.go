package lambdaguard

import "testing"

func TestMetricsValues(t *testing.T) {
	m := &Metrics{}
	m.AnalyzesTotal.Add(3)
	m.FunctionsTotal.Add(10)
	m.FindingsTotal.Add(25)
	m.CriticalFindings.Add(2)

	snap := MetricsSnapshot{
		AnalyzesTotal:    m.AnalyzesTotal.Load(),
		FunctionsTotal:   m.FunctionsTotal.Load(),
		FindingsTotal:    m.FindingsTotal.Load(),
		CriticalFindings: m.CriticalFindings.Load(),
	}

	if snap.AnalyzesTotal != 3 {
		t.Errorf("AnalyzesTotal = %d, want 3", snap.AnalyzesTotal)
	}
	if snap.FunctionsTotal != 10 {
		t.Errorf("FunctionsTotal = %d, want 10", snap.FunctionsTotal)
	}
	if snap.FindingsTotal != 25 {
		t.Errorf("FindingsTotal = %d, want 25", snap.FindingsTotal)
	}
	if snap.CriticalFindings != 2 {
		t.Errorf("CriticalFindings = %d, want 2", snap.CriticalFindings)
	}
}
