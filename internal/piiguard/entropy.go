package piiguard

import "math"

func ShannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}

	freq := make(map[rune]int)
	runes := 0
	for _, r := range s {
		freq[r]++
		runes++
	}

	if runes == 0 {
		return 0
	}

	var entropy float64
	for _, count := range freq {
		p := float64(count) / float64(runes)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func IsHighEntropy(s string, threshold float64) bool {
	return ShannonEntropy(s) >= threshold
}

func extractStringLiterals(content []byte) []string {
	var literals []string
	in := false
	var quote rune
	var start int
	runes := []rune(string(content))

	for i := 0; i < len(runes); i++ {
		ch := runes[i]

		if ch == '\\' && in {
			i++
			continue
		}

		if !in {
			if ch == '"' || ch == '\'' || ch == '`' {
				in = true
				quote = ch
				start = i + 1
			}
		} else if ch == quote {
			in = false
			if start <= i {
				literals = append(literals, string(runes[start:i]))
			}
		}
	}
	if in && start < len(runes) {
		literals = append(literals, string(runes[start:]))
	}
	return literals
}
