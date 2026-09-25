package audit

import (
	_ "embed"
	"strings"
)

//go:embed popular_packages.txt
var popularPackagesText string

var popularPackages = parsePopular(popularPackagesText)

func parsePopular(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// NamesquatWarning reports when name is confusable with a popular package.
// Mirrors cli/src/core/risk.rs; both read popular_packages.txt.
func NamesquatWarning(name string) string {
	if name == "" {
		return ""
	}
	for _, popular := range popularPackages {
		if name == popular {
			return ""
		}
	}
	normalized := normalizeName(name)
	for _, popular := range popularPackages {
		target := normalizeName(popular)
		if normalized == target {
			return "possible namesquat: confusable with " + popular
		}
		threshold := 0
		switch n := len([]rune(target)); {
		case n >= 8:
			threshold = 2
		case n >= 5:
			threshold = 1
		}
		if threshold > 0 && editDistance(normalized, target) <= threshold {
			return "possible namesquat: confusable with " + popular
		}
	}
	return ""
}

func normalizeName(name string) string {
	var b strings.Builder
	for _, ch := range strings.ToLower(name) {
		switch ch {
		case '-', '_', '.':
			continue
		case '0':
			b.WriteRune('o')
		case '1', 'l', 'í', 'ì', 'ï', 'î':
			b.WriteRune('i')
		case 'á', 'à', 'ä', 'â':
			b.WriteRune('a')
		case 'é', 'è', 'ë', 'ê':
			b.WriteRune('e')
		case 'ó', 'ò', 'ö', 'ô':
			b.WriteRune('o')
		case 'ú', 'ù', 'ü', 'û':
			b.WriteRune('u')
		default:
			if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '@' || ch == '/' {
				b.WriteRune(ch)
			}
		}
	}
	return b.String()
}

// editDistance is the optimal-string-alignment distance: Levenshtein plus
// adjacent transpositions, the most common typosquat edit.
func editDistance(a, b string) int {
	left, right := []rune(a), []rune(b)
	rows := make([][]int, len(left)+1)
	for i := range rows {
		rows[i] = make([]int, len(right)+1)
		rows[i][0] = i
	}
	for j := range rows[0] {
		rows[0][j] = j
	}
	for i := 1; i <= len(left); i++ {
		for j := 1; j <= len(right); j++ {
			cost := 1
			if left[i-1] == right[j-1] {
				cost = 0
			}
			rows[i][j] = min(rows[i-1][j]+1, rows[i][j-1]+1, rows[i-1][j-1]+cost)
			if i > 1 && j > 1 && left[i-1] == right[j-2] && left[i-2] == right[j-1] {
				rows[i][j] = min(rows[i][j], rows[i-2][j-2]+1)
			}
		}
	}
	return rows[len(left)][len(right)]
}
