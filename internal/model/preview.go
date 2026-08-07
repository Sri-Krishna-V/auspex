package model

import "strings"

// ContentPreviewMaxRunes bounds normalized content excerpts.
const ContentPreviewMaxRunes = 200

// NormalizeContentPreview collapses whitespace and keeps only complete tokens
// within the limit. Cutting a token could fabricate a domain, hash, or address
// when indicators are mined from the preview.
func NormalizeContentPreview(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	runes := []rune(s)
	if len(runes) <= ContentPreviewMaxRunes {
		return s
	}
	if runes[ContentPreviewMaxRunes] == ' ' {
		return string(runes[:ContentPreviewMaxRunes])
	}
	for i := ContentPreviewMaxRunes - 1; i >= 0; i-- {
		if runes[i] == ' ' {
			return string(runes[:i])
		}
	}
	return ""
}
