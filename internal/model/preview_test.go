package model

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestNormalizeContentPreview(t *testing.T) {
	exact := strings.Repeat("x", ContentPreviewMaxRunes)
	tests := map[string]struct {
		input string
		want  string
	}{
		"short normalized":   {"first\n  second", "first second"},
		"exact token":        {exact + " trailing", exact},
		"partial token":      {"prefix " + strings.Repeat("x", ContentPreviewMaxRunes), "prefix"},
		"only long token":    {strings.Repeat("x", ContentPreviewMaxRunes+1), ""},
		"multibyte boundary": {strings.Repeat("世 ", ContentPreviewMaxRunes), strings.TrimSpace(strings.Repeat("世 ", 100))},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := NormalizeContentPreview(tc.input)
			if got != tc.want {
				t.Fatalf("preview = %q, want %q", got, tc.want)
			}
			if !utf8.ValidString(got) || len([]rune(got)) > ContentPreviewMaxRunes {
				t.Fatalf("preview is invalid or over limit: %q", got)
			}
		})
	}
}
