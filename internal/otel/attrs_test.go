package otel

import "testing"

// TestAttrsIntvalRejectsFractionalDouble is the Regression: a
// fractional double attribute (e.g. exit_code:1.7) must NOT be truncated into a
// fabricated integer. An integral double (2.0) and a real int still resolve, and
// a fractional integer string is rejected by the existing ParseInt path.
func TestAttrsIntvalRejectsFractionalDouble(t *testing.T) {
	tests := []struct {
		name   string
		value  anyValue
		want   int64
		wantOK bool
	}{
		{"fractional double is absent", anyValue{kind: valueDouble, doubleValue: 1.7}, 0, false},
		{"integral double resolves", anyValue{kind: valueDouble, doubleValue: 2.0}, 2, true},
		{"real int resolves", anyValue{kind: valueInt, intValue: 7}, 7, true},
		{"clean exit zero resolves", anyValue{kind: valueInt, intValue: 0}, 0, true},
		{"integer string resolves", anyValue{kind: valueString, stringValue: "5"}, 5, true},
		{"fractional string is absent", anyValue{kind: valueString, stringValue: "1.7"}, 0, false},
		// Regression: a double of exactly 2^63 (one past math.MaxInt64) must be
		// absent, not wrapped to math.MinInt64. The guard's upper bound must be a
		// strict < against float64(1<<63), since float64(math.MaxInt64) rounds up
		// to 2^63 and would otherwise let this through.
		{"2^63 double is absent (not wrapped)", anyValue{kind: valueDouble, doubleValue: float64(1 << 63)}, 0, false},
		{"max int64 as double is absent (not faithfully representable)", anyValue{kind: valueDouble, doubleValue: 9223372036854775807.0}, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := attrs{m: map[string]anyValue{"exit_code": tt.value}}
			got, ok := a.intval("exit_code")
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("intval = (%d, %v), want (%d, %v)", got, ok, tt.want, tt.wantOK)
			}
		})
	}
}
