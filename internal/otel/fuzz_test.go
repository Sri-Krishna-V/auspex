package otel

import "testing"

func FuzzOTLPLogs(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		{0x0a, 0x00},
		{0x0a, 0x04, 0x12, 0x02, 0x12, 0x00},
		{0xff, 0xff, 0xff},
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _ = MapRecords(body, func(int) string { return "fuzz-event" })
	})
}
