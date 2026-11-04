package decoder

import "testing"

// BenchmarkDecode uses the explicit 48-byte unit-test fixture. This is NOT
// kernel telemetry, event-loss measurement, or agent overhead measurement.
func BenchmarkDecode(b *testing.B) {
	data := validWire()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := Decode(data); err != nil {
			b.Fatal(err)
		}
	}
}
