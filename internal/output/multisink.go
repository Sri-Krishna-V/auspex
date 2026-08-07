package output

import (
	"errors"
	"io"
)

// MultiSink writes each NDJSON record to multiple sinks. It is intentionally
// synchronous: either every configured sink sees the same ordered stream, or
// the caller gets a delivery error for that record.
type MultiSink struct {
	sinks []Sink
}

// NewMultiSink returns a sink that fans out writes to every supplied sink. A
// single sink is returned unchanged so callers do not pay an extra wrapper in
// the common case.
func NewMultiSink(sinks ...Sink) Sink {
	if len(sinks) == 1 {
		return sinks[0]
	}
	cp := append([]Sink(nil), sinks...)
	return &MultiSink{sinks: cp}
}

// Write writes p to every child sink. It attempts all sinks even after one
// fails, so an HTTP outage does not prevent a local file sink from receiving the
// record, and a file error does not hide an HTTP delivery attempt.
func (m *MultiSink) Write(p []byte) (int, error) {
	var errs []error
	for _, s := range m.sinks {
		n, err := s.Write(p)
		if err != nil {
			errs = append(errs, err)
		}
		if n != len(p) {
			errs = append(errs, io.ErrShortWrite)
		}
	}
	if len(errs) > 0 {
		return len(p), errors.Join(errs...)
	}
	return len(p), nil
}

// Close closes every child sink, returning all close errors joined.
func (m *MultiSink) Close() error {
	var errs []error
	for _, s := range m.sinks {
		if err := s.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Stats reports aggregate transport counters from child sinks that expose
// StatsReporter. Today that means the HTTP sink; file/stdout children do not
// alter the counters.
func (m *MultiSink) Stats() SinkStats {
	var out SinkStats
	for _, s := range m.sinks {
		r, ok := s.(StatsReporter)
		if !ok {
			continue
		}
		st := r.Stats()
		out.HTTPTransport = out.HTTPTransport || st.HTTPTransport
		out.PendingFailure = out.PendingFailure || st.PendingFailure
		out.BatchesAttempted += st.BatchesAttempted
		out.BatchesSucceeded += st.BatchesSucceeded
		out.BatchesFailed += st.BatchesFailed
		out.RecordsSent += st.RecordsSent
		out.RecordsDropped += st.RecordsDropped
		out.BytesDropped += st.BytesDropped
		if st.HTTPTransport {
			out.LastStatus = st.LastStatus
		}
	}
	return out
}
