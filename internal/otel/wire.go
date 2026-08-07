package otel

// This file decodes the small OTLP/HTTP logs protobuf subset auspex needs using
// protowire, avoiding the collector package's gRPC dependency graph. Unknown
// fields are skipped so newer exporters remain compatible.

import (
	"fmt"
	"math"

	"google.golang.org/protobuf/encoding/protowire"
)

// logsData is the decoded ExportLogsServiceRequest: a batch of resource-scoped
// log records. auspex flattens it to (resource attrs + record) pairs in Map.
type logsData struct {
	resourceLogs []resourceLogs
}

// resourceLogs groups records sharing one Resource (one emitting process). The
// resource attributes carry service.name/process.command and other
// process-level semconv keys auspex keys off.
type resourceLogs struct {
	resource  resource
	scopeLogs []scopeLogs
}

type resource struct {
	attributes []keyValue
}

// scopeLogs groups records from one instrumentation scope. auspex does not key
// off the scope itself but must walk it to reach the records.
type scopeLogs struct {
	logRecords []logRecord
}

// logRecord is one OTLP log record. auspex reads the timestamp, the body (when
// it is a string), and the per-record attributes, which carry the gen_ai.* /
// session.id / tool.* semconv keys the mapper classifies on.
type logRecord struct {
	timeUnixNano         uint64
	observedTimeUnixNano uint64
	severityNumber       uint64
	severityText         string
	eventName            string
	body                 anyValue
	attributes           []keyValue
}

// keyValue is an OTLP attribute: a string key and a typed value.
type keyValue struct {
	key   string
	value anyValue
}

// anyValue is the decoded OTLP AnyValue. Structured values are retained so
// current GenAI message and tool-argument attributes can be normalized.
type anyValue struct {
	stringValue string
	boolValue   bool
	intValue    int64
	doubleValue float64
	arrayValue  []anyValue
	kvlistValue []keyValue
	bytesValue  []byte
	// kind records which scalar variant was set, so an absent value stays
	// distinct from a real empty string / zero / false.
	kind valueKind
}

type valueKind uint8

const (
	valueNone valueKind = iota
	valueString
	valueBool
	valueInt
	valueDouble
	valueArray
	valueKVList
	valueBytes
)

// Decode bounds cap the work one request can demand, so a small body that
// declares pathologically many tiny sub-messages cannot amplify into unbounded
// allocation. They are generous next to any real export batch (a normal batch is
// a few hundred records with a handful of attributes each) but finite: a body
// that exceeds one is rejected as malformed rather than decoded. maxOTLPBody in
// cmd/auspex bounds the raw bytes; these bound the decoded element counts.
const (
	// maxResourceLogs and maxScopeLogs bound empty grouping messages, which do
	// not count toward maxRecords but still allocate slices and structs.
	maxResourceLogs = 1_000
	maxScopeLogs    = 10_000
	// maxRecords caps the total LogRecords decoded from one request, summed across
	// every ResourceLogs/ScopeLogs group.
	maxRecords = 10_000
	// maxAttrsPerCollection caps the attributes decoded for any single Resource or
	// LogRecord, so one element cannot carry an unbounded attribute list.
	maxAttrsPerCollection = 1_000
	maxAnyValues          = 100_000
	maxAnyValueDepth      = 16
)

// errTooManyRecords and errTooManyAttrs report a decode that exceeded the bounds
// above; the receiver maps either to a 400, the same as any malformed batch.
var (
	errTooManyResourceLogs = fmt.Errorf("otlp: too many resource_logs groups (limit %d)", maxResourceLogs)
	errTooManyScopeLogs    = fmt.Errorf("otlp: too many scope_logs groups (limit %d)", maxScopeLogs)
	errTooManyRecords      = fmt.Errorf("otlp: too many log records (limit %d)", maxRecords)
	errTooManyAttrs        = fmt.Errorf("otlp: too many attributes (limit %d)", maxAttrsPerCollection)
	errTooManyAnyValues    = fmt.Errorf("otlp: too many nested values (limit %d)", maxAnyValues)
	errAnyValueTooDeep     = fmt.Errorf("otlp: nested value depth exceeds %d", maxAnyValueDepth)
)

type decodeCounts struct {
	resourceLogs int
	scopeLogs    int
	records      int
	anyValues    int
}

// OTLP field numbers (proto3) for the messages auspex decodes.
const (
	fieldExportResourceLogs = 1 // ExportLogsServiceRequest.resource_logs

	fieldResourceLogsResource  = 1 // ResourceLogs.resource
	fieldResourceLogsScopeLogs = 2 // ResourceLogs.scope_logs

	fieldResourceAttributes = 1 // Resource.attributes

	fieldScopeLogsLogRecords = 2 // ScopeLogs.log_records

	fieldLogRecordTimeUnixNano         = 1  // LogRecord.time_unix_nano (fixed64)
	fieldLogRecordSeverityNumber       = 2  // LogRecord.severity_number
	fieldLogRecordSeverityText         = 3  // LogRecord.severity_text
	fieldLogRecordBody                 = 5  // LogRecord.body (AnyValue)
	fieldLogRecordAttributes           = 6  // LogRecord.attributes (repeated KeyValue)
	fieldLogRecordObservedTimeUnixNano = 11 // LogRecord.observed_time_unix_nano
	fieldLogRecordEventName            = 12 // LogRecord.event_name

	fieldKeyValueKey   = 1 // KeyValue.key
	fieldKeyValueValue = 2 // KeyValue.value (AnyValue)

	fieldAnyValueString = 1 // AnyValue.string_value
	fieldAnyValueBool   = 2 // AnyValue.bool_value
	fieldAnyValueInt    = 3 // AnyValue.int_value
	fieldAnyValueDouble = 4 // AnyValue.double_value
	fieldAnyValueArray  = 5 // AnyValue.array_value
	fieldAnyValueKVList = 6 // AnyValue.kvlist_value
	fieldAnyValueBytes  = 7 // AnyValue.bytes_value

	fieldArrayValueValues  = 1 // ArrayValue.values
	fieldKVListValueValues = 1 // KeyValueList.values
)

// decodeLogsRequest decodes a serialized OTLP ExportLogsServiceRequest. It
// returns an error on a truncated or malformed message so the receiver can
// answer 400 rather than silently dropping a partial batch. Unknown fields are
// skipped, so a newer exporter that sets fields auspex ignores still decodes.
func decodeLogsRequest(b []byte) (logsData, error) {
	var out logsData
	var counts decodeCounts
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return logsData{}, fmt.Errorf("otlp: bad tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		if num == fieldExportResourceLogs && typ == protowire.BytesType {
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return logsData{}, fmt.Errorf("otlp: bad resource_logs: %w", protowire.ParseError(n))
			}
			b = b[n:]
			if counts.resourceLogs >= maxResourceLogs {
				return logsData{}, errTooManyResourceLogs
			}
			counts.resourceLogs++
			rl, err := decodeResourceLogs(msg, &counts)
			if err != nil {
				return logsData{}, err
			}
			out.resourceLogs = append(out.resourceLogs, rl)
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return logsData{}, fmt.Errorf("otlp: bad field %d: %w", num, protowire.ParseError(n))
		}
		b = b[n:]
	}
	return out, nil
}

func decodeResourceLogs(b []byte, counts *decodeCounts) (resourceLogs, error) {
	var out resourceLogs
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return resourceLogs{}, fmt.Errorf("otlp: bad resource_logs tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		switch {
		case num == fieldResourceLogsResource && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return resourceLogs{}, fmt.Errorf("otlp: bad resource: %w", protowire.ParseError(n))
			}
			b = b[n:]
			res, err := decodeResource(msg, counts)
			if err != nil {
				return resourceLogs{}, err
			}
			out.resource = res
		case num == fieldResourceLogsScopeLogs && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return resourceLogs{}, fmt.Errorf("otlp: bad scope_logs: %w", protowire.ParseError(n))
			}
			b = b[n:]
			if counts.scopeLogs >= maxScopeLogs {
				return resourceLogs{}, errTooManyScopeLogs
			}
			counts.scopeLogs++
			sl, err := decodeScopeLogs(msg, counts)
			if err != nil {
				return resourceLogs{}, err
			}
			out.scopeLogs = append(out.scopeLogs, sl)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return resourceLogs{}, fmt.Errorf("otlp: bad resource_logs field %d: %w", num, protowire.ParseError(n))
			}
			b = b[n:]
		}
	}
	return out, nil
}

func decodeResource(b []byte, counts *decodeCounts) (resource, error) {
	var out resource
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return resource{}, fmt.Errorf("otlp: bad resource tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		if num == fieldResourceAttributes && typ == protowire.BytesType {
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return resource{}, fmt.Errorf("otlp: bad resource attr: %w", protowire.ParseError(n))
			}
			b = b[n:]
			if len(out.attributes) >= maxAttrsPerCollection {
				return resource{}, errTooManyAttrs
			}
			kv, err := decodeKeyValue(msg, counts, 0)
			if err != nil {
				return resource{}, err
			}
			out.attributes = append(out.attributes, kv)
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return resource{}, fmt.Errorf("otlp: bad resource field %d: %w", num, protowire.ParseError(n))
		}
		b = b[n:]
	}
	return out, nil
}

func decodeScopeLogs(b []byte, counts *decodeCounts) (scopeLogs, error) {
	var out scopeLogs
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return scopeLogs{}, fmt.Errorf("otlp: bad scope_logs tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		if num == fieldScopeLogsLogRecords && typ == protowire.BytesType {
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return scopeLogs{}, fmt.Errorf("otlp: bad log_record: %w", protowire.ParseError(n))
			}
			b = b[n:]
			if counts.records >= maxRecords {
				return scopeLogs{}, errTooManyRecords
			}
			counts.records++
			lr, err := decodeLogRecord(msg, counts)
			if err != nil {
				return scopeLogs{}, err
			}
			out.logRecords = append(out.logRecords, lr)
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return scopeLogs{}, fmt.Errorf("otlp: bad scope_logs field %d: %w", num, protowire.ParseError(n))
		}
		b = b[n:]
	}
	return out, nil
}

func decodeLogRecord(b []byte, counts *decodeCounts) (logRecord, error) {
	var out logRecord
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return logRecord{}, fmt.Errorf("otlp: bad log_record tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		switch {
		case num == fieldLogRecordTimeUnixNano && typ == protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(b)
			if n < 0 {
				return logRecord{}, fmt.Errorf("otlp: bad time_unix_nano: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.timeUnixNano = v
		case num == fieldLogRecordObservedTimeUnixNano && typ == protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(b)
			if n < 0 {
				return logRecord{}, fmt.Errorf("otlp: bad observed_time_unix_nano: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.observedTimeUnixNano = v
		case num == fieldLogRecordSeverityNumber && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return logRecord{}, fmt.Errorf("otlp: bad severity_number: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.severityNumber = v
		case num == fieldLogRecordSeverityText && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(b)
			if n < 0 {
				return logRecord{}, fmt.Errorf("otlp: bad severity_text: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.severityText = v
		case num == fieldLogRecordEventName && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(b)
			if n < 0 {
				return logRecord{}, fmt.Errorf("otlp: bad event_name: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.eventName = v
		case num == fieldLogRecordBody && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return logRecord{}, fmt.Errorf("otlp: bad body: %w", protowire.ParseError(n))
			}
			b = b[n:]
			av, err := decodeAnyValue(msg, counts, 0)
			if err != nil {
				return logRecord{}, err
			}
			out.body = av
		case num == fieldLogRecordAttributes && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return logRecord{}, fmt.Errorf("otlp: bad log_record attr: %w", protowire.ParseError(n))
			}
			b = b[n:]
			if len(out.attributes) >= maxAttrsPerCollection {
				return logRecord{}, errTooManyAttrs
			}
			kv, err := decodeKeyValue(msg, counts, 0)
			if err != nil {
				return logRecord{}, err
			}
			out.attributes = append(out.attributes, kv)
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return logRecord{}, fmt.Errorf("otlp: bad log_record field %d: %w", num, protowire.ParseError(n))
			}
			b = b[n:]
		}
	}
	return out, nil
}

func decodeKeyValue(b []byte, counts *decodeCounts, valueDepth int) (keyValue, error) {
	var out keyValue
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return keyValue{}, fmt.Errorf("otlp: bad key_value tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		switch {
		case num == fieldKeyValueKey && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(b)
			if n < 0 {
				return keyValue{}, fmt.Errorf("otlp: bad key: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.key = v
		case num == fieldKeyValueValue && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return keyValue{}, fmt.Errorf("otlp: bad value: %w", protowire.ParseError(n))
			}
			b = b[n:]
			av, err := decodeAnyValue(msg, counts, valueDepth)
			if err != nil {
				return keyValue{}, err
			}
			out.value = av
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return keyValue{}, fmt.Errorf("otlp: bad key_value field %d: %w", num, protowire.ParseError(n))
			}
			b = b[n:]
		}
	}
	return out, nil
}

func decodeAnyValue(b []byte, counts *decodeCounts, depth int) (anyValue, error) {
	if depth > maxAnyValueDepth {
		return anyValue{}, errAnyValueTooDeep
	}
	if counts.anyValues >= maxAnyValues {
		return anyValue{}, errTooManyAnyValues
	}
	counts.anyValues++
	var out anyValue
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return anyValue{}, fmt.Errorf("otlp: bad any_value tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		switch {
		case num == fieldAnyValueString && typ == protowire.BytesType:
			v, n := protowire.ConsumeString(b)
			if n < 0 {
				return anyValue{}, fmt.Errorf("otlp: bad string_value: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.stringValue, out.kind = v, valueString
		case num == fieldAnyValueBool && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return anyValue{}, fmt.Errorf("otlp: bad bool_value: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.boolValue, out.kind = v != 0, valueBool
		case num == fieldAnyValueInt && typ == protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				return anyValue{}, fmt.Errorf("otlp: bad int_value: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.intValue, out.kind = int64(v), valueInt
		case num == fieldAnyValueDouble && typ == protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(b)
			if n < 0 {
				return anyValue{}, fmt.Errorf("otlp: bad double_value: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.doubleValue, out.kind = math.Float64frombits(v), valueDouble
		case num == fieldAnyValueArray && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return anyValue{}, fmt.Errorf("otlp: bad array_value: %w", protowire.ParseError(n))
			}
			b = b[n:]
			values, err := decodeArrayValue(msg, counts, depth+1)
			if err != nil {
				return anyValue{}, err
			}
			out.arrayValue, out.kind = values, valueArray
		case num == fieldAnyValueKVList && typ == protowire.BytesType:
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return anyValue{}, fmt.Errorf("otlp: bad kvlist_value: %w", protowire.ParseError(n))
			}
			b = b[n:]
			values, err := decodeKVListValue(msg, counts, depth+1)
			if err != nil {
				return anyValue{}, err
			}
			out.kvlistValue, out.kind = values, valueKVList
		case num == fieldAnyValueBytes && typ == protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return anyValue{}, fmt.Errorf("otlp: bad bytes_value: %w", protowire.ParseError(n))
			}
			b = b[n:]
			out.bytesValue, out.kind = v, valueBytes
		default:
			n = protowire.ConsumeFieldValue(num, typ, b)
			if n < 0 {
				return anyValue{}, fmt.Errorf("otlp: bad any_value field %d: %w", num, protowire.ParseError(n))
			}
			b = b[n:]
		}
	}
	return out, nil
}

func decodeArrayValue(b []byte, counts *decodeCounts, depth int) ([]anyValue, error) {
	var out []anyValue
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, fmt.Errorf("otlp: bad array_value tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		if num == fieldArrayValueValues && typ == protowire.BytesType {
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return nil, fmt.Errorf("otlp: bad array value: %w", protowire.ParseError(n))
			}
			b = b[n:]
			value, err := decodeAnyValue(msg, counts, depth)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return nil, fmt.Errorf("otlp: bad array_value field %d: %w", num, protowire.ParseError(n))
		}
		b = b[n:]
	}
	return out, nil
}

func decodeKVListValue(b []byte, counts *decodeCounts, depth int) ([]keyValue, error) {
	var out []keyValue
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return nil, fmt.Errorf("otlp: bad kvlist_value tag: %w", protowire.ParseError(n))
		}
		b = b[n:]
		if num == fieldKVListValueValues && typ == protowire.BytesType {
			msg, n := protowire.ConsumeBytes(b)
			if n < 0 {
				return nil, fmt.Errorf("otlp: bad kvlist value: %w", protowire.ParseError(n))
			}
			b = b[n:]
			value, err := decodeKeyValue(msg, counts, depth)
			if err != nil {
				return nil, err
			}
			out = append(out, value)
			continue
		}
		n = protowire.ConsumeFieldValue(num, typ, b)
		if n < 0 {
			return nil, fmt.Errorf("otlp: bad kvlist_value field %d: %w", num, protowire.ParseError(n))
		}
		b = b[n:]
	}
	return out, nil
}
