package otel

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// attrs is a flattened view of one log record's effective attributes: the
// emitting Resource's attributes (process/service-level: service.name,
// process.command, ...) merged with the LogRecord's own attributes
// (event-level: gen_ai.*, tool.*, ...). Record-level attributes win on a key
// clash, since they describe the specific event rather than the process.
//
// Lookups tolerate the small spelling differences between exporters the way the
// hook resolver does, and coerce scalar AnyValue variants to the string/number
// shape the mapper needs, so a token count sent as an int and one sent as a
// string both resolve.
type attrs struct {
	m map[string]anyValue
}

// newAttrs flattens resource + record attributes into a single lookup. Resource
// attributes are laid down first so a record-level key of the same name
// overrides them.
func newAttrs(resource []keyValue, record []keyValue) attrs {
	m := make(map[string]anyValue, len(resource)+len(record))
	for _, kv := range resource {
		m[kv.key] = kv.value
	}
	for _, kv := range record {
		m[kv.key] = kv.value
	}
	return attrs{m: m}
}

// str returns the first attribute among keys that resolves to a non-empty
// string, coercing bool/int/double scalars to their textual form so a value
// sent under an unexpected type is not silently dropped.
func (a attrs) str(keys ...string) string {
	for _, k := range keys {
		v, ok := a.m[k]
		if !ok {
			continue
		}
		switch v.kind {
		case valueString:
			if v.stringValue != "" {
				return v.stringValue
			}
		case valueBool:
			return strconv.FormatBool(v.boolValue)
		case valueInt:
			return strconv.FormatInt(v.intValue, 10)
		case valueDouble:
			return strconv.FormatFloat(v.doubleValue, 'f', -1, 64)
		case valueArray, valueKVList, valueBytes:
			if text := v.structuredText(); text != "" {
				return text
			}
		}
	}
	return ""
}

func (v anyValue) structuredText() string {
	value := v.nativeValue()
	if value == nil {
		return ""
	}
	b, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	return string(b)
}

func (v anyValue) nativeValue() any {
	switch v.kind {
	case valueString:
		return v.stringValue
	case valueBool:
		return v.boolValue
	case valueInt:
		return v.intValue
	case valueDouble:
		return v.doubleValue
	case valueArray:
		out := make([]any, len(v.arrayValue))
		for i := range v.arrayValue {
			out[i] = v.arrayValue[i].nativeValue()
		}
		return out
	case valueKVList:
		out := make(map[string]any, len(v.kvlistValue))
		for _, kv := range v.kvlistValue {
			out[kv.key] = kv.value.nativeValue()
		}
		return out
	case valueBytes:
		return v.bytesValue
	default:
		return nil
	}
}

// has reports whether any of keys is present at all, regardless of value, so a
// record can be classified on the mere presence of a semconv attribute.
func (a attrs) has(keys ...string) bool {
	for _, k := range keys {
		if _, ok := a.m[k]; ok {
			return true
		}
	}
	return false
}

// maxInt64AsFloat is float64(1<<63) == 2^63, exactly representable and one past
// math.MaxInt64. A float64 integer is in int64 range iff strictly less than it.
const maxInt64AsFloat = float64(1 << 63)

// intval returns the first attribute among keys as an int64, accepting an int,
// an integral double (rejecting any fractional value rather than truncating it
// into fabricated evidence), or an integer string. ok is false when none is
// present or parseable, so a real 0 stays distinct from absent.
func (a attrs) intval(keys ...string) (int64, bool) {
	for _, k := range keys {
		v, ok := a.m[k]
		if !ok {
			continue
		}
		switch v.kind {
		case valueInt:
			return v.intValue, true
		case valueDouble:
			// Accept only an integral double strictly inside the int64 range. The
			// upper bound is a STRICT < against 2^63 (float64(1<<63), exactly
			// representable): comparing against float64(math.MaxInt64) is wrong
			// because that constant rounds UP to 2^63, so a double of exactly 2^63
			// would pass and int64(d) would wrap to math.MinInt64 — a fabricated
			// negative. Anything fractional or out of range is treated as absent.
			d := v.doubleValue
			if d == math.Trunc(d) && !math.IsInf(d, 0) && d >= -maxInt64AsFloat && d < maxInt64AsFloat {
				return int64(d), true
			}
		case valueString:
			if n, err := strconv.ParseInt(strings.TrimSpace(v.stringValue), 10, 64); err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

// boolval returns the first attribute among keys as a bool, accepting a bool or
// a "true"/"false" string. ok is false when none is present or parseable.
func (a attrs) boolval(keys ...string) (bool, bool) {
	for _, k := range keys {
		v, ok := a.m[k]
		if !ok {
			continue
		}
		switch v.kind {
		case valueBool:
			return v.boolValue, true
		case valueString:
			if b, err := strconv.ParseBool(strings.TrimSpace(v.stringValue)); err == nil {
				return b, true
			}
		}
	}
	return false, false
}
