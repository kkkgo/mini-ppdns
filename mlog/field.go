package mlog

import (
	"fmt"
	"math"
	"reflect"
	"strconv"
	"time"
)

// fieldType identifies the type of data stored in a Field.
type fieldType uint8

const (
	fieldString  fieldType = iota
	fieldInt64             // covers int, int8, int16, int32, int64
	fieldUint64            // covers uint, uint8, uint16, uint32, uint64
	fieldFloat64           // covers float32, float64
	fieldBool
	fieldDuration
	fieldError
	fieldStringer // fmt.Stringer — .String() is deferred until encoding
)

// Field is a strongly-typed, stack-allocated log field.
// Its zero value is a valid (empty) field.
//
// Unlike fmt.Sprintf-based logging, Fields avoid:
//   - interface{} boxing of basic types (no heap escape)
//   - fmt reflection and format-string parsing
//   - eager evaluation: Stringer.String() is deferred until the log level check passes
//
// Field is designed as a small value type (~56 bytes) that stays on the stack
// when passed through ...Field variadic arguments.
type Field struct {
	Key  string
	Type fieldType
	Int  int64
	Str  string
	Any  any // only used for fieldError and fieldStringer
}

// --- Constructors: each returns a stack-allocated Field value ---

// String creates a string field.
func String(key, val string) Field {
	return Field{Key: key, Type: fieldString, Str: val}
}

// Int creates an int field.
func Int(key string, val int) Field {
	return Field{Key: key, Type: fieldInt64, Int: int64(val)}
}

// Int64 creates an int64 field.
func Int64(key string, val int64) Field {
	return Field{Key: key, Type: fieldInt64, Int: val}
}

// Uint16 creates a uint16 field.
func Uint16(key string, val uint16) Field {
	return Field{Key: key, Type: fieldUint64, Int: int64(val)}
}

// Uint64 creates a uint64 field.
func Uint64(key string, val uint64) Field {
	return Field{Key: key, Type: fieldUint64, Int: int64(val)}
}

// Float64 creates a float64 field. The bit pattern is stashed in Int so that
// the fractional part survives until encoding.
func Float64(key string, val float64) Field {
	return Field{Key: key, Type: fieldFloat64, Int: int64(math.Float64bits(val))}
}

// Bool creates a boolean field.
func Bool(key string, val bool) Field {
	v := int64(0)
	if val {
		v = 1
	}
	return Field{Key: key, Type: fieldBool, Int: v}
}

// Duration creates a duration field, rendered as human-readable (e.g. "12ms", "1.5s").
func Duration(key string, val time.Duration) Field {
	return Field{Key: key, Type: fieldDuration, Int: int64(val)}
}

// Err creates an "error" field. If err is nil, the field is a no-op.
func Err(err error) Field {
	if err == nil {
		return Field{}
	}
	return Field{Key: "err", Type: fieldError, Any: err}
}

// Stringer creates a field from a fmt.Stringer. The .String() call is
// deferred until the field is actually encoded, avoiding allocation
// when the log level filters the message.
func Stringer(key string, val fmt.Stringer) Field {
	return Field{Key: key, Type: fieldStringer, Any: val}
}

// Byte creates a uint8 field.
func Byte(key string, val byte) Field {
	return Field{Key: key, Type: fieldUint64, Int: int64(val)}
}

// --- Encoder: appends " key=value" directly to []byte, zero allocation ---

// appendField appends " key=value" to buf without any heap allocation
// for the common types (string, int, uint, bool, duration).
func appendField(buf []byte, f Field) []byte {
	if f.Key == "" {
		return buf // skip empty/nil fields (e.g. Err(nil))
	}
	buf = append(buf, ' ')
	buf = append(buf, f.Key...)
	buf = append(buf, '=')

	switch f.Type {
	case fieldString:
		buf = append(buf, f.Str...)
	case fieldInt64:
		buf = strconv.AppendInt(buf, f.Int, 10)
	case fieldUint64:
		buf = strconv.AppendUint(buf, uint64(f.Int), 10)
	case fieldFloat64:
		buf = strconv.AppendFloat(buf, math.Float64frombits(uint64(f.Int)), 'f', -1, 64)
	case fieldBool:
		if f.Int != 0 {
			buf = append(buf, "true"...)
		} else {
			buf = append(buf, "false"...)
		}
	case fieldDuration:
		buf = appendDuration(buf, time.Duration(f.Int))
	case fieldError:
		if e, ok := f.Any.(error); ok {
			buf = append(buf, e.Error()...)
		}
	case fieldStringer:
		if s, ok := f.Any.(fmt.Stringer); ok {
			// Guard against typed-nil pointers: the interface is non-nil but
			// the underlying pointer is nil, so .String() would panic.
			if v := reflect.ValueOf(s); v.Kind() == reflect.Ptr && v.IsNil() {
				buf = append(buf, "<nil>"...)
			} else {
				buf = append(buf, s.String()...)
			}
		}
	}
	return buf
}

// appendDuration appends a human-readable duration to buf.
// Uses integer arithmetic to avoid fmt.Sprintf.
func appendDuration(buf []byte, d time.Duration) []byte {
	if d < 0 {
		buf = append(buf, '-')
		d = -d
	}
	switch {
	case d < time.Microsecond:
		buf = strconv.AppendInt(buf, int64(d), 10)
		buf = append(buf, "ns"...)
	case d < time.Millisecond:
		us := d.Microseconds()
		buf = strconv.AppendInt(buf, us, 10)
		buf = append(buf, "µs"...)
	case d < time.Second:
		ms := d.Milliseconds()
		buf = strconv.AppendInt(buf, ms, 10)
		buf = append(buf, "ms"...)
	case d < time.Minute:
		// Show as "1.234s"
		sec := d / time.Second
		frac := (d % time.Second) / time.Millisecond
		buf = strconv.AppendInt(buf, int64(sec), 10)
		if frac > 0 {
			buf = append(buf, '.')
			buf = strconv.AppendInt(buf, int64(frac), 10)
		}
		buf = append(buf, 's')
	default:
		// Show as "1m30s" or "1h2m"
		buf = append(buf, d.String()...)
	}
	return buf
}
