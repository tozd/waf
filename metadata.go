package waf

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"gitlab.com/tozd/go/errors"
)

const metadataHeader = "Metadata"

func encodeMetadataKey(key string, b *bytes.Buffer) errors.E {
	if len(key) == 0 {
		errE := errors.New("unsupported dictionary key")
		errors.Details(errE)["value"] = key
		return errE
	}
	if !('a' <= key[0] && key[0] <= 'z' || key[0] == '*') {
		errE := errors.New("unsupported dictionary key")
		errors.Details(errE)["value"] = key
		return errE
	}
	for _, k := range key {
		if !('a' <= k && k <= 'z' || '0' <= k && k <= '9' || k == '_' || k == '-' || k == '.' || k == '*') {
			errE := errors.New("unsupported dictionary key")
			errors.Details(errE)["value"] = key
			return errE
		}
	}

	b.WriteString(key)
	return nil
}

func encodeMetadataSignedInteger(v int64, b *bytes.Buffer) errors.E {
	if v < -999_999_999_999_999 || v > 999_999_999_999_999 {
		errE := errors.New("integer out of range")
		errors.Details(errE)["value"] = v
		return errE
	}

	out := strconv.AppendInt(b.AvailableBuffer(), v, 10) //nolint:gomnd
	b.Write(out)
	return nil
}

func encodeMetadataUnsignedInteger(v uint64, b *bytes.Buffer) errors.E {
	if v > 999_999_999_999_999 { //nolint:gomnd
		errE := errors.New("integer out of range")
		errors.Details(errE)["value"] = v
		return errE
	}

	out := strconv.AppendUint(b.AvailableBuffer(), v, 10) //nolint:gomnd
	b.Write(out)
	return nil
}

func encodeMetadataFloat(v float64, b *bytes.Buffer) errors.E {
	rounded := math.RoundToEven(v/0.001) * 0.001 //nolint:gomnd
	if rounded < -999_999_999_999 || rounded > 999_999_999_999 {
		errE := errors.New("decimal out of range")
		errors.Details(errE)["value"] = v
		return errE
	}

	s := strings.TrimRight(strconv.FormatFloat(rounded, 'f', 3, 64), "0")
	b.WriteString(s)

	if strings.HasSuffix(s, ".") {
		b.WriteString("0")
	}

	return nil
}

func encodeMetadataItem(value interface{}, b *bytes.Buffer) errors.E {
	switch v := value.(type) {
	case int:
		return encodeMetadataSignedInteger(int64(v), b)
	case int8:
		return encodeMetadataSignedInteger(int64(v), b)
	case int16:
		return encodeMetadataSignedInteger(int64(v), b)
	case int32:
		return encodeMetadataSignedInteger(int64(v), b)
	case int64:
		return encodeMetadataSignedInteger(v, b)
	case uint:
		return encodeMetadataUnsignedInteger(uint64(v), b)
	case uint8:
		return encodeMetadataUnsignedInteger(uint64(v), b)
	case uint16:
		return encodeMetadataUnsignedInteger(uint64(v), b)
	case uint32:
		return encodeMetadataUnsignedInteger(uint64(v), b)
	case uint64:
		return encodeMetadataUnsignedInteger(v, b)
	case float32:
		return encodeMetadataFloat(float64(v), b)
	case float64:
		return encodeMetadataFloat(v, b)
	case bool:
		b.WriteString("?")
		if v {
			b.WriteString("1")
		} else {
			b.WriteString("0")
		}
	case []byte:
		b.WriteString(":")
		b.Grow(base64.StdEncoding.EncodedLen(len(v)))
		base64.StdEncoding.Encode(v, b.AvailableBuffer())
		b.WriteString(":")
	case string:
		b.WriteString(`"`)
		for _, r := range v {
			if r <= 0x1f || r >= 0x7f {
				errE := errors.New("string contains unsupported character")
				errors.Details(errE)["value"] = v
				errors.Details(errE)["char"] = string(r)
				return errE
			}
			if r == '"' || r == '\\' {
				b.WriteString(`\`)
			}
			b.WriteRune(r)
		}
		b.WriteString(`"`)
	case time.Time:
		b.WriteString(`@`)
		return encodeMetadataSignedInteger(v.Unix(), b)
	default:
		errE := errors.New("unsupported data type")
		errors.Details(errE)["value"] = value
		errors.Details(errE)["type"] = fmt.Sprintf("%T", value)
		return errE
	}
	return nil
}

func encodeMetadataInnerList(value interface{}, b *bytes.Buffer) errors.E {
	b.WriteString(`(`)
	v := reflect.ValueOf(value)
	for i := 0; i < v.Len(); i++ {
		errE := encodeMetadataItem(v.Index(i).Interface(), b)
		if errE != nil {
			return errE
		}
	}
	b.WriteString(`)`)
	return nil
}

func encodeMetadata(metadata map[string]interface{}, b *bytes.Buffer) errors.E {
	keys := make([]string, 0, len(metadata))
	for key := range metadata {
		keys = append(keys, key)
	}
	// We sort keys to have deterministic output.
	sort.Strings(keys)
	first := true
	for _, key := range keys {
		value := metadata[key]

		if first {
			first = false
		} else {
			b.WriteString(", ")
		}

		errE := encodeMetadataKey(key, b)
		if errE != nil {
			return errE
		}

		if value == true {
			continue
		}

		b.WriteString("=")

		_, ok := value.([]byte)
		if ok {
			errE = encodeMetadataItem(value, b)
			if errE != nil {
				return errE
			}
			continue
		}

		valueKind := reflect.TypeOf(value).Kind()
		if valueKind == reflect.Slice || valueKind == reflect.Array {
			errE = encodeMetadataInnerList(value, b)
			if errE != nil {
				return errE
			}
			continue
		}

		errE = encodeMetadataItem(value, b)
		if errE != nil {
			return errE
		}
	}

	return nil
}
