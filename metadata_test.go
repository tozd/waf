package waf

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeMetadataKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  string
		err  string
	}{
		{
			name: "ValidKey",
			key:  "valid_key",
			err:  "",
		},
		{
			name: "EmptyKey",
			key:  "",
			err:  "unsupported dictionary key",
		},
		{
			name: "InvalidFirstChar",
			key:  "1invalid_key",
			err:  "unsupported dictionary key",
		},
		{
			name: "InvalidCharacter",
			key:  "invalid@key",
			err:  "unsupported dictionary key",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out := &bytes.Buffer{}
			err := encodeMetadataKey(tt.key, out)
			if tt.err != "" {
				assert.EqualError(t, err, tt.err)
			} else {
				assert.Equal(t, tt.key, out.String())
			}
		})
	}
}

func TestEncodeMetadataSignedInteger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    int64
		expected string
		err      string
	}{
		{
			name:     "ValidPositiveValue",
			value:    42,
			expected: "42",
			err:      "",
		},
		{
			name:     "ValidNegativeValue",
			value:    -42,
			expected: "-42",
			err:      "",
		},
		{
			name:     "OutOfRangePositive",
			value:    1000000000000000,
			expected: "",
			err:      "integer out of range",
		},
		{
			name:     "OutOfRangeNegative",
			value:    -1000000000000000,
			expected: "",
			err:      "integer out of range",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out := &bytes.Buffer{}
			err := encodeMetadataSignedInteger(tt.value, out)
			if tt.err != "" {
				assert.EqualError(t, err, tt.err)
			} else {
				assert.Equal(t, tt.expected, out.String())
			}
		})
	}
}

func TestEncodeMetadataUnsignedInteger(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    uint64
		expected string
		err      string
	}{
		{
			name:     "ValidValue",
			value:    42,
			expected: "42",
			err:      "",
		},
		{
			name:     "OutOfRange",
			value:    1000000000000000,
			expected: "",
			err:      "integer out of range",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out := &bytes.Buffer{}
			err := encodeMetadataUnsignedInteger(tt.value, out)
			if tt.err != "" {
				assert.EqualError(t, err, tt.err)
			} else {
				assert.Equal(t, tt.expected, out.String())
			}
		})
	}
}

func TestEncodeMetadataDecimal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    float64
		expected string
		err      string
	}{
		{
			name:     "ValidPositiveValue",
			value:    3.14,
			expected: "3.14",
			err:      "",
		},
		{
			name:     "ValidNegativeValue",
			value:    -3.14,
			expected: "-3.14",
			err:      "",
		},
		{
			name:     "ValidLongValue",
			value:    3.141234,
			expected: "3.141",
			err:      "",
		},
		{
			name:     "ValidIntegerValue",
			value:    3.0,
			expected: "3.0",
			err:      "",
		},
		{
			name:     "OutOfRangePositive",
			value:    1000000000000000,
			expected: "",
			err:      "decimal out of range",
		},
		{
			name:     "OutOfRangeNegative",
			value:    -1000000000000000,
			expected: "",
			err:      "decimal out of range",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out := &bytes.Buffer{}
			err := encodeMetadataDecimal(tt.value, out)
			if tt.err != "" {
				assert.EqualError(t, err, tt.err)
			} else {
				assert.Equal(t, tt.expected, out.String())
			}
		})
	}
}

func TestEncodeMetadataItem(t *testing.T) {
	t.Parallel()

	d, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
	require.NoError(t, err)

	tests := []struct {
		name     string
		value    interface{}
		expected string
		err      string
	}{
		{
			name:     "IntegerValue",
			value:    42,
			expected: "42",
			err:      "",
		},
		{
			name:     "UnsignedIntegerValue",
			value:    uint(42),
			expected: "42",
			err:      "",
		},
		{
			name:     "DecimalValue",
			value:    3.14,
			expected: "3.14",
			err:      "",
		},
		{
			name:     "BooleanTrueValue",
			value:    true,
			expected: "?1",
			err:      "",
		},
		{
			name:     "BooleanFalseValue",
			value:    false,
			expected: "?0",
			err:      "",
		},
		{
			name:     "BinaryValue",
			value:    []byte{'a', 'b'},
			expected: ":YWI=:",
			err:      "",
		},
		{
			name:     "StringValue",
			value:    "test",
			expected: `"test"`,
			err:      "",
		},
		{
			name:     "StringQuotedValue",
			value:    `te"s\t`,
			expected: `"te\"s\\t"`,
			err:      "",
		},
		{
			name:     "DateValue",
			value:    d,
			expected: `@1136214245`,
			err:      "",
		},
		{
			name:     "StringUnsupportedValue",
			value:    "te\nst",
			expected: "",
			err:      "string contains unsupported character",
		},
		{
			name:  "UnsupportedType",
			value: struct{}{},
			err:   "unsupported data type",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out := &bytes.Buffer{}
			err := encodeMetadataItem(tt.value, out)
			if tt.err != "" {
				assert.EqualError(t, err, tt.err)
			} else {
				assert.Equal(t, tt.expected, out.String())
			}
		})
	}
}

func TestEncodeMetadataInnerList(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    interface{}
		expected string
		err      string
	}{
		{
			name:     "ValidList",
			value:    []interface{}{42, "test", 3.14, true},
			expected: `(42 "test" 3.14 ?1)`,
			err:      "",
		},
		{
			name:     "EmptyList",
			value:    []interface{}{},
			expected: `()`,
			err:      "",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out := &bytes.Buffer{}
			err := encodeMetadataInnerList(tt.value, out)
			if tt.err != "" {
				assert.EqualError(t, err, tt.err)
			} else {
				assert.Equal(t, tt.expected, out.String())
			}
		})
	}
}

func TestEncodeMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		metadata map[string]interface{}
		expected string
		err      string
	}{
		{
			name:     "ValidMetadata",
			metadata: map[string]interface{}{"key1": 42, "key2": "test", "key3": true, "key4": []byte{'c', 'd'}, "key5": []int{1, 2, 3}},
			expected: `key1=42, key2="test", key3, key4=:Y2Q=:, key5=(1 2 3)`,
			err:      "",
		},
		{
			name:     "EmptyMetadata",
			metadata: map[string]interface{}{},
			expected: "",
			err:      "",
		},
		{
			name:     "UnsupportedType",
			metadata: map[string]interface{}{"key1": struct{}{}},
			expected: "",
			err:      "unsupported data type",
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out := &bytes.Buffer{}
			err := encodeMetadata(tt.metadata, out)
			if tt.err != "" {
				assert.EqualError(t, err, tt.err)
			} else {
				assert.Equal(t, tt.expected, out.String())
			}
		})
	}
}
