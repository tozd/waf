package waf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetHost(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"", ""},
		{"example.com:8080", "example.com"},
		{"example.com", "example.com"},
		{"invalid", "invalid"},
		{"192.168.0.1:8080", "192.168.0.1"},
		{"[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:8080", "2001:0db8:85a3:0000:0000:8a2e:0370:7334"},
		{"こんにちは.com:8080", "こんにちは.com"},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()

			result := getHost(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
