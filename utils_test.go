package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

func TestParsePostForm(t *testing.T) {
	t.Parallel()

	queryString := "key1=value1&key2=value2"
	postBody := "key3=value3&key4=value4"
	req := httptest.NewRequest(http.MethodPost, "/example?"+queryString, strings.NewReader(postBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	err := parsePostForm(req)
	assert.NoError(t, err)
	assert.Nil(t, req.Form)

	require.NotNil(t, req.PostForm)
	assert.Len(t, req.PostForm, 2)
	assert.Equal(t, "value3", req.PostForm.Get("key3"))
	assert.Equal(t, "value4", req.PostForm.Get("key4"))
}

func TestGetQueryForm(t *testing.T) {
	t.Parallel()

	queryString := "key1=value1&key2=value2"
	postBody := "key3=value3&key4=value4"
	req := httptest.NewRequest(http.MethodPost, "/example?"+queryString, strings.NewReader(postBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	queryForm, err := getQueryForm(req)
	assert.NoError(t, err)

	assert.Len(t, queryForm, 2)
	assert.Equal(t, "value1", queryForm.Get("key1"))
	assert.Equal(t, "value2", queryForm.Get("key2"))

	assert.Nil(t, req.Form)
	assert.Nil(t, req.PostForm)

	err = parsePostForm(req)
	assert.NoError(t, err)
	assert.Nil(t, req.Form)

	require.NotNil(t, req.PostForm)
	assert.Len(t, req.PostForm, 2)
	assert.Equal(t, "value3", req.PostForm.Get("key3"))
	assert.Equal(t, "value4", req.PostForm.Get("key4"))

	queryForm, err = getQueryForm(req)
	assert.NoError(t, err)

	assert.Len(t, queryForm, 2)
	assert.Equal(t, "value1", queryForm.Get("key1"))
	assert.Equal(t, "value2", queryForm.Get("key2"))

	assert.Nil(t, req.Form)
	assert.NotNil(t, req.PostForm)
	assert.Len(t, req.PostForm, 2)
	assert.Equal(t, "value3", req.PostForm.Get("key3"))
	assert.Equal(t, "value4", req.PostForm.Get("key4"))
}
