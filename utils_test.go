package waf

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePostForm(t *testing.T) {
	t.Parallel()

	queryString := "key1=value1&key2=value2"
	postBody := "key3=value3&key4=value4"
	req := httptest.NewRequest(http.MethodPost, "/example?"+queryString, strings.NewReader(postBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	errE := parsePostForm(req)
	assert.NoError(t, errE, "% -+#.1v", errE)
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

	queryForm, errE := getQueryForm(req)
	assert.NoError(t, errE, "% -+#.1v", errE)

	assert.Len(t, queryForm, 2)
	assert.Equal(t, "value1", queryForm.Get("key1"))
	assert.Equal(t, "value2", queryForm.Get("key2"))

	assert.Nil(t, req.Form)
	assert.Nil(t, req.PostForm)

	errE = parsePostForm(req)
	assert.NoError(t, errE, "% -+#.1v", errE)
	assert.Nil(t, req.Form)

	require.NotNil(t, req.PostForm)
	assert.Len(t, req.PostForm, 2)
	assert.Equal(t, "value3", req.PostForm.Get("key3"))
	assert.Equal(t, "value4", req.PostForm.Get("key4"))

	queryForm, errE = getQueryForm(req)
	assert.NoError(t, errE, "% -+#.1v", errE)

	assert.Len(t, queryForm, 2)
	assert.Equal(t, "value1", queryForm.Get("key1"))
	assert.Equal(t, "value2", queryForm.Get("key2"))

	assert.Nil(t, req.Form)
	assert.NotNil(t, req.PostForm)
	assert.Len(t, req.PostForm, 2)
	assert.Equal(t, "value3", req.PostForm.Get("key3"))
	assert.Equal(t, "value4", req.PostForm.Get("key4"))
}
