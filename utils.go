package waf

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"net"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"sync/atomic"
	"unicode"

	"github.com/andybalholm/brotli"
	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"

	"gitlab.com/tozd/identifier"
)

const (
	compressionBrotli   = "br"
	compressionGzip     = "gzip"
	compressionDeflate  = "deflate"
	compressionIdentity = "identity"

	// Compress only if content is larger than 1 KB.
	minCompressionSize = 1024
)

var allCompressions = []string{compressionBrotli, compressionGzip, compressionDeflate, compressionIdentity} //nolint:gochecknoglobals

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation.
type contextKey struct {
	name string
}

// connectionIDContextKey provides a random ID for each HTTP connection.
var connectionIDContextKey = &contextKey{"connection-id"} //nolint:gochecknoglobals

// requestIDContextKey provides a random ID for each HTTP request.
var requestIDContextKey = &contextKey{"request-id"} //nolint:gochecknoglobals

func getHost(hostPort string) string {
	if hostPort == "" {
		return ""
	}

	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

// TODO: Use a pool of compression workers?
func compress(compression string, data []byte) ([]byte, errors.E) {
	switch compression {
	case compressionBrotli:
		var buf bytes.Buffer
		writer := brotli.NewWriter(&buf)
		_, err := writer.Write(data)
		if closeErr := writer.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, errors.WithMessage(err, compression)
		}
		data = buf.Bytes()
	case compressionGzip:
		var buf bytes.Buffer
		writer := gzip.NewWriter(&buf)
		_, err := writer.Write(data)
		if closeErr := writer.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, errors.WithMessage(err, compression)
		}
		data = buf.Bytes()
	case compressionDeflate:
		var buf bytes.Buffer
		writer, err := flate.NewWriter(&buf, -1)
		if err != nil {
			return nil, errors.WithMessage(err, compression)
		}
		_, err = writer.Write(data)
		if closeErr := writer.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, errors.WithMessage(err, compression)
		}
		data = buf.Bytes()
	case compressionIdentity:
		// Nothing.
	default:
		errE := errors.New("unknown compression")
		errors.Details(errE)["compression"] = compression
		return nil, errE
	}
	return data, nil
}

func idFromRequest(req *http.Request) (identifier.Identifier, bool) {
	if req == nil {
		return identifier.Identifier{}, false
	}
	id, ok := req.Context().Value(requestIDContextKey).(identifier.Identifier)
	return id, ok
}

type valuesLogObjectMarshaler map[string][]string

func (v valuesLogObjectMarshaler) MarshalZerologObject(e *zerolog.Event) {
	for key, values := range v {
		arr := zerolog.Arr()
		for _, val := range values {
			arr.Str(val)
		}
		e.Array(key, arr)
	}
}

func logValues(c zerolog.Context, field string, values map[string][]string) zerolog.Context {
	if len(values) == 0 {
		return c
	}

	return c.Object(field, valuesLogObjectMarshaler(values))
}

type metricsConn struct {
	net.Conn
	read    *int64
	written *int64
}

func (c *metricsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	atomic.AddInt64(c.read, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func (c *metricsConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	atomic.AddInt64(c.written, int64(n))
	if err == io.EOF { //nolint:errorlint
		// See: https://github.com/golang/go/issues/39155
		return n, io.EOF
	}
	return n, errors.WithStack(err)
}

func logHandlerName(name string, h Handler) Handler {
	if name == "" {
		return h
	}

	return func(w http.ResponseWriter, req *http.Request, params Params) {
		logger := zerolog.Ctx(req.Context())
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str(zerolog.MessageFieldName, name)
		})
		h(w, req, params)
	}
}

func autoName(h Handler) string {
	fn := runtime.FuncForPC(reflect.ValueOf(h).Pointer())
	if fn == nil {
		return ""
	}
	name := fn.Name()
	i := strings.LastIndex(name, ".")
	if i != -1 {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(name, "-fm")

	// Make sure the first letter is upper case. We have some internal handlers
	// but we want uniform look in logs.
	rs := []rune(name)
	rs[0] = unicode.ToUpper(rs[0])
	name = string(rs)

	return name
}
