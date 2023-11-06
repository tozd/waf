package waf

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync/atomic"

	"github.com/andybalholm/brotli"
	"github.com/hashicorp/go-cleanhttp"
	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
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

// siteContextKey provides a site for the HTTP request.
var siteContextKey = &contextKey{"site"} //nolint:gochecknoglobals

// metadataContextKey accumulates metadata for the HTTP response.
var metadataContextKey = &contextKey{"metadata"} //nolint:gochecknoglobals

var disabledLogger *zerolog.Logger //nolint:gochecknoglobals

func init() { //nolint:gochecknoinits
	l := zerolog.Nop()
	disabledLogger = &l
}

// canonicalLoggerContextKey provides a canonical log line logger for each HTTP request.
var canonicalLoggerContextKey = &contextKey{"canonical-logger"} //nolint:gochecknoglobals

// canonicalLogger is similar to zerolog.Ctx, but uses canonicalLoggerContextKey context key.
func canonicalLogger(ctx context.Context) *zerolog.Logger {
	if l, ok := ctx.Value(canonicalLoggerContextKey).(*zerolog.Logger); ok {
		return l
	} else if l = zerolog.DefaultContextLogger; l != nil {
		return l
	}
	return disabledLogger
}

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

type valuesLogObjectMarshaler map[string][]string

func (v valuesLogObjectMarshaler) MarshalZerologObject(e *zerolog.Event) {
	for key, values := range v {
		arr := zerolog.Arr()
		// Directly iterating over a map does not produce deterministic order
		// but it is faster than first sorting the keys and then iterating.
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
		logger := canonicalLogger(req.Context())
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str(zerolog.MessageFieldName, name)
		})
		h(w, req, params)
	}
}

func logHandlerFuncName(name string, h func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	if name == "" {
		return h
	}

	return func(w http.ResponseWriter, req *http.Request) {
		logger := canonicalLogger(req.Context())
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str(zerolog.MessageFieldName, name)
		})
		h(w, req)
	}
}

// parsePostForm parses and sets only PostForm on http.Request.
//
// See: https://github.com/golang/go/issues/63688
func parsePostForm(r *http.Request) errors.E {
	if r.PostForm != nil {
		return nil
	}

	// We temporary make r.Form non-nil, so that only code path
	// for populating r.PostForm runs when we call r.ParseForm.
	form := r.Form
	defer func() { r.Form = form }()
	r.Form = make(url.Values)

	return errors.WithStack(r.ParseForm())
}

// getQueryForm returns parsed query string. It does not
// set it on http.Request.
func getQueryForm(r *http.Request) (url.Values, errors.E) {
	// Only if r.PostForm is empty, r.Form does not include
	// values from r.PostForm. Otherwise we have to re-parse
	// the query string even if r.Form is not nil.
	if r.Form != nil && len(r.PostForm) == 0 {
		return r.Form, nil
	}

	// We temporary make r.PostForm non-nil and r.Form nil
	// (even if the latter is already nil), so that only code
	// path for populating r.Form runs when we call r.ParseForm.
	form, postForm := r.Form, r.PostForm
	defer func() { r.Form, r.PostForm = form, postForm }()
	r.PostForm = make(url.Values)
	r.Form = nil

	err := r.ParseForm()
	return r.Form, errors.WithStack(err)
}

// Copied from net/http/request.go.
func copyValues(dst, src url.Values) {
	for k, vs := range src {
		dst[k] = append(dst[k], vs...)
	}
}

func parseCertPool(certs []byte) (*x509.CertPool, errors.E) {
	var blocks []byte
	for {
		var block *pem.Block
		block, certs = pem.Decode(certs)
		if block == nil {
			return nil, errors.New("PEM not parsed")
		}
		blocks = append(blocks, block.Bytes...)
		if len(certs) == 0 {
			break
		}
	}
	certificates, err := x509.ParseCertificates(blocks)
	if err != nil {
		return nil, errors.WithMessage(err, "unable to parse certificates")
	}
	certpool := x509.NewCertPool()
	for _, certificate := range certificates {
		certpool.AddCert(certificate)
	}
	return certpool, nil
}

func parseCertPoolFrom(certsPath string) (*x509.CertPool, errors.E) {
	certs, err := os.ReadFile(certsPath)
	if err != nil {
		errE := errors.WithMessage(err, "unable to read file")
		errors.Details(err)["certsPath"] = certsPath
		return nil, errE
	}
	certpool, errE := parseCertPool(certs)
	if errE != nil {
		errors.Details(err)["certsPath"] = certsPath
		return nil, errE
	}
	return certpool, nil
}

func acmeClient(certsPath string) (*http.Client, errors.E) {
	client := cleanhttp.DefaultPooledClient()
	if certsPath != "" {
		certpool, err := parseCertPoolFrom(certsPath)
		if err != nil {
			return nil, err
		}
		client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{ //nolint:exhaustruct,gosec,forcetypeassert
			RootCAs: certpool,
		}
	}
	return client, nil
}

// cleanPath returns the canonical path for p, eliminating . and .. elements.
// Copied from net/http/server.go.
func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	if p[0] != '/' {
		p = "/" + p
	}
	np := path.Clean(p)
	// path.Clean removes trailing slash except for root;
	// put the trailing slash back if necessary.
	if p[len(p)-1] == '/' && np != "/" {
		// Fast path for common case of p being the string we want.
		if len(p) == len(np)+1 && strings.HasPrefix(p, np) {
			np = p
		} else {
			np += "/"
		}
	}
	return np
}

// Copied from https://github.com/rs/zerolog/pull/562.
type byteCountReadCloser struct {
	rc   io.ReadCloser
	read int64
}

func newByteCountReadCloser(body io.ReadCloser) io.ReadCloser {
	if _, ok := body.(io.WriterTo); ok {
		return &byteCountReadCloserWriterTo{
			rc:   body,
			read: 0,
		}
	}
	return &byteCountReadCloser{
		rc:   body,
		read: 0,
	}
}

func (b *byteCountReadCloser) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	b.read += int64(n)
	return n, err //nolint:wrapcheck
}

func (b *byteCountReadCloser) Close() error {
	return b.rc.Close() //nolint:wrapcheck
}

func (b *byteCountReadCloser) BytesRead() int64 {
	return b.read
}

type byteCountReadCloserWriterTo struct {
	rc   io.ReadCloser
	read int64
}

func (b *byteCountReadCloserWriterTo) WriteTo(w io.Writer) (int64, error) {
	n, err := b.rc.(io.WriterTo).WriteTo(w)
	b.read += n
	return n, err //nolint:wrapcheck
}

func (b *byteCountReadCloserWriterTo) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	b.read += int64(n)
	return n, err //nolint:wrapcheck
}

func (b *byteCountReadCloserWriterTo) Close() error {
	return b.rc.Close() //nolint:wrapcheck
}

func (b *byteCountReadCloserWriterTo) BytesRead() int64 {
	return b.read
}

// This is the condition when req.ParseForm consumes the body.
//
// It is equal to the check req.ParseForm does internally.
func postFormParsed(req *http.Request) bool {
	if req.Body == nil {
		return false
	}

	if !(req.Method == "POST" || req.Method == "PUT" || req.Method == "PATCH") {
		return false
	}

	ct := req.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	ct, _, _ = mime.ParseMediaType(ct)
	return ct == "application/x-www-form-urlencoded"
}
