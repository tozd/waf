package waf

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"

	"github.com/andybalholm/brotli"
	gddo "github.com/golang/gddo/httputil"
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
	// Compress only if compressed content is smaller than 99% of the original.
	minCompressionRatio = 0.99
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

// metricsContextKey provides metrics for each HTTP request.
var metricsContextKey = &contextKey{"metadata"} //nolint:gochecknoglobals

// We have to use the same disabledLogger that is used in zerolog.Ctx because
// it is checked in logger.UpdateContext.
// See: https://github.com/rs/zerolog/issues/643
var disabledLogger = zerolog.Ctx(context.Background()) //nolint:gochecknoglobals

// canonicalLoggerContextKey provides a canonical log line logger for each HTTP request.
var canonicalLoggerContextKey = &contextKey{"canonical-logger"} //nolint:gochecknoglobals

// canonicalLoggerMessageContextKey provides access to the message for the canonical log line.
var canonicalLoggerMessageContextKey = &contextKey{"canonical-logger-message"} //nolint:gochecknoglobals

// canonicalLogger is similar to zerolog.Ctx, but uses canonicalLoggerContextKey context key.
func canonicalLogger(ctx context.Context) *zerolog.Logger {
	if l, ok := ctx.Value(canonicalLoggerContextKey).(*zerolog.Logger); ok {
		return l
	} else if l = zerolog.DefaultContextLogger; l != nil {
		return l
	}
	return disabledLogger
}

func canonicalLoggerMessage(ctx context.Context) *string {
	if message, ok := ctx.Value(canonicalLoggerMessageContextKey).(*string); ok && message != nil {
		return message
	}
	panic(errors.New("canonical logger message not found in context"))
}

func negotiateContentEncoding(w http.ResponseWriter, req *http.Request, offers []string) string {
	if offers == nil {
		offers = allCompressions
	}

	// We use this header so responses might depend on it.
	if !slices.Contains(w.Header().Values("Vary"), "Accept-Encoding") {
		// This function might have been called multiple times, but
		// we want to add this header with this value only once.
		w.Header().Add("Vary", "Accept-Encoding")
	}

	return gddo.NegotiateContentEncoding(req, offers)
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

func logHandlerName(name string, h Handler) Handler {
	if name == "" {
		return h
	}

	return func(w http.ResponseWriter, req *http.Request, params Params) {
		*canonicalLoggerMessage(req.Context()) = name
		h(w, req, params)
	}
}

func logHandlerFuncName(name string, h func(http.ResponseWriter, *http.Request)) func(http.ResponseWriter, *http.Request) {
	if name == "" {
		return h
	}

	return func(w http.ResponseWriter, req *http.Request) {
		*canonicalLoggerMessage(req.Context()) = name
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
		errors.Details(errE)["certsPath"] = certsPath
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

func computeEtag(data ...[]byte) string {
	hash := sha256.New()
	for _, d := range data {
		_, _ = hash.Write(d)
	}
	return `"` + base64.RawURLEncoding.EncodeToString(hash.Sum(nil)) + `"`
}

// Same as in zerolog/hlog/hlog.go.
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
