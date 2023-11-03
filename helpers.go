package waf

import (
	"context"
	"net/http"

	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
)

func Error(w http.ResponseWriter, _ *http.Request, code int) {
	http.Error(w,
		http.StatusText(code),
		code,
	)
}

func RequestID(req *http.Request) (identifier.Identifier, bool) {
	if req == nil {
		return identifier.Identifier{}, false
	}
	id, ok := req.Context().Value(requestIDContextKey).(identifier.Identifier)
	return id, ok
}

func ToHandler(f func(http.ResponseWriter, *http.Request)) Handler {
	return func(w http.ResponseWriter, req *http.Request, _ Params) {
		f(w, req)
	}
}

// NotFound is a HTTP request handler which returns a 404 error to the client.
func (s *Service[SiteT]) NotFound(w http.ResponseWriter, req *http.Request) {
	// We do not use http.NotFound because http.StatusText(http.StatusNotFound)
	// is different from what http.NotFound uses, and we want to use the same pattern.
	Error(w, req, http.StatusNotFound)
}

func (s *Service[SiteT]) NotFoundWithError(w http.ResponseWriter, req *http.Request, err errors.E) {
	logger := canonicalLogger(req.Context())
	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Err(err)
	})

	s.NotFound(w, req)
}

func (s *Service[SiteT]) MethodNotAllowed(w http.ResponseWriter, req *http.Request) {
	Error(w, req, http.StatusMethodNotAllowed)
}

func (s *Service[SiteT]) NotAcceptable(w http.ResponseWriter, req *http.Request) {
	Error(w, req, http.StatusNotAcceptable)
}

func (s *Service[SiteT]) BadRequest(w http.ResponseWriter, req *http.Request) {
	Error(w, req, http.StatusBadRequest)
}

func (s *Service[SiteT]) BadRequestWithError(w http.ResponseWriter, req *http.Request, err errors.E) {
	logger := canonicalLogger(req.Context())
	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Err(err)
	})

	s.BadRequest(w, req)
}

func (s *Service[SiteT]) InternalServerError(w http.ResponseWriter, req *http.Request) {
	Error(w, req, http.StatusInternalServerError)
}

func (s *Service[SiteT]) InternalServerErrorWithError(w http.ResponseWriter, req *http.Request, err errors.E) {
	logger := canonicalLogger(req.Context())

	// TODO: Extract cause from context and log it. See: https://github.com/golang/go/issues/51365
	if errors.Is(err, context.Canceled) {
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("context", "canceled")
		})
		// Rationale: the client canceled the request and stopped reading the response, so in
		// a way we are not prepared to wait indefinitely for the client to read the response.
		Error(w, req, http.StatusRequestTimeout)
		return
	} else if errors.Is(err, context.DeadlineExceeded) {
		logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
			return c.Str("context", "deadline exceeded")
		})
		// Rationale: the client was reading the response too slowly, and we were
		// not prepared to wait for so long.
		Error(w, req, http.StatusRequestTimeout)
		return
	}

	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Err(err)
	})

	s.InternalServerError(w, req)
}

func (s *Service[SiteT]) Proxy(w http.ResponseWriter, req *http.Request) {
	s.reverseProxy.ServeHTTP(w, req)
}

// TemporaryRedirect redirects the client to a new URL while keeping the method and body not changed.
func (s *Service[SiteT]) TemporaryRedirect(w http.ResponseWriter, req *http.Request, location string) {
	http.Redirect(w, req, location, http.StatusTemporaryRedirect)
}
