package waf

import (
	"context"
	"net/http"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
	"gitlab.com/tozd/go/errors"
)

// NotFound is a HTTP request handler which returns a 404 error to the client.
func (s *Service[SiteT]) NotFound(w http.ResponseWriter, req *http.Request, _ Params) {
	// We do not use http.NotFound because http.StatusText(http.StatusNotFound)
	// is different from what http.NotFound uses, and we want to use the same pattern.
	Error(w, req, http.StatusNotFound)
}

func (s *Service[SiteT]) NotFoundWithError(w http.ResponseWriter, req *http.Request, err errors.E) {
	logger := hlog.FromRequest(req)
	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Err(err)
	})

	s.NotFound(w, req, nil)
}

func (s *Service[SiteT]) MethodNotAllowed(w http.ResponseWriter, req *http.Request, _ Params) {
	Error(w, req, http.StatusMethodNotAllowed)
}

func (s *Service[SiteT]) NotAcceptable(w http.ResponseWriter, req *http.Request, _ Params) {
	Error(w, req, http.StatusNotAcceptable)
}

func (s *Service[SiteT]) BadRequest(w http.ResponseWriter, req *http.Request, _ Params) {
	Error(w, req, http.StatusBadRequest)
}

func (s *Service[SiteT]) BadRequestWithError(w http.ResponseWriter, req *http.Request, err errors.E) {
	logger := hlog.FromRequest(req)
	logger.UpdateContext(func(c zerolog.Context) zerolog.Context {
		return c.Err(err)
	})

	s.BadRequest(w, req, nil)
}

func (s *Service[SiteT]) InternalServerError(w http.ResponseWriter, req *http.Request, _ Params) {
	Error(w, req, http.StatusInternalServerError)
}

func (s *Service[SiteT]) InternalServerErrorWithError(w http.ResponseWriter, req *http.Request, err errors.E) {
	logger := hlog.FromRequest(req)

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

	s.InternalServerError(w, req, nil)
}

func (s *Service[SiteT]) Proxy(w http.ResponseWriter, req *http.Request, _ Params) {
	s.reverseProxy.ServeHTTP(w, req)
}
