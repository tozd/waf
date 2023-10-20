package waf

import (
	"net/http"
)

// NotFound is a HTTP request handler which returns a 404 error to the client.
func (s *Service[SiteT]) NotFound(w http.ResponseWriter, req *http.Request, _ Params) {
	// We do not use http.NotFound because http.StatusText(http.StatusNotFound)
	// is different from what http.NotFound uses, and we want to use the same pattern.
	Error(w, req, http.StatusNotFound)
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

func (s *Service[SiteT]) InternalServerError(w http.ResponseWriter, req *http.Request, _ Params) {
	Error(w, req, http.StatusInternalServerError)
}

func (s *Service[SiteT]) Proxy(w http.ResponseWriter, req *http.Request, _ Params) {
	s.reverseProxy.ServeHTTP(w, req)
}
