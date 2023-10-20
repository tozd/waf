package waf

import (
	"bytes"
	"mime"
	"net/http"
	"path/filepath"
	"strconv"
	"time"

	eddo "github.com/golang/gddo/httputil"
	"gitlab.com/tozd/go/errors"
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

// TODO: Use Vite's manifest.json to send preload headers.
func (s *Service[SiteT]) staticFile(w http.ResponseWriter, req *http.Request, path string, immutable bool) {
	contentEncoding := eddo.NegotiateContentEncoding(req, allCompressions)
	if contentEncoding == "" {
		s.NotAcceptable(w, req, nil)
		return
	}

	siteT, err := s.getSite(req)
	if err != nil {
		s.notFoundWithError(w, req, err)
		return
	}

	site := siteT.GetSite()

	data, ok := site.compressedFiles[contentEncoding][path]
	if !ok {
		s.internalServerErrorWithError(w, req, errors.Errorf(`no data for compression %s and file "%s"`, contentEncoding, path))
		return
	}

	if len(data) <= minCompressionSize {
		contentEncoding = compressionIdentity
		data, ok = site.compressedFiles[contentEncoding][path]
		if !ok {
			s.internalServerErrorWithError(w, req, errors.Errorf(`no data for compression %s and file "%s"`, contentEncoding, path))
			return
		}
	}

	etag, ok := site.compressedFilesEtags[contentEncoding][path]
	if !ok {
		s.internalServerErrorWithError(w, req, errors.Errorf(`no etag for compression %s and file "%s"`, contentEncoding, path))
		return
	}

	contentType := mime.TypeByExtension(filepath.Ext(path))
	if contentType == "" {
		s.internalServerErrorWithError(w, req, errors.Errorf(`unable to determine content type for file "%s"`, path))
		return
	}

	w.Header().Set("Content-Type", contentType)
	if contentEncoding != compressionIdentity {
		w.Header().Set("Content-Encoding", contentEncoding)
	} else {
		// TODO: Always set Content-Length.
		//       See: https://github.com/golang/go/pull/50904
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	}
	if immutable {
		w.Header().Set("Cache-Control", "public,max-age=31536000,immutable,stale-while-revalidate=86400")
	} else {
		w.Header().Set("Cache-Control", "no-cache")
	}
	w.Header().Add("Vary", "Accept-Encoding")
	w.Header().Set("Etag", etag)
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// See: https://github.com/golang/go/issues/50905
	// See: https://github.com/golang/go/pull/50903
	http.ServeContent(w, req, "", time.Time{}, bytes.NewReader(data))
}

func (s *Service[SiteT]) StaticFile(w http.ResponseWriter, req *http.Request, _ Params) {
	s.staticFile(w, req, req.URL.Path, false)
}

func (s *Service[SiteT]) ImmutableFile(w http.ResponseWriter, req *http.Request, _ Params) {
	s.staticFile(w, req, req.URL.Path, true)
}
