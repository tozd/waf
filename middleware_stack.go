package waf

import (
	"net/http"
	"time"

	"github.com/justinas/alice"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/hlog"
)

// newMiddlewareStack creates an initial part of the middleware stack used by both HTTPS and HTTP servers.
func newMiddlewareStack(canonicalLogger zerolog.Logger, metadataHeaderPrefix string) alice.Chain {
	c := alice.New()

	// We first create a canonical log line logger as context logger.
	c = c.Append(hlog.NewHandler(canonicalLogger))
	// Then we set the canonical log line logger under its own context key as well.
	c = c.Append(setCanonicalLogger)
	// It has to be before accessHandler so that it can access the metrics context.
	c = c.Append(metricsMiddleware)

	// Is logger enabled at all (not zerolog.Nop or zero zerolog struct)?
	// See: https://github.com/rs/zerolog/pull/617
	if l := canonicalLogger.Sample(nil); l.Log().Enabled() { //nolint:zerologlint
		c = c.Append(accessHandler(func(req *http.Request, code int, responseBody, requestBody int64, duration time.Duration) {
			ctx := req.Context()

			level := zerolog.InfoLevel
			if code >= http.StatusBadRequest {
				level = zerolog.WarnLevel
			}
			if code >= http.StatusInternalServerError {
				level = zerolog.ErrorLevel
			}

			metrics := MustGetMetrics(ctx)
			metrics.Duration(MetricTotal).Duration = duration

			l := zerolog.Ctx(ctx).WithLevel(level) //nolint:zerologlint
			if code != 0 {
				l = l.Int("code", code)
			}
			l = l.Int64("responseBody", responseBody).
				Int64("requestBody", requestBody).
				Object("metrics", metrics)

			message := canonicalLoggerMessage(ctx)
			if *message != "" {
				l.Msg(*message)
			} else {
				l.Send()
			}
		}))
		if metadataHeaderPrefix != "" {
			c = c.Append(logMetadata(metadataHeaderPrefix))
		}
		c = c.Append(websocketHandler("ws"))
		c = c.Append(hlog.MethodHandler("method"))
		c = c.Append(urlHandler("path"))
		c = c.Append(hlog.RemoteIPHandler("client"))
		c = c.Append(hlog.UserAgentHandler("agent"))
		c = c.Append(hlog.RefererHandler("referer"))
		c = c.Append(connectionIDHandler("connection"))
		c = c.Append(requestIDHandler("request", "Request-Id"))
		c = c.Append(hlog.HTTPVersionHandler("proto"))
		c = c.Append(hlog.HostHandler("host", true))
		c = c.Append(hlog.EtagHandler("etag"))
		c = c.Append(hlog.ResponseHeaderHandler("encoding", "Content-Encoding"))
	} else {
		c = c.Append(accessHandler(func(req *http.Request, _ int, _, _ int64, duration time.Duration) {
			ctx := req.Context()
			metrics := MustGetMetrics(ctx)
			metrics.Duration(MetricTotal).Duration = duration
		}))
		c = c.Append(requestIDHandler("", "Request-Id"))
	}

	c = c.Append(addNosniffHeader)

	return c
}
