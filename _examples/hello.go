package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"

	"github.com/alecthomas/kong"
	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/cli"
	"gitlab.com/tozd/go/errors"
	z "gitlab.com/tozd/go/zerolog"

	"gitlab.com/tozd/waf"
)

//go:embed routes.json
var routesConfiguration []byte

//go:embed files
var files embed.FS

type App struct {
	Config          cli.ConfigFlag `help:"Load configuration from a JSON or YAML file." name:"config"  placeholder:"PATH" short:"c" yaml:"-"`
	z.LoggingConfig `yaml:",inline"`
	Server          waf.Server[*Site] `embed:""                                            yaml:",inline"`
}

// We extend Site with a title.
type Site struct {
	waf.Site
	Title string `json:"title"`
}

// We extend Service with our handlers.
type Service struct {
	waf.Service[*Site]
}

func (s *Service) Home(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	zerolog.Ctx(req.Context()).Info().Msg("hello from Home handler")

	s.ServeStaticFile(w, req, "/index.html")
}

func main() {
	var app App
	cli.Run(&app, kong.Vars{
		"defaultProxyTo":  "http://localhost:3000",
		"defaultTLSCache": "letsencrypt",
	}, func(_ *kong.Context) errors.E {
		var routesConfig struct {
			Routes []waf.Route `json:"routes"`
		}
		err := json.Unmarshal(routesConfiguration, &routesConfig)
		if err != nil {
			return errors.WithStack(err)
		}

		app.Server.Logger = app.Logger

		// Used for testing.
		if os.Getenv("PEBBLE_HOST") != "" {
			app.Server.TLS.ACMEDirectory = fmt.Sprintf("https://%s/dir", net.JoinHostPort(os.Getenv("PEBBLE_HOST"), "14000"))
			app.Server.TLS.ACMEDirectoryRootCAs = "../testdata/pebble.minica.pem"
			app.Server.ListenAddr = ":5001"
		}

		// Sites are automatically constructed based on the certificate or domain name for Let's Encrypt.
		sites, errE := app.Server.Init(nil)
		if errE != nil {
			return errE
		}

		// We set Title on sites.
		for _, site := range sites {
			site.Title = "Hello site"
		}

		// We remove "files" prefix.
		f, err := fs.Sub(files, "files")
		if err != nil {
			return errors.WithStack(err)
		}

		service := &Service{ //nolint:forcetypeassert
			waf.Service[*Site]{ //nolint:exhaustruct
				Logger:          app.Logger,
				CanonicalLogger: app.Logger,
				WithContext:     app.WithContext,
				StaticFiles:     f.(fs.ReadFileFS),
				Routes:          routesConfig.Routes,
				Sites:           sites,
				SiteContextPath: "/api",
				Development:     app.Server.InDevelopment(),
				SkipServingFile: func(path string) bool {
					// We want the file to be served by Home handler at / and to not be
					// available at index.html (as well).
					return path == "/index.html"
				},
			},
		}

		handler, errE := service.RouteWith(service, &waf.Router{}) //nolint:exhaustruct
		if errE != nil {
			return errE
		}

		// We stop the server on ctrl-c.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()

		return app.Server.Run(ctx, handler)
	})
}
