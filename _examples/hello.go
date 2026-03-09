// Command main is a simple example of a Waf service.
package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/alecthomas/kong"
	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/cli"
	"gitlab.com/tozd/go/errors"
	z "gitlab.com/tozd/go/zerolog"

	"gitlab.com/tozd/waf"
)

//go:embed files
var files embed.FS

//nolint:lll
type App struct {
	z.LoggingConfig `yaml:",inline"`

	Config cli.ConfigFlag    `         help:"Load configuration from a JSON or YAML file." name:"config" placeholder:"PATH" short:"c" yaml:"-"`
	Server waf.Server[*Site] `embed:""                                                                                                yaml:",inline"`

	Domains []string `help:"Domain name(s) to use. If not provided, they are determined from domain names found in TLS certificates." name:"domain" placeholder:"STRING" short:"d" yaml:"domains"`
}

func (a *App) Validate() error {
	// We have to call Validate on kong-embedded structs ourselves.
	// See: https://github.com/alecthomas/kong/issues/90
	err := a.Server.HTTPS.Validate()
	if err != nil {
		return err //nolint:wrapcheck
	}
	return nil
}

// Site extends basic Site with a title.
type Site struct {
	waf.Site

	Title string `json:"title"`
}

// Service extends basic Service with our handlers.
type Service struct {
	waf.Service[*Site]
}

func (s *Service) Home(w http.ResponseWriter, req *http.Request, _ waf.Params) {
	zerolog.Ctx(req.Context()).Info().Msg("hello from Home handler")

	s.ServeStaticFile(w, req, "/index.html")
}

func main() {
	// We use Kong to populate App struct with config (based on CLI arguments or a config file).
	var app App
	cli.Run(&app, kong.Vars{
		"defaultListen":       ":8080",
		"defaultProxyTo":      "http://localhost:5173",
		"developmentModeHelp": " Proxy unknown requests.",
	}, func(_ *kong.Context) errors.E {
		app.Server.Logger = app.Logger

		// Used for testing.
		if os.Getenv("PEBBLE_HOST") != "" {
			app.Server.HTTPS.ACMEDirectory = fmt.Sprintf("https://%s/dir", net.JoinHostPort(os.Getenv("PEBBLE_HOST"), "14000"))
			app.Server.HTTPS.ACMEDirectoryRootCAs = "../testdata/pebble.minica.pem"
			app.Server.HTTPS.Listen = ":5001"
		}

		sites := map[string]*Site{}
		// If domains are provided, we create sites based on those domains.
		for _, domain := range app.Domains {
			sites[domain] = &Site{
				Site: waf.Site{
					Domain:   domain,
					CertFile: "",
					KeyFile:  "",
				},
				Title: "", // We will set title later for all sites.
			}
		}
		// If domains are not provided, sites are automatically constructed based on the certificate.
		sites, errE := app.Server.Init(sites)
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
			waf.Service[*Site]{
				Logger:          app.Logger,
				CanonicalLogger: app.Logger,
				WithContext:     app.WithContext,
				StaticFiles:     f.(fs.ReadFileFS), //nolint:errcheck
				Routes:          nil,
				Sites:           sites,
				SiteContextPath: "/context.json",
				RoutesPath:      "/routes.json",
				ProxyStaticTo:   app.Server.ProxyToInDevelopment(),
				SkipServingFile: func(path string) bool {
					// We want the file to be served by Home route at / and not be
					// available at index.html (as well).
					return path == "/index.html"
				},
			},
		}

		service.Routes = map[string]waf.Route{
			"Home": {
				RouteOptions: waf.RouteOptions{
					Handlers: map[string]waf.Handler{
						http.MethodGet: service.Home,
					},
				},
				Path: "/",
			},
		}

		// Construct the main handler for the service using the router.
		handler, errE := service.RouteWith(&waf.Router{})
		if errE != nil {
			return errE
		}

		// We stop the server gracefully on ctrl-c and TERM signal.
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		// It returns only on error or if the server is gracefully shut down using ctrl-c.
		return app.Server.Run(ctx, handler)
	})
}
