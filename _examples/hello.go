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
	"syscall"

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

//nolint:lll
type App struct {
	z.LoggingConfig `yaml:",inline"`

	Config cli.ConfigFlag    `         help:"Load configuration from a JSON or YAML file." name:"config" placeholder:"PATH" short:"c" yaml:"-"`
	Server waf.Server[*Site] `embed:""                                                                                                yaml:",inline"`

	Domains []string `help:"Domain name(s) to use. If not provided, they are determined from domain names found in TLS certificates." name:"domain" placeholder:"STRING" short:"D" yaml:"domains"`
}

func (a *App) Validate() error {
	// We have to call Validate on kong-embedded structs ourselves.
	// See: https://github.com/alecthomas/kong/issues/90
	if err := a.Server.TLS.Validate(); err != nil {
		return err
	}
	return nil
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
	// We use Kong to populate App struct with config (based on CLI arguments or a config file).
	var app App
	cli.Run(&app, kong.Vars{
		"defaultProxyTo":      "http://localhost:5173",
		"defaultTLSCache":     "letsencrypt",
		"developmentModeHelp": " Proxy unknown requests.",
	}, func(_ *kong.Context) errors.E {
		// Routes come from a single source of truth, e.g., a file.
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
			app.Server.Addr = ":5001"
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
				StaticFiles:     f.(fs.ReadFileFS),
				Routes:          routesConfig.Routes,
				Sites:           sites,
				SiteContextPath: "/context.json",
				ProxyStaticTo:   app.Server.ProxyToInDevelopment(),
				SkipServingFile: func(path string) bool {
					// We want the file to be served by Home route at / and not be
					// available at index.html (as well).
					return path == "/index.html"
				},
			},
		}

		// Construct the main handler for the service using the router.
		handler, errE := service.RouteWith(service, &waf.Router{}) //nolint:exhaustruct
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
