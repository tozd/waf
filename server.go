package waf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/go/x"
	"gitlab.com/tozd/identifier"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"
	"golang.org/x/sync/errgroup"
)

const (
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 10 * time.Minute
)

// HTTPS configuration used by the server.
//
//nolint:lll
type HTTPS struct {
	// Default certificate for HTTPS, when not using Let's Encrypt.
	CertFile string `group:"HTTPS:" help:"Default certificate for HTTPS, when not using Let's Encrypt. In PEM format." name:"cert" placeholder:"PATH" short:"k" type:"existingfile" yaml:"cert"`

	// Default certificate's private key, when not using Let's Encrypt.
	KeyFile string `group:"HTTPS:" help:"Default certificate's private key, when not using Let's Encrypt. In PEM format." name:"key" placeholder:"PATH" short:"K" type:"existingfile" yaml:"key"`

	// Let's Encrypt's cache directory.
	LetsEncryptCache string `group:"HTTPS:" help:"Let's Encrypt's cache directory. Set it to enable Let's Encrypt." name:"letsencrypt" placeholder:"PATH" short:"C" type:"path" yaml:"letsencrypt"`

	// Listen on which TCP address.
	Listen string `default:"${defaultListen}" group:"HTTPS:" help:"TCP address for the HTTPS server to listen on." placeholder:"HOST:PORT" short:"L" yaml:"listen"`

	// External port can be different.
	ExternalPort int `group:"HTTPS:" help:"Port on which HTTPS server is accessible when it is different from the port on which the HTTPS server listens." placeholder:"INT" yaml:"externalPort"`

	// Used primarily for testing.
	ACMEDirectory        string `json:"-" kong:"-" yaml:"-"`
	ACMEDirectoryRootCAs string `json:"-" kong:"-" yaml:"-"`
}

// Validate is used by Kong to validate the struct.
func (t *HTTPS) Validate() error {
	if t.CertFile != "" || t.KeyFile != "" {
		if t.CertFile == "" {
			return errors.New("missing file certificate for provided private key")
		}
		if t.KeyFile == "" {
			return errors.New("missing file certificate's matching private key")
		}
		if t.LetsEncryptCache != "" {
			return errors.New("Let's Encrypt's cannot be enabled together with default certificate set")
		}
	}

	return nil
}

// HTTP configuration used by the server.
type HTTP struct {
	// Listen on which TCP address.
	Listen string `group:"HTTP:" help:"TCP address for the HTTP server to listen on. Setting it enables HTTP redirect to HTTPS." placeholder:"HOST:PORT" yaml:"listen"`
}

// Server listens to HTTP/1.1 and HTTP2 requests on HTTPS enabled port 8080 and
// serves requests using the provided handler. Server is production ready and
// can be exposed directly on open Internet.
//
// Certificates for HTTPS can be provided as files (which are daily reread to allow updating them)
// or can be automatically obtained (and updated) using [Let's Encrypt] (when running
// accessible from the Internet).
//
// [Let's Encrypt]: https://letsencrypt.org/
type Server[SiteT hasSite] struct {
	// Logger to be used by the server.
	Logger zerolog.Logger `kong:"-" yaml:"-"`

	// Run in development mode. By default proxy unknown requests.
	Development bool `help:"Run in development mode.${developmentModeHelp}" short:"D" yaml:"development"`

	// Base URL to proxy to in development mode.
	ProxyTo string `default:"${defaultProxyTo}" help:"Base URL to proxy to in development mode." placeholder:"URL" short:"P" yaml:"proxyTo"`

	// HTTPS configuration.
	HTTPS HTTPS `embed:"" prefix:"https." yaml:"https"`

	// HTTP configuration.
	HTTP HTTP `embed:"" prefix:"http." yaml:"http"`

	// Exposed primarily for use in tests.
	HTTPSServer *http.Server `json:"-" kong:"-" yaml:"-"`
	HTTPServer  *http.Server `json:"-" kong:"-" yaml:"-"`

	// Autocert managers do not have to be stopped, but certificate managers do.
	managers []*certificateManager

	domains []string

	listenAddrHTTPS *x.SyncVar[string]
	listenAddrHTTP  *x.SyncVar[string]
}

// Init determines the set of sites based on HTTPS configuration and sites provided,
// returning possibly updated and expanded set of sites.
//
// If sites parameter is empty, sites are determined from domain names found in HTTPS
// certificates. If sites are provided and HTTPS certificates are not, their domains
// are used to obtain the necessary certificate from Let's Encrypt.
//
// Key in sites map must match site's domain.
func (s *Server[SiteT]) Init(sites map[string]SiteT) (map[string]SiteT, errors.E) { //nolint:maintidx
	// TODO: How to shutdown websocket connections?

	// TODO: Add limits on max idle time and min speed for writing the whole response.
	//       If a limit is reached, context should be canceled.
	//       See: https://github.com/golang/go/issues/16100
	//       See: https://github.com/golang/go/issues/21389
	//       See: https://github.com/golang/go/issues/59602
	httpsServer := &http.Server{ //nolint:exhaustruct
		Addr:                         s.HTTPS.Listen,
		Handler:                      nil,
		DisableGeneralOptionsHandler: false,
		TLSConfig: &tls.Config{ //nolint:exhaustruct
			CipherSuites: []uint16{
				tls.TLS_AES_128_GCM_SHA256,
				tls.TLS_AES_256_GCM_SHA384,
				tls.TLS_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			},
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			NextProtos:       []string{"h2", "http/1.1"},
		},
		ReadTimeout:       0,
		ReadHeaderTimeout: readHeaderTimeout,
		WriteTimeout:      0,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    0,
		ErrorLog:          log.New(s.Logger, "", 0),
		BaseContext: func(l net.Listener) context.Context {
			errE := s.listenAddrHTTPS.Store(l.Addr().String())
			if errE != nil {
				panic(errE)
			}
			return context.Background()
		},
		ConnContext: s.connContext,
	}

	domains := []string{}

	var fileGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	var letsEncryptGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	var nextProtos []string

	letsEncryptDomainsList := []string{}

	if len(sites) > 0 { //nolint:nestif
		fileGetCertificateFunctions := map[string]func(*tls.ClientHelloInfo) (*tls.Certificate, error){}

		for domain, siteT := range sites {
			site := siteT.GetSite()

			if site.Domain == "" {
				return sites, errors.New("site's domain is required")
			}
			if domain != site.Domain {
				err := errors.New("domain does not match site's domain")
				errors.Details(err)["domain1"] = domain
				errors.Details(err)["domain2"] = site.Domain
				return sites, err
			}

			domains = append(domains, site.Domain)

			if site.CertFile != "" && site.KeyFile != "" {
				manager := &certificateManager{
					CertFile:    site.CertFile,
					KeyFile:     site.KeyFile,
					Logger:      s.Logger,
					certificate: nil,
					mu:          sync.RWMutex{},
					ticker:      nil,
					done:        nil,
				}

				err := manager.Init()
				if err != nil {
					return sites, errors.WithDetails(err, "certFile", site.CertFile, "domain", site.Domain)
				}
				s.managers = append(s.managers, manager)

				fileGetCertificateFunctions[site.Domain] = manager.GetCertificate

				err = manager.ValidForDomain(site.Domain)
				if err != nil {
					return sites, errors.WithDetails(err, "certFile", site.CertFile)
				}
			} else if s.HTTPS.LetsEncryptCache != "" {
				letsEncryptDomainsList = append(letsEncryptDomainsList, site.Domain)
			} else if s.HTTPS.CertFile != "" && s.HTTPS.KeyFile != "" {
				manager := &certificateManager{
					CertFile:    s.HTTPS.CertFile,
					KeyFile:     s.HTTPS.KeyFile,
					Logger:      s.Logger,
					certificate: nil,
					mu:          sync.RWMutex{},
					ticker:      nil,
					done:        nil,
				}

				err := manager.Init()
				if err != nil {
					return sites, errors.WithDetails(err, "certFile", s.HTTPS.CertFile, "domain", site.Domain)
				}
				s.managers = append(s.managers, manager)

				fileGetCertificateFunctions[site.Domain] = manager.GetCertificate

				err = manager.ValidForDomain(site.Domain)
				if err != nil {
					return sites, errors.WithDetails(err, "certFile", s.HTTPS.CertFile)
				}
			} else {
				err := errors.New("missing file or Let's Encrypt's certificate configuration")
				errors.Details(err)["domain"] = site.Domain
				return sites, err
			}
		}

		if len(fileGetCertificateFunctions) > 0 {
			fileGetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				// Note that this conversion is necessary because some server names in the handshakes
				// started by some clients (such as cURL) are not converted to Punycode, which will
				// prevent us from obtaining certificates for them. In addition, we should also treat
				// example.com and EXAMPLE.COM as equivalent and return the same certificate for them.
				// Fortunately, this conversion also helped us deal with this kind of mixedcase problems.
				//
				// Due to the "σςΣ" problem (see https://unicode.org/faq/idn.html#22), we can't use
				// idna.Punycode.ToASCII (or just idna.ToASCII) here.
				name, err := idna.Lookup.ToASCII(hello.ServerName)
				if err != nil {
					errE := errors.WithMessage(err, "server name contains invalid character")
					errors.Details(errE)["name"] = hello.ServerName
					return nil, errE
				}
				f, ok := fileGetCertificateFunctions[name]
				if ok {
					return f(hello)
				}
				return nil, nil //nolint:nilnil
			}
		}
	} else if s.HTTPS.CertFile != "" && s.HTTPS.KeyFile != "" {
		manager := &certificateManager{
			CertFile:    s.HTTPS.CertFile,
			KeyFile:     s.HTTPS.KeyFile,
			Logger:      s.Logger,
			certificate: nil,
			mu:          sync.RWMutex{},
			ticker:      nil,
			done:        nil,
		}

		errE := manager.Init()
		if errE != nil {
			return sites, errors.WithDetails(errE, "certFile", s.HTTPS.CertFile)
		}
		s.managers = append(s.managers, manager)

		fileGetCertificate = manager.GetCertificate

		// We have to determine domain names this certificate is valid for.
		certificate, err := manager.GetCertificate(nil)
		if err != nil {
			return sites, errors.WithDetails(err, "certFile", s.HTTPS.CertFile)
		}
		// certificate.Leaf is nil, so we have to parse leaf ourselves.
		// See: https://github.com/golang/go/issues/35504
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return sites, errors.WithDetails(err, "certFile", s.HTTPS.CertFile)
		}

		sites = map[string]SiteT{}
		if leaf.Subject.CommonName != "" && len(leaf.DNSNames) == 0 {
			st, site := newSiteT[SiteT]()
			*site = Site{
				Domain:      leaf.Subject.CommonName,
				CertFile:    "",
				KeyFile:     "",
				staticFiles: nil,
			}
			sites[leaf.Subject.CommonName] = st
			domains = append(domains, site.Domain)
		}
		for _, san := range leaf.DNSNames {
			if _, ok := sites[san]; ok {
				continue
			}
			st, site := newSiteT[SiteT]()
			*site = Site{
				Domain:      san,
				CertFile:    "",
				KeyFile:     "",
				staticFiles: nil,
			}
			sites[san] = st
			domains = append(domains, site.Domain)
		}

		if len(sites) == 0 {
			err := errors.New("certificate is not valid for any domain")
			errors.Details(err)["certFile"] = s.HTTPS.CertFile
			return sites, err
		}
	} else {
		return sites, errors.New("missing file or Let's Encrypt's certificate configuration")
	}

	if len(letsEncryptDomainsList) > 0 {
		directory := autocert.DefaultACMEDirectory
		if s.HTTPS.ACMEDirectory != "" {
			directory = s.HTTPS.ACMEDirectory
		}
		client, err := acmeClient(s.HTTPS.ACMEDirectoryRootCAs)
		if err != nil {
			return sites, err
		}
		manager := autocert.Manager{
			Prompt:      autocert.AcceptTOS,
			Cache:       autocert.DirCache(s.HTTPS.LetsEncryptCache),
			HostPolicy:  autocert.HostWhitelist(letsEncryptDomainsList...),
			RenewBefore: 0,
			Client: &acme.Client{ //nolint:exhaustruct
				DirectoryURL: directory,
				HTTPClient:   client,
			},
			Email:                  "",
			ForceRSA:               false,
			ExtraExtensions:        nil,
			ExternalAccountBinding: nil,
		}

		letsEncryptGetCertificate = manager.GetCertificate
		nextProtos = manager.TLSConfig().NextProtos
	}

	if fileGetCertificate != nil && letsEncryptGetCertificate != nil {
		httpsServer.TLSConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := fileGetCertificate(hello)
			if err != nil {
				return c, err
			} else if c != nil {
				return c, nil
			}

			return letsEncryptGetCertificate(hello)
		}
		httpsServer.TLSConfig.NextProtos = nextProtos
	} else if fileGetCertificate != nil {
		httpsServer.TLSConfig.GetCertificate = fileGetCertificate
	} else if letsEncryptGetCertificate != nil {
		httpsServer.TLSConfig.GetCertificate = letsEncryptGetCertificate
		httpsServer.TLSConfig.NextProtos = nextProtos
	} else {
		panic(errors.New("not possible"))
	}

	s.HTTPSServer = httpsServer

	sort.Strings(domains)
	s.domains = domains

	s.listenAddrHTTPS = x.NewSyncVar[string]()
	s.listenAddrHTTP = x.NewSyncVar[string]()

	if s.HTTP.Listen != "" {
		// TODO: Add limits on max idle time and min speed for writing the whole response.
		//       If a limit is reached, context should be canceled.
		//       See: https://github.com/golang/go/issues/16100
		//       See: https://github.com/golang/go/issues/21389
		//       See: https://github.com/golang/go/issues/59602
		s.HTTPServer = &http.Server{ //nolint:exhaustruct
			Addr:                         s.HTTP.Listen,
			Handler:                      s.newHTTPRedirectHandler(),
			DisableGeneralOptionsHandler: false,
			TLSConfig:                    nil,
			ReadTimeout:                  0,
			ReadHeaderTimeout:            readHeaderTimeout,
			WriteTimeout:                 0,
			IdleTimeout:                  idleTimeout,
			MaxHeaderBytes:               0,
			ErrorLog:                     log.New(s.Logger, "", 0),
			BaseContext: func(l net.Listener) context.Context {
				errE := s.listenAddrHTTP.Store(l.Addr().String())
				if errE != nil {
					panic(errE)
				}
				return context.Background()
			},
			ConnContext: nil,
		}
	} else {
		s.HTTPServer = nil
		// This cannot error.
		_ = s.listenAddrHTTP.Store("")
	}

	return sites, nil
}

// ProxyToInDevelopment returns ProxyTo base URL if Development is true.
// Otherwise it returns an empty string.
func (s *Server[SiteT]) ProxyToInDevelopment() string {
	proxyTo := s.ProxyTo
	if !s.Development {
		proxyTo = ""
	}
	return proxyTo
}

// Run runs the server serving requests using the provided handler.
//
// It returns only on error or if the server is gracefully shut down
// when the context is canceled.
func (s *Server[SiteT]) Run(ctx context.Context, httpsHandler http.Handler) errors.E {
	if s.HTTPSServer == nil {
		return errors.New("server not configured")
	}
	if s.HTTPSServer.Handler != nil {
		return errors.New("run already called")
	}
	s.HTTPSServer.Handler = httpsHandler

	for _, manager := range s.managers {
		err := manager.Start()
		if err != nil {
			return err
		}
		// We use defer here and not s.server.RegisterOnShutdown so that
		// manager is stopped also on errors and not only at clean shutdown.
		defer manager.Stop()
	}

	g, errCtx := errgroup.WithContext(ctx)

	g.Go(func() error {
		c, cancel := context.WithCancel(errCtx)
		go func() {
			addr, err := s.listenAddrHTTPS.LoadContext(c)
			if err != nil {
				// Context is cancelled, we just return.
				return
			}

			s.Logger.Info().Str("listenAddr", addr).Strs("domains", s.domains).Msg("HTTPS server starting")
		}()

		// If ListenAndServeTLS returns we return from this goroutine and cancel
		// the context which in turn gets the goroutine above to exit.
		defer cancel()

		// We make sure we store something to unblock everyone waiting on the address.
		// This might return an error if the value is already stored, but we ignore it.
		defer s.listenAddrHTTPS.Store("") //nolint:errcheck

		err := s.HTTPSServer.ListenAndServeTLS("", "")
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return errors.WithStack(err)
		}

		return nil
	})

	g.Go(func() error {
		<-errCtx.Done()

		// Parent context was not canceled (is nil) or the error is different,
		// which both means the server's goroutine exited with an error.
		// We do not have to do anything.
		if ctx.Err() != errCtx.Err() { //nolint:errorlint,err113
			return nil
		}

		s.Logger.Info().Msg("HTTPS server stopping")

		// We wait indefinitely for the server to shut down cleanly.
		// The whole process will be killed anyway if we wait too long.
		return errors.WithStack(s.HTTPSServer.Shutdown(context.Background())) //nolint:contextcheck
	})

	if s.HTTPServer != nil {
		g.Go(func() error {
			c, cancel := context.WithCancel(errCtx)
			go func() {
				addr, err := s.listenAddrHTTP.LoadContext(c)
				if err != nil {
					// Context is cancelled, we just return.
					return
				}

				s.Logger.Info().Str("listenAddr", addr).Strs("domains", s.domains).Msg("HTTP server starting")
			}()

			// If ListenAndServe returns we return from this goroutine and cancel
			// the context which in turn gets the goroutine above to exit.
			defer cancel()

			// We make sure we store something to unblock everyone waiting on the address.
			// This might return an error if the value is already stored, but we ignore it.
			defer s.listenAddrHTTP.Store("") //nolint:errcheck

			err := s.HTTPServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				return errors.WithStack(err)
			}

			return nil
		})

		g.Go(func() error {
			<-errCtx.Done()

			// Parent context was not canceled (is nil) or the error is different,
			// which both means the server's goroutine exited with an error.
			// We do not have to do anything.
			if ctx.Err() != errCtx.Err() { //nolint:errorlint,err113
				return nil
			}

			s.Logger.Info().Msg("HTTP server stopping")

			// We wait indefinitely for the server to shut down cleanly.
			// The whole process will be killed anyway if we wait too long.
			return errors.WithStack(s.HTTPServer.Shutdown(context.Background())) //nolint:contextcheck
		})
	}

	return errors.WithStack(g.Wait())
}

func (s *Server[SiteT]) connContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connectionIDContextKey, identifier.New())
}

// ListenAddrHTTPS returns the address on which the HTTPS server is listening.
//
// Available only after the server runs. It blocks until the server runs
// if called before. If server fails to start before the address is obtained,
// it unblocks and returns an empty string.
func (s *Server[SiteT]) ListenAddrHTTPS() string {
	return s.listenAddrHTTPS.Load()
}

// ListenAddrHTTP returns the address on which the HTTP server is listening.
//
// Available only after the server runs. It blocks until the server runs
// if called before. If server fails to start before the address is obtained,
// it unblocks and returns an empty string. If HTTP server is not enabled,
// it returns an empty string.
func (s *Server[SiteT]) ListenAddrHTTP() string {
	return s.listenAddrHTTP.Load()
}

func (s *Server[SiteT]) httpRedirectHandler(w http.ResponseWriter, req *http.Request) {
	ctx := req.Context()

	defer func() {
		if err := recover(); err != nil {
			canonicalLoggerWithPanic(ctx, err)
			Error(w, req, http.StatusInternalServerError)
		}
	}()

	if req.Body != nil {
		io.Copy(io.Discard, req.Body) //nolint:errcheck,gosec
		req.Body.Close()              //nolint:errcheck,gosec
	}

	host, errE := getHost(req.Host)
	if errE != nil {
		canonicalLoggerWithError(ctx, errors.WithMessage(errE, "unable to get host"))
		Error(w, req, http.StatusNotFound)
		return
	} else if !slices.Contains(s.domains, host) {
		canonicalLoggerWithError(ctx, errors.New("host not found in domains"))
		Error(w, req, http.StatusNotFound)
		return
	}

	externalPort := strconv.Itoa(s.HTTPS.ExternalPort)

	// If port is not explicitly provided.
	if externalPort == "0" {
		_, port, err := net.SplitHostPort(s.HTTPS.Listen)
		if err != nil {
			canonicalLoggerWithError(ctx, errors.WithMessage(err, "unable to split host port"))
			Error(w, req, http.StatusInternalServerError)
			return
		} else if port == "" {
			canonicalLoggerWithError(ctx, errors.New("port empty"))
			Error(w, req, http.StatusInternalServerError)
			return
		}
		externalPort = port
	}

	// If port is not known in advance.
	if externalPort == "0" {
		_, port, err := net.SplitHostPort(s.ListenAddrHTTPS())
		if err != nil {
			canonicalLoggerWithError(ctx, errors.WithMessage(err, "unable to split host port"))
			Error(w, req, http.StatusInternalServerError)
			return
		} else if port == "" {
			canonicalLoggerWithError(ctx, errors.New("port empty"))
			Error(w, req, http.StatusInternalServerError)
			return
		}
		externalPort = port
	}

	if externalPort != "443" {
		host = net.JoinHostPort(host, externalPort)
	}

	req.URL.Scheme = "https"
	req.URL.Host = host

	w.Header().Set("Cache-Control", "max-age=31536000")
	http.Redirect(w, req, req.URL.String(), http.StatusPermanentRedirect)
}

func (s *Server[SiteT]) newHTTPRedirectHandler() http.Handler {
	// We use global logger as canonical logger here.
	c := newMiddlewareStack(s.Logger, "")

	h := http.HandlerFunc(s.httpRedirectHandler)
	h = logHandlerFuncName("HTTP2HTTPSRedirect", h)

	return c.Then(h)
}
