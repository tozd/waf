package waf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"sort"
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
	defaultListenAddr = ":8080"
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 10 * time.Minute
)

// TLS configuration used by the server.
//
//nolint:lll
type TLS struct {
	// Default certificate for TLS, when not using Let's Encrypt.
	CertFile string `group:"File certificate:" help:"Default certificate for TLS, when not using Let's Encrypt. In PEM format." name:"cert" placeholder:"PATH" short:"k" type:"existingfile" yaml:"cert"`

	// Default certificate's private key, when not using Let's Encrypt.
	KeyFile string `group:"File certificate:" help:"Default certificate's private key, when not using Let's Encrypt. In PEM format." name:"key" placeholder:"PATH" short:"K" type:"existingfile" yaml:"key"`

	// Contact e-mail to use with Let's Encrypt.
	Email string `group:"Let's Encrypt:" help:"Contact e-mail to use with Let's Encrypt." short:"E" yaml:"email"`

	// Let's Encrypt's cache directory.
	Cache string `default:"${defaultTLSCache}" group:"Let's Encrypt:" help:"Let's Encrypt's cache directory." placeholder:"PATH" short:"C" type:"path" yaml:"cache"`

	// Used primarily for testing.
	ACMEDirectory        string `json:"-" kong:"-" yaml:"-"`
	ACMEDirectoryRootCAs string `json:"-" kong:"-" yaml:"-"`
}

// Validate is used by Kong to validate the struct.
func (t *TLS) Validate() error {
	if t.CertFile != "" || t.KeyFile != "" {
		if t.CertFile == "" {
			return errors.New("missing file certificate for provided private key")
		}
		if t.KeyFile == "" {
			return errors.New("missing file certificate's matching private key")
		}
	}

	if t.Email != "" && t.Cache == "" {
		return errors.New("cache directory is required for Let's Encrypt's certificate")
	}

	return nil
}

// Server listens to HTTP/1.1 and HTTP2 requests on TLS enabled port 8080 and
// serves requests using the provided handler. Server is production ready and
// can be exposed directly on open Internet.
//
// Certificates for TLS can be provided as files (which are daily reread to allow updating them)
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

	// TLS configuration.
	TLS TLS `embed:"" prefix:"tls." yaml:"tls"`

	// Exposed primarily for use in tests.
	Addr string `json:"-" kong:"-" yaml:"-"`

	// Exposed primarily for use in tests.
	HTTPServer *http.Server `json:"-" kong:"-" yaml:"-"`

	// Autocert managers do not have to be stopped, but certificate managers do.
	managers []*certificateManager

	domains []string

	listenAddr *x.SyncVar[string]
}

// Init determines the set of sites based on TLS configuration and sites provided,
// returning possibly updated and expanded set of sites.
//
// If sites parameter is empty, sites are determined from domain names found in TLS
// certificates. If sites are provided and TLS certificates are not, their domains
// are used to obtain the necessary certificate from Let's Encrypt.
//
// Key in sites map must match site's domain.
func (s *Server[SiteT]) Init(sites map[string]SiteT) (map[string]SiteT, errors.E) { //nolint:maintidx
	if s.Addr == "" {
		s.Addr = defaultListenAddr
	}

	// TODO: How to shutdown websocket connections?

	// TODO: Add limits on max idle time and min speed for writing the whole response.
	//       If a limit is reached, context should be canceled.
	//       See: https://github.com/golang/go/issues/16100
	//       See: https://github.com/golang/go/issues/21389
	//       See: https://github.com/golang/go/issues/59602
	server := &http.Server{ //nolint:exhaustruct
		Addr:                         s.Addr,
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
			errE := s.listenAddr.Store(l.Addr().String())
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
			} else if s.TLS.Email != "" && s.TLS.Cache != "" {
				letsEncryptDomainsList = append(letsEncryptDomainsList, site.Domain)
			} else if s.TLS.CertFile != "" && s.TLS.KeyFile != "" {
				manager := &certificateManager{
					CertFile:    s.TLS.CertFile,
					KeyFile:     s.TLS.KeyFile,
					Logger:      s.Logger,
					certificate: nil,
					mu:          sync.RWMutex{},
					ticker:      nil,
					done:        nil,
				}

				err := manager.Init()
				if err != nil {
					return sites, errors.WithDetails(err, "certFile", s.TLS.CertFile, "domain", site.Domain)
				}
				s.managers = append(s.managers, manager)

				fileGetCertificateFunctions[site.Domain] = manager.GetCertificate

				err = manager.ValidForDomain(site.Domain)
				if err != nil {
					return sites, errors.WithDetails(err, "certFile", s.TLS.CertFile)
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
	} else if s.TLS.CertFile != "" && s.TLS.KeyFile != "" {
		manager := &certificateManager{
			CertFile:    s.TLS.CertFile,
			KeyFile:     s.TLS.KeyFile,
			Logger:      s.Logger,
			certificate: nil,
			mu:          sync.RWMutex{},
			ticker:      nil,
			done:        nil,
		}

		errE := manager.Init()
		if errE != nil {
			return sites, errors.WithDetails(errE, "certFile", s.TLS.CertFile)
		}
		s.managers = append(s.managers, manager)

		fileGetCertificate = manager.GetCertificate

		// We have to determine domain names this certificate is valid for.
		certificate, err := manager.GetCertificate(nil)
		if err != nil {
			return sites, errors.WithDetails(err, "certFile", s.TLS.CertFile)
		}
		// certificate.Leaf is nil, so we have to parse leaf ourselves.
		// See: https://github.com/golang/go/issues/35504
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return sites, errors.WithDetails(err, "certFile", s.TLS.CertFile)
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
			errors.Details(err)["certFile"] = s.TLS.CertFile
			return sites, err
		}
	} else {
		return sites, errors.New("missing file or Let's Encrypt's certificate configuration")
	}

	if len(letsEncryptDomainsList) > 0 {
		directory := autocert.DefaultACMEDirectory
		if s.TLS.ACMEDirectory != "" {
			directory = s.TLS.ACMEDirectory
		}
		client, err := acmeClient(s.TLS.ACMEDirectoryRootCAs)
		if err != nil {
			return sites, err
		}
		manager := autocert.Manager{
			Prompt:      autocert.AcceptTOS,
			Cache:       autocert.DirCache(s.TLS.Cache),
			HostPolicy:  autocert.HostWhitelist(letsEncryptDomainsList...),
			RenewBefore: 0,
			Client: &acme.Client{ //nolint:exhaustruct
				DirectoryURL: directory,
				HTTPClient:   client,
			},
			Email:                  s.TLS.Email,
			ForceRSA:               false,
			ExtraExtensions:        nil,
			ExternalAccountBinding: nil,
		}

		letsEncryptGetCertificate = manager.GetCertificate
		nextProtos = manager.TLSConfig().NextProtos
	}

	if fileGetCertificate != nil && letsEncryptGetCertificate != nil {
		server.TLSConfig.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := fileGetCertificate(hello)
			if err != nil {
				return c, err
			} else if c != nil {
				return c, nil
			}

			return letsEncryptGetCertificate(hello)
		}
		server.TLSConfig.NextProtos = nextProtos
	} else if fileGetCertificate != nil {
		server.TLSConfig.GetCertificate = fileGetCertificate
	} else if letsEncryptGetCertificate != nil {
		server.TLSConfig.GetCertificate = letsEncryptGetCertificate
		server.TLSConfig.NextProtos = nextProtos
	} else {
		panic(errors.New("not possible"))
	}

	s.HTTPServer = server

	sort.Strings(domains)
	s.domains = domains

	s.listenAddr = x.NewSyncVar[string]()

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
func (s *Server[SiteT]) Run(ctx context.Context, handler http.Handler) errors.E {
	if s.HTTPServer == nil {
		return errors.New("server not configured")
	}
	if s.HTTPServer.Handler != nil {
		return errors.New("run already called")
	}
	s.HTTPServer.Handler = handler

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
			addr, err := s.listenAddr.LoadContext(c)
			if err != nil {
				// Context is cancelled, we just return.
				return
			}

			s.Logger.Info().Str("listenAddr", addr).Strs("domains", s.domains).Msg("server starting")
		}()

		// If ListenAndServeTLS returns we return from this goroutine and cancel
		// the context which in turn gets the goroutine above to exit.
		defer cancel()

		// We make sure we store something to unblock everyone waiting on the address.
		// This might return an error if the value is already stored, but we ignore it.
		defer s.listenAddr.Store("") //nolint:errcheck

		err := s.HTTPServer.ListenAndServeTLS("", "")
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

		s.Logger.Info().Msg("server stopping")

		// We wait indefinitely for the server to shut down cleanly.
		// The whole process will be killed anyway if we wait too long.
		return errors.WithStack(s.HTTPServer.Shutdown(context.Background())) //nolint:contextcheck
	})

	return errors.WithStack(g.Wait())
}

func (s *Server[SiteT]) connContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connectionIDContextKey, identifier.New())
}

// ListenAddr returns the address on which the server is listening.
//
// Available only after the server runs. It blocks until the server runs
// if called before. If server fails to start before the address is obtained,
// it unblocks and returns an empty string.
func (s *Server[SiteT]) ListenAddr() string {
	return s.listenAddr.Load()
}
