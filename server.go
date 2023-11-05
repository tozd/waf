package waf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"
	"golang.org/x/sync/errgroup"
)

const (
	listenAddr        = ":8080"
	readHeaderTimeout = 10 * time.Second
	idleTimeout       = 10 * time.Minute
)

//nolint:lll
type TLS struct {
	CertFile string `group:"File certificate:"    help:"Default  certificate for TLS, when not using Let's Encrypt."                           name:"cert"                                                          placeholder:"PATH" short:"k"     type:"existingfile" yaml:"cert"`
	KeyFile  string `group:"File certificate:"    help:"Default certificate's private key, when not using Let's Encrypt."                      name:"key"                                                           placeholder:"PATH" short:"K"     type:"existingfile" yaml:"key"`
	Domain   string `group:"Let's Encrypt:"       help:"Domain name to request for Let's Encrypt's certificate when sites are not configured." placeholder:"STRING"                                                 short:"D"          yaml:"domain"`
	Email    string `group:"Let's Encrypt:"       help:"Contact e-mail to use with Let's Encrypt."                                             short:"E"                                                            yaml:"email"`
	Cache    string `default:"${defaultTLSCache}" group:"Let's Encrypt:"                                                                       help:"Let's Encrypt's cache directory. Default: ${defaultTLSCache}." placeholder:"PATH" short:"C"     type:"path"         yaml:"cache"`

	// Used primarily for testing.
	ACMEDirectory        string `json:"-" kong:"-" yaml:"-"`
	ACMEDirectoryRootCAs string `json:"-" kong:"-" yaml:"-"`
}

//nolint:lll
type Server[SiteT hasSite] struct {
	Logger zerolog.Logger `kong:"-" yaml:"-"`

	Development bool   `help:"Run in development mode and proxy unknown requests." short:"d"                                                                    yaml:"development"`
	ProxyTo     string `default:"${defaultProxyTo}"                                help:"Base URL to proxy to in development mode. Default: ${defaultProxyTo}." placeholder:"URL"                                                                              short:"P"          yaml:"proxyTo"`
	TLS         TLS    `embed:""                                                   prefix:"tls."                                                                yaml:"tls"`
	Title       string `default:"${defaultTitle}"                                  group:"Sites:"                                                               help:"Title to be shown to the users when sites are not configured. Default: ${defaultTitle}." placeholder:"NAME" short:"T"      yaml:"title"`

	server   *http.Server
	managers []*certificateManager
}

func (s *Server[SiteT]) Init(sites map[string]SiteT) (map[string]SiteT, errors.E) { //nolint:maintidx
	// TODO: How to shutdown ACME manager?
	//       See: https://github.com/golang/go/issues/63706

	// TODO: How to shutdown websocket connections?

	// TODO: Add limits on max idle time and min speed for writing the whole response.
	//       If a limit is reached, context should be canceled.
	//       See: https://github.com/golang/go/issues/16100
	//       See: https://github.com/golang/go/issues/21389
	//       See: https://github.com/golang/go/issues/59602
	server := &http.Server{
		Addr:                         listenAddr,
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
		TLSNextProto:      nil,
		ConnState:         nil,
		ErrorLog:          log.New(s.Logger, "", 0),
		BaseContext:       nil,
		ConnContext:       s.connContext,
	}

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
	} else if s.TLS.Domain != "" && s.TLS.Email != "" && s.TLS.Cache != "" {
		letsEncryptDomainsList = append(letsEncryptDomainsList, s.TLS.Domain)

		st, site := newSiteT[SiteT]()
		*site = Site{
			Domain:   s.TLS.Domain,
			Title:    s.Title,
			CertFile: "",
			KeyFile:  "",
			files:    nil,
		}
		sites = map[string]SiteT{
			s.TLS.Domain: st,
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
				Domain:   leaf.Subject.CommonName,
				Title:    s.Title,
				CertFile: "",
				KeyFile:  "",
				files:    nil,
			}
			sites[leaf.Subject.CommonName] = st
		}
		for _, san := range leaf.DNSNames {
			st, site := newSiteT[SiteT]()
			*site = Site{
				Domain:   san,
				Title:    s.Title,
				CertFile: "",
				KeyFile:  "",
				files:    nil,
			}
			sites[san] = st
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

	s.server = server

	return sites, nil
}

func (s *Server[SiteT]) InDevelopment() string {
	development := s.ProxyTo
	if !s.Development {
		development = ""
	}
	return development
}

func (s *Server[SiteT]) Run(ctx context.Context, handler http.Handler) errors.E {
	if s.server == nil {
		return errors.New("server not configured")
	}
	if s.server.Handler != nil {
		return errors.New("run already called")
	}
	s.server.Handler = handler

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
		s.Logger.Info().Msgf("server starting on %s", listenAddr)

		err := s.server.ListenAndServeTLS("", "")
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
		if ctx.Err() != errCtx.Err() { //nolint:errorlint,goerr113
			return nil
		}

		s.Logger.Info().Msg("server stopping")

		// We wait indefinitely for the server to shut down cleanly.
		// The whole process will be killed anyway if we wait too long.
		return errors.WithStack(s.server.Shutdown(context.Background())) //nolint:contextcheck
	})

	return errors.WithStack(g.Wait())
}

func (s *Server[SiteT]) connContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connectionIDContextKey, identifier.New())
}
