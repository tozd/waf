package waf

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
	"gitlab.com/tozd/identifier"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/net/idna"
)

const (
	listenAddr = ":8080"
)

//nolint:lll
type Server struct {
	Logger zerolog.Logger `kong:"-" yaml:"-"`

	Development bool   `help:"Run in development mode and proxy unknown requests." short:"d"                                                                    yaml:"development"`
	ProxyTo     string `default:"${defaultProxyTo}"                                help:"Base URL to proxy to in development mode. Default: ${defaultProxyTo}." placeholder:"URL"  short:"P" yaml:"proxyTo"`
	TLS         struct {
		CertFile string `group:"File certificate:"    help:"Default  certificate for TLS, when not using Let's Encrypt."                           name:"cert"                                                          placeholder:"PATH" short:"k"     type:"existingfile" yaml:"cert"`
		KeyFile  string `group:"File certificate:"    help:"Default certificate's private key, when not using Let's Encrypt."                      name:"key"                                                           placeholder:"PATH" short:"K"     type:"existingfile" yaml:"key"`
		Domain   string `group:"Let's Encrypt:"       help:"Domain name to request for Let's Encrypt's certificate when sites are not configured." placeholder:"STRING"                                                 short:"D"          yaml:"domain"`
		Email    string `group:"Let's Encrypt:"       help:"Contact e-mail to use with Let's Encrypt."                                             short:"E"                                                            yaml:"email"`
		Cache    string `default:"${defaultTLSCache}" group:"Let's Encrypt:"                                                                       help:"Let's Encrypt's cache directory. Default: ${defaultTLSCache}." placeholder:"PATH" short:"C"     type:"path"         yaml:"cache"`
	} `embed:"" prefix:"tls." yaml:"tls"`
	Title string `default:"${defaultTitle}" group:"Sites:" help:"Title to be shown to the users when sites are not configured. Default: ${defaultTitle}." placeholder:"NAME" short:"T" yaml:"title"`
}

func validForDomain(manager *certificateManager, domain string) (bool, errors.E) {
	certificate, err := manager.GetCertificate(nil)
	if err != nil {
		return false, errors.WithStack(err)
	}
	// certificate.Leaf is nil, so we have to parse leaf ourselves.
	// See: https://github.com/golang/go/issues/35504
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return false, errors.WithStack(err)
	}

	found := false
	if leaf.Subject.CommonName != "" && len(leaf.DNSNames) == 0 {
		found = leaf.Subject.CommonName == domain
	}
	for _, san := range leaf.DNSNames {
		if san == domain {
			found = true
			break
		}
	}

	return found, nil
}

func (s *Server) Run(router *Router, service *Service) errors.E { //nolint:maintidx
	var fileGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	var letsEncryptGetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	letsEncryptDomainsList := []string{}

	if len(service.Sites) > 0 { //nolint:nestif
		fileGetCertificateFunctions := map[string]func(*tls.ClientHelloInfo) (*tls.Certificate, error){}

		for domain, site := range service.Sites {
			if site.Domain == "" {
				return errors.Errorf(`site's domain is required`)
			}
			if domain != site.Domain {
				return errors.Errorf(`domain "%s" does not match site's domain "%s"`, domain, site.Domain)
			}

			if site.CertFile != "" && site.KeyFile != "" {
				manager := certificateManager{
					CertFile: site.CertFile,
					KeyFile:  site.KeyFile,
					Logger:   s.Logger,
				}

				err := manager.Start()
				if err != nil {
					return err
				}
				defer manager.Stop()

				fileGetCertificateFunctions[site.Domain] = manager.GetCertificate

				ok, err := validForDomain(&manager, site.Domain)
				if err != nil {
					return err
				}
				if !ok {
					return errors.Errorf(`certificate "%s" is not valid for domain "%s"`, site.CertFile, site.Domain)
				}
			} else if s.TLS.Email != "" && s.TLS.Cache != "" {
				letsEncryptDomainsList = append(letsEncryptDomainsList, site.Domain)
			} else if s.TLS.CertFile != "" && s.TLS.KeyFile != "" {
				manager := certificateManager{
					CertFile: s.TLS.CertFile,
					KeyFile:  s.TLS.KeyFile,
					Logger:   s.Logger,
				}

				err := manager.Start()
				if err != nil {
					return err
				}
				defer manager.Stop()

				fileGetCertificateFunctions[site.Domain] = manager.GetCertificate

				ok, err := validForDomain(&manager, site.Domain)
				if err != nil {
					return err
				}
				if !ok {
					return errors.Errorf(`certificate "%s" is not valid for domain "%s"`, site.CertFile, site.Domain)
				}
			} else {
				return errors.Errorf(`missing file or Let's Encrypt's certificate configuration for site "%s"`, site.Domain)
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
					return nil, errors.Errorf(`server name contains invalid character: %s`, hello.ServerName)
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

		service.Sites = map[string]Site{
			s.TLS.Domain: {
				Domain: s.TLS.Domain,
				Title:  s.Title,
			},
		}
	} else if s.TLS.CertFile != "" && s.TLS.KeyFile != "" {
		manager := certificateManager{
			CertFile: s.TLS.CertFile,
			KeyFile:  s.TLS.KeyFile,
			Logger:   s.Logger,
		}

		errE := manager.Start()
		if errE != nil {
			return errE
		}
		defer manager.Stop()

		fileGetCertificate = manager.GetCertificate

		// We have to determine domain names this certificate is valid for.
		certificate, err := manager.GetCertificate(nil)
		if err != nil {
			return errors.WithStack(err)
		}
		// certificate.Leaf is nil, so we have to parse leaf ourselves.
		// See: https://github.com/golang/go/issues/35504
		leaf, err := x509.ParseCertificate(certificate.Certificate[0])
		if err != nil {
			return errors.WithStack(err)
		}

		service.Sites = map[string]Site{}
		if leaf.Subject.CommonName != "" && len(leaf.DNSNames) == 0 {
			service.Sites[leaf.Subject.CommonName] = Site{
				Domain: leaf.Subject.CommonName,
				Title:  s.Title,
			}
		}
		for _, san := range leaf.DNSNames {
			service.Sites[san] = Site{
				Domain: san,
				Title:  s.Title,
			}
		}

		if len(service.Sites) == 0 {
			return errors.Errorf(`certificate "%s" is not valid for any domain`, s.TLS.CertFile)
		}
	} else {
		return errors.New("missing file or Let's Encrypt's certificate configuration")
	}

	if len(letsEncryptDomainsList) > 0 {
		manager := autocert.Manager{
			Cache:      autocert.DirCache(s.TLS.Cache),
			Prompt:     autocert.AcceptTOS,
			Email:      s.TLS.Email,
			HostPolicy: autocert.HostWhitelist(letsEncryptDomainsList...),
		}

		letsEncryptGetCertificate = manager.GetCertificate
	}

	development := s.ProxyTo
	if !s.Development {
		development = ""
	}

	handler, err := service.RouteWith(router, development)
	if err != nil {
		return err
	}

	// TODO: Implement graceful shutdown.
	// TODO: Add request timeouts so that malicious client cannot make too slow requests or read too slowly the response.
	//       Currently this is not possible, because ReadTimeout and WriteTimeout count in handler processing time as well.
	//       Moreover, when they timeout, they do not cancel the handler itself. See: https://github.com/golang/go/issues/16100
	server := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ErrorLog:          log.New(s.Logger, "", 0),
		ConnContext:       s.connContext,
		ReadHeaderTimeout: time.Minute,
		TLSConfig: &tls.Config{
			MinVersion:       tls.VersionTLS12,
			CurvePreferences: []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
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
		},
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
		server.TLSConfig.NextProtos = []string{"h2", "http/1.1", acme.ALPNProto}
	} else if fileGetCertificate != nil {
		server.TLSConfig.GetCertificate = fileGetCertificate
	} else if letsEncryptGetCertificate != nil {
		server.TLSConfig.GetCertificate = letsEncryptGetCertificate
		server.TLSConfig.NextProtos = []string{"h2", "http/1.1", acme.ALPNProto}
	} else {
		panic(errors.New("no GetCertificate"))
	}

	s.Logger.Info().Msgf("starting on %s", listenAddr)

	return errors.WithStack(server.ListenAndServeTLS("", ""))
}

func (s *Server) connContext(ctx context.Context, _ net.Conn) context.Context {
	return context.WithValue(ctx, connectionIDContextKey, identifier.New())
}
