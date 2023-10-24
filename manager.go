package waf

import (
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
)

const (
	certificateReloadInterval = 24 * time.Hour
)

var errCertificateNotValid = errors.Base("certificate is not valid for domain")

// certificateManager loads certificate and key from file paths and reloads them
// daily. So if certificate is rotated at least a day before expiration,
// a new certificate will be picked up automatically.
type certificateManager struct {
	CertFile    string
	KeyFile     string
	Logger      zerolog.Logger
	certificate *tls.Certificate
	mu          sync.RWMutex
	ticker      *time.Ticker
	done        chan struct{}
}

func (c *certificateManager) Init() errors.E {
	return c.reloadCertificate()
}

func (c *certificateManager) Start() errors.E {
	if c.certificate == nil {
		return errors.New("manager not configured")
	}
	c.ticker = time.NewTicker(certificateReloadInterval)
	c.done = make(chan struct{})
	go func(d chan struct{}) {
		for {
			select {
			case <-d:
				return
			case <-c.ticker.C:
				err := c.reloadCertificate()
				if err != nil {
					c.Logger.Error().Err(err).Str("certFile", c.CertFile).Str("keyFile", c.KeyFile).Send()
				}
			}
		}
	}(c.done) // We make a copy of c.done so that we can nil c.done in Close in this goroutine.
	return nil
}

func (c *certificateManager) reloadCertificate() errors.E {
	certificate, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		errE := errors.WithMessage(err, "error loading key pair")
		errors.Details(errE)["certFile"] = c.CertFile
		errors.Details(errE)["keyFile"] = c.KeyFile
		return errE
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certificate = &certificate
	return nil
}

func (c *certificateManager) Stop() {
	c.ticker.Stop()
	if c.done != nil {
		close(c.done)
		c.done = nil
	}
}

func (c *certificateManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.certificate, nil
}

func (c *certificateManager) ValidForDomain(domain string) errors.E {
	certificate, err := c.GetCertificate(nil)
	if err != nil {
		return errors.WithStack(err)
	}
	// certificate.Leaf is nil, so we have to parse leaf ourselves.
	// See: https://github.com/golang/go/issues/35504
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return errors.WithStack(err)
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

	if !found {
		return errors.WithDetails(errCertificateNotValid, "domain", domain)
	}

	return nil
}
