package waf

import (
	"crypto/tls"
	"sync"
	"time"

	"github.com/rs/zerolog"
	"gitlab.com/tozd/go/errors"
)

const (
	certificateReloadInterval = 24 * time.Hour
)

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

func (c *certificateManager) Configure() errors.E {
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
