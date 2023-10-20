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

type certificateManager struct {
	CertFile    string
	KeyFile     string
	Logger      zerolog.Logger
	certificate *tls.Certificate
	mu          sync.RWMutex
	ticker      *time.Ticker
	done        chan bool
}

func (c *certificateManager) Start() errors.E {
	err := c.reloadCertificate()
	if err != nil {
		return err
	}
	c.ticker = time.NewTicker(certificateReloadInterval)
	c.done = make(chan bool)
	go func() {
		for {
			select {
			case <-c.done:
				return
			case <-c.ticker.C:
				err := c.reloadCertificate()
				if err != nil {
					c.Logger.Error().Err(err).Str("certFile", c.CertFile).Str("keyFile", c.KeyFile).Send()
				}
			}
		}
	}()
	return nil
}

func (c *certificateManager) reloadCertificate() errors.E {
	certificate, err := tls.LoadX509KeyPair(c.CertFile, c.KeyFile)
	if err != nil {
		return errors.WithStack(err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.certificate = &certificate
	return nil
}

func (c *certificateManager) Stop() {
	c.ticker.Stop()
	c.done <- true
}

func (c *certificateManager) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.certificate, nil
}
