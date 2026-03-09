package waf

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
)

func TestCertificateManager(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test_cert.pem")
	keyPath := filepath.Join(tempDir, "test_key.pem")

	errE := x.CreateTempCertificateFiles(certPath, keyPath, []string{"example.com"})
	require.NoError(t, errE)

	errE = (&certificateManager{}).Start()
	assert.EqualError(t, errE, "manager not configured")

	certManager := certificateManager{
		CertFile: certPath,
		KeyFile:  keyPath,
		Logger:   zerolog.Nop(),
	}

	errE = certManager.Init()
	require.NoError(t, errE, "% -+#.1v", errE)

	cert, err := certManager.GetCertificate(nil)
	require.NoError(t, err)
	assert.NotNil(t, cert)

	errE = certManager.ValidForDomain("example.com")
	assert.NoError(t, errE, "% -+#.1v", errE) //nolint:testifylint

	errE = certManager.ValidForDomain("")
	assert.ErrorIs(t, errE, errCertificateNotValid)

	errE = certManager.ValidForDomain("something.com")
	assert.ErrorIs(t, errE, errCertificateNotValid)

	errE = certManager.Start()
	require.NoError(t, errE, "% -+#.1v", errE)
	t.Cleanup(certManager.Stop)

	cert, err = certManager.GetCertificate(nil)
	require.NoError(t, err)
	assert.NotNil(t, cert)

	errE = certManager.reloadCertificate()
	require.NoError(t, errE, "% -+#.1v", errE)

	// Simulate an error condition for reloading the certificate.
	certManager.CertFile = filepath.Join(tempDir, "non_existent_cert.pem")
	certManager.KeyFile = filepath.Join(tempDir, "non_existent_key.pem")
	errE = certManager.reloadCertificate()
	assert.ErrorContains(t, errE, "error loading key pair")
}

// createCNOnlyCert creates a self-signed certificate with CommonName but no SAN.
func createCNOnlyCert(t *testing.T, cn string) (certPath, keyPath string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		// No DNSNames — relies on CommonName only.
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	certPath = filepath.Join(tmpDir, "cn-cert.pem")
	keyPath = filepath.Join(tmpDir, "cn-key.pem")

	certFile, err := os.Create(certPath) //nolint:gosec
	require.NoError(t, err)
	require.NoError(t, pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	certFile.Close() //nolint:errcheck,gosec

	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyFile, err := os.Create(keyPath) //nolint:gosec
	require.NoError(t, err)
	require.NoError(t, pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	keyFile.Close() //nolint:errcheck,gosec

	return certPath, keyPath
}

func TestValidForDomainCommonName(t *testing.T) {
	t.Parallel()

	certPath, keyPath := createCNOnlyCert(t, "cn.example.com")

	certManager := certificateManager{
		CertFile:       certPath,
		KeyFile:        keyPath,
		Logger:         zerolog.Nop(),
		reloadInterval: time.Millisecond,
	}
	errE := certManager.Init()
	require.NoError(t, errE, "% -+#.1v", errE)

	// Verify with CommonName (no SAN) — covers the CommonName path.
	errE = certManager.ValidForDomain("cn.example.com")
	assert.NoError(t, errE, "% -+#.1v", errE) //nolint:testifylint

	// Wrong domain.
	errE = certManager.ValidForDomain("other.example.com")
	assert.ErrorIs(t, errE, errCertificateNotValid)

	// Verify that Start goroutine stop path is exercised.
	errE = certManager.Start()
	require.NoError(t, errE, "% -+#.1v", errE)
	// Delete the cert file to cause the reload goroutine to log an error,
	// covering the error log path.
	require.NoError(t, os.Remove(certPath))
	time.Sleep(10 * time.Millisecond)
	certManager.Stop()
}
