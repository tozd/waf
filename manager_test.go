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
)

func createTempCertificateFiles(certPath, keyPath string) error {
	// Generate a new ECDSA private key.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	// Create a self-signed certificate.
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(24 * time.Hour), // Set an expiration time.
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return err
	}

	// Write the certificate to a file.
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return err
	}

	// Write the private key to a file.
	keyFile, err := os.Create(keyPath)
	if err != nil {
		return err
	}
	defer keyFile.Close()
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}

	err = pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	if err != nil {
		return err
	}

	return nil
}

func TestCertificateManager(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "test_cert.pem")
	keyPath := filepath.Join(tempDir, "test_key.pem")

	err := createTempCertificateFiles(certPath, keyPath)
	require.NoError(t, err)

	certManager := certificateManager{
		CertFile: certPath,
		KeyFile:  keyPath,
		Logger:   zerolog.Nop(),
	}

	errE := certManager.Start()
	require.NoError(t, errE)
	t.Cleanup(certManager.Stop)

	cert, err := certManager.GetCertificate(nil)
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	errE = certManager.reloadCertificate()
	assert.NoError(t, errE)

	// Simulate an error condition for reloading the certificate.
	certManager.CertFile = filepath.Join(tempDir, "non_existent_cert.pem")
	certManager.KeyFile = filepath.Join(tempDir, "non_existent_key.pem")
	errE = certManager.reloadCertificate()
	assert.Error(t, errE)
	assert.Contains(t, errE.Error(), "error loading key pair")
}
