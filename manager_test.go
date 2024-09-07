package waf

import (
	"path/filepath"
	"testing"

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
