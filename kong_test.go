package waf

import (
	"bytes"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestKong(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}

	var config Server[*testSite]
	k, err := kong.New(&config,
		kong.Writers(
			buf,
			buf,
		),
		kong.Vars{
			"defaultProxyTo":  "http://localhost:3000",
			"defaultTLSCache": "letsencrypt",
			"defaultTitle":    "test",
		},
	)
	require.NoError(t, err)
	ctx, err := k.Parse([]string{})
	require.NoError(t, err)
	err = kong.DefaultHelpPrinter(kong.HelpOptions{}, ctx)
	assert.NoError(t, err)
	assert.Equal(t, `Usage: waf.test

Flags:
  -h, --help            Show context-sensitive help.
  -d, --development     Run in development mode and proxy unknown requests.
  -P, --proxy-to=URL    Base URL to proxy to in development mode. Default:
                        http://localhost:3000.

File certificate:
  -k, --tls.cert=PATH    Default certificate for TLS, when not using Let's
                         Encrypt.
  -K, --tls.key=PATH     Default certificate's private key, when not using Let's
                         Encrypt.

Let's Encrypt:
  -D, --tls.domain=STRING    Domain name to request for Let's Encrypt's
                             certificate when sites are not configured.
  -E, --tls.email=STRING     Contact e-mail to use with Let's Encrypt.
  -C, --tls.cache=PATH       Let's Encrypt's cache directory. Default:
                             letsencrypt.

Sites:
  -T, --title=NAME    Title to be shown to the users when sites are not
                      configured. Default: test.
`, buf.String())
}
