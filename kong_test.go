package waf

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/x"
	"gopkg.in/yaml.v3"
)

type configTest struct {
	Server[*testSite]

	Title string `default:"${defaultTitle}" group:"Sites:" help:"Title to be shown to the users when sites are not configured. Default: ${defaultTitle}." placeholder:"NAME" short:"T" yaml:"title"`
}

func TestKong(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}

	var config configTest
	k, err := kong.New(&config,
		kong.Writers(
			buf,
			buf,
		),
		kong.Vars{
			"defaultProxyTo":      "http://localhost:5173",
			"defaultTLSCache":     "letsencrypt",
			"defaultTitle":        "test",
			"developmentModeHelp": " Proxy unknown requests.",
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
  -D, --development     Run in development mode. Proxy unknown requests.
  -P, --proxy-to=URL    Base URL to proxy to in development mode. Default:
                        http://localhost:5173.

File certificate:
  -k, --tls.cert=PATH    Default certificate for TLS, when not using Let's
                         Encrypt.
  -K, --tls.key=PATH     Default certificate's private key, when not using Let's
                         Encrypt.

Let's Encrypt:
  -E, --tls.email=STRING    Contact e-mail to use with Let's Encrypt.
  -C, --tls.cache=PATH      Let's Encrypt's cache directory. Default:
                            letsencrypt.

Sites:
  -T, --title=NAME    Title to be shown to the users when sites are not
                      configured. Default: test.
`, buf.String())
}

func TestConfig(t *testing.T) {
	t.Parallel()

	config := `{"title":"test","description":"desc","domain":"example.com"}`

	decoder := yaml.NewDecoder(strings.NewReader(config))
	decoder.KnownFields(true)
	var site testSite
	err := decoder.Decode(&site)
	assert.NoError(t, err)
	assert.Equal(t, "test", site.Title)
	assert.Equal(t, "desc", site.Description)
	assert.Equal(t, "example.com", site.Domain)

	site = testSite{}
	errE := x.UnmarshalWithoutUnknownFields([]byte(config), &site)
	assert.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "test", site.Title)
	assert.Equal(t, "desc", site.Description)
	assert.Equal(t, "example.com", site.Domain)
}
