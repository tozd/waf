package waf

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gitlab.com/tozd/go/cli"
	"gitlab.com/tozd/go/x"
	"gopkg.in/yaml.v3"
)

type configTest struct {
	Server[*testSite]

	Title string `default:"${defaultTitle}" group:"Sites:" help:"Title to be shown to the users when sites are not configured." placeholder:"NAME" short:"T" yaml:"title"`
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
			"defaultListen":       ":8080",
			"defaultProxyTo":      "http://localhost:5173",
			"defaultTitle":        "test",
			"developmentModeHelp": " Proxy unknown requests.",
		},
		kong.ValueFormatter(cli.DefaultValueFormatter),
	)
	require.NoError(t, err)
	ctx, err := k.Parse([]string{})
	require.NoError(t, err)
	err = kong.DefaultHelpPrinter(kong.HelpOptions{}, ctx)
	require.NoError(t, err)
	assert.Equal(t, `Usage: waf.test [flags]

Flags:
  -h, --help            Show context-sensitive help.
  -D, --development     Run in development mode. Proxy unknown requests.
  -P, --proxy-to=URL    Base URL to proxy to in development mode. Default:
                        http://localhost:5173.

HTTPS:
  -k, --https.cert=PATH            Default certificate for HTTPS, when not using
                                   Let's Encrypt. In PEM format.
  -K, --https.key=PATH             Default certificate's private key, when not
                                   using Let's Encrypt. In PEM format.
  -C, --https.letsencrypt=PATH     Let's Encrypt's cache directory. Set it to
                                   enable Let's Encrypt.
  -L, --https.listen=HOST:PORT     TCP address for the HTTPS server to listen
                                   on. Default: :8080.
      --https.external-port=INT    Port on which HTTPS server is accessible when
                                   it is different from the port on which the
                                   HTTPS server listens.

HTTP:
  --http.listen=HOST:PORT    TCP address for the HTTP server to listen on.
                             Setting it enables HTTP redirect to HTTPS.

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
	require.NoError(t, err)
	assert.Equal(t, "test", site.Title)
	assert.Equal(t, "desc", site.Description)
	assert.Equal(t, "example.com", site.Domain)

	site = testSite{}
	errE := x.UnmarshalWithoutUnknownFields([]byte(config), &site)
	require.NoError(t, errE, "% -+#.1v", errE)
	assert.Equal(t, "test", site.Title)
	assert.Equal(t, "desc", site.Description)
	assert.Equal(t, "example.com", site.Domain)
}

func TestHTTPSValidate(t *testing.T) {
	t.Parallel()

	// No cert or key — valid.
	h := HTTPS{}
	assert.NoError(t, h.Validate())

	// Only key file — missing cert error.
	h = HTTPS{KeyFile: "key.pem"}
	assert.EqualError(t, h.Validate(), "missing file certificate for provided private key")

	// Only cert file — missing key error.
	h = HTTPS{CertFile: "cert.pem"}
	assert.EqualError(t, h.Validate(), "missing file certificate's matching private key")

	// Both cert and key — valid.
	h = HTTPS{CertFile: "cert.pem", KeyFile: "key.pem"}
	assert.NoError(t, h.Validate())

	// Both cert/key plus Let's Encrypt — conflict error.
	h = HTTPS{CertFile: "cert.pem", KeyFile: "key.pem", LetsEncryptCache: "/cache"}
	assert.EqualError(t, h.Validate(), "Let's Encrypt's cannot be enabled together with default certificate set")
}

func TestSiteValidate(t *testing.T) {
	t.Parallel()

	// No cert or key — valid.
	s := Site{Domain: "example.com"}
	assert.NoError(t, s.Validate())

	// Only key file — missing cert error.
	s = Site{Domain: "example.com", KeyFile: "key.pem"}
	assert.EqualError(t, s.Validate(), "missing file certificate for provided private key")

	// Only cert file — missing key error.
	s = Site{Domain: "example.com", CertFile: "cert.pem"}
	assert.EqualError(t, s.Validate(), "missing file certificate's matching private key")

	// Both cert and key — valid.
	s = Site{Domain: "example.com", CertFile: "cert.pem", KeyFile: "key.pem"}
	assert.NoError(t, s.Validate())
}

func TestAddStaticFileErrors(t *testing.T) {
	t.Parallel()

	site := &Site{Domain: "example.com"}
	site.initializeStaticFiles()

	// Path not starting with "/" returns an error.
	errE := site.addStaticFile("no-slash", "text/plain", []byte("data"))
	assert.EqualError(t, errE, `path does not start with "/"`)

	// Adding the same path twice returns "already exists" on the second call.
	errE = site.addStaticFile("/first", "text/plain", []byte("data"))
	require.NoError(t, errE)
	errE = site.addStaticFile("/first", "text/plain", []byte("data"))
	assert.EqualError(t, errE, "static file for path already exists")
}
