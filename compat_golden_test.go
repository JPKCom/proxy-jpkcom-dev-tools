package main

// Golden test of the v1.3.0 responses (COMPAT-3 of the v1.4.0 requirements).
//
// TestCompat_Golden sends a fixed request matrix — the call patterns of the
// seven JPKCom tools (seo, dns-ssl-redirect-url, source, wysiwyg, llms,
// robots-sitemap, md) plus the error paths — to the real handlers and compares
// every response (status, headers, body) with a file under testdata/golden/.
// The files were recorded on v1.3.0 with -update; afterwards only the
// differences listed in section 4.1 of the v1.4.0 spec may change, in one
// reviewed commit of their own.
//
// /proxy, /inspect and /page run in-process against httptest targets. /ping
// and /version are inline closures in main(), so those cases (and a few
// through the full server stack, including the Host check) run against main()
// itself in a subprocess.
//
// Normalised are only values that depend on time or on the ports the test
// happens to get: the Date header (also inside JSON header maps and raw header
// blocks), X-Upstream-Timing, the JSON timing values, certificate daysLeft and
// every listener port. Everything else is compared byte for byte.
//
// Record:  go test -run TestCompat_Golden -update
// Compare: go test -run TestCompat_Golden

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

var goldenUpdate = flag.Bool("update", false, "rewrite the golden files of TestCompat_Golden")

const (
	goldenDir     = "testdata/golden"
	goldenCertPEM = "testdata/golden-tls/cert.pem"
	goldenKeyPEM  = "testdata/golden-tls/key.pem"
	goldenOrigin  = "https://test.example.com"
	goldenToken   = "test-token-abc"
	goldenMainEnv = "LOCALPROXY_GOLDEN_MAIN_ARGS"
)

// -----------------------------------------------------------------------
// Targets
// -----------------------------------------------------------------------

// goldenTargetHandler is the upstream every case talks to. All its answers
// are fixed; nothing in a response depends on time or on the port.
func goldenTargetHandler() http.Handler {
	mux := http.NewServeMux()

	// A plain page with the headers the tools look at.
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/html; charset=utf-8")
		h.Set("Cache-Control", "max-age=60")
		h.Set("X-Custom", "hello")
		h.Set("Server", "golden-target")
		h.Set("Alt-Svc", `h3=":443"; ma=86400`)
		h.Add("Set-Cookie", "a=1; Path=/; Expires=Wed, 01 Jan 2031 00:00:00 GMT")
		h.Add("Set-Cookie", "b=2; Path=/; HttpOnly")
		h.Set("Access-Control-Allow-Origin", "https://upstream.example")
		h.Set("Link", `</style.css>; rel=preload; as=style`)
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			io.WriteString(w, "<!doctype html><html><head><title>Golden</title></head><body><h1>ok</h1></body></html>\n")
		}
	})

	// One redirect, relative Location.
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/ok")
		w.WriteHeader(http.StatusFound)
	})

	// Two redirects: 301 -> /redirect -> /ok.
	mux.HandleFunc("/redirect-chain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/redirect")
		w.WriteHeader(http.StatusMovedPermanently)
	})

	// /hop/N redirects to /hop/N+1 up to 25, then answers 200: deeper than
	// both the /proxy (5) and the /page (20) limit.
	mux.HandleFunc("/hop/", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if n >= 25 {
			io.WriteString(w, "end of hops\n")
			return
		}
		w.Header().Set("Location", "/hop/"+strconv.Itoa(n+1))
		w.WriteHeader(http.StatusFound)
	})

	// Redirects back to itself.
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/loop")
		w.WriteHeader(http.StatusFound)
	})

	// Refuses HEAD with 405, as some servers do.
	mux.HandleFunc("/no-head", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			w.Header().Set("Allow", "GET")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Only-On-Get", "yes")
		io.WriteString(w, "GET only\n")
	})

	// Content negotiation as the md/llms/seo Markdown probes use it.
	mux.HandleFunc("/markdown", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Vary", "Accept")
		if strings.Contains(r.Header.Get("Accept"), "text/markdown") {
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			io.WriteString(w, "# Golden\n\nMarkdown body.\n")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, "<h1>Golden</h1>\n")
	})

	// Echoes what reached the target: method, URI, body and headers.
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"method":  r.Method,
			"uri":     r.RequestURI,
			"body":    string(body),
			"headers": r.Header,
		})
	})

	// A gzip-encoded page (body decoding, contentEncoding).
	mux.HandleFunc("/gzip", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		io.WriteString(zw, "<p>compressed golden body</p>\n")
		zw.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			w.Write(buf.Bytes())
		}
	})

	// Answers only after the proxy has given up.
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
		io.WriteString(w, "too late\n")
	})

	// Redirect to a name the test's SSRF hook blocks.
	mux.HandleFunc("/redirect-blocked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "http://blocked.test/secret")
		w.WriteHeader(http.StatusFound)
	})

	// Redirect to a scheme the proxy does not follow.
	mux.HandleFunc("/redirect-ftp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "ftp://files.example/pub/")
		w.WriteHeader(http.StatusFound)
	})

	// A target that sends the proxy's own metadata header names itself
	// (difference 6 of section 4.1).
	mux.HandleFunc("/upstream-headers", func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "text/plain; charset=utf-8")
		h.Set("X-Upstream-Location", "https://evil.example/forged")
		h.Set("X-Upstream-Final-URL", "https://evil.example/final")
		h.Set("X-Upstream-Redirects", "9")
		h.Set("X-Upstream-IP", "203.0.113.66")
		h.Set("X-Upstream-Auth", "sent")
		io.WriteString(w, "forged metadata\n")
	})

	// Reports whether Basic credentials from URL userinfo arrived
	// (difference 5 of section 4.1).
	mux.HandleFunc("/auth", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "basic=%t user=%q pass=%q\n", ok, user, pass)
	})
	mux.HandleFunc("/auth-redirect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/auth")
		w.WriteHeader(http.StatusFound)
	})

	return mux
}

// goldenTLSCert loads the fixed self-signed certificate of the TLS target.
// With -update it is created once when missing; it is committed with the
// golden files, so certificate details (serial, fingerprints, PEM) stay fixed.
func goldenTLSCert(t *testing.T) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	if _, err := os.Stat(goldenCertPEM); errors.Is(err, os.ErrNotExist) {
		if !*goldenUpdate {
			t.Fatalf("%s missing — record with -update", goldenCertPEM)
		}
		goldenWriteTLSCert(t)
	}
	pair, err := tls.LoadX509KeyPair(goldenCertPEM, goldenKeyPEM)
	if err != nil {
		t.Fatalf("load golden TLS cert: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parse golden TLS cert: %v", err)
	}
	return pair, leaf
}

func goldenWriteTLSCert(t *testing.T) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(20261027),
		Subject:               pkix.Name{CommonName: "golden.test", Organization: []string{"JPKCom Golden Test"}},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2126, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"golden.test", "localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(goldenCertPEM), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goldenCertPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(goldenKeyPEM, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// goldenEnv holds the targets, the config variants and the port names used
// for normalisation.
type goldenEnv struct {
	plain *httptest.Server
	tls   *httptest.Server
	// closed is a loopback address nothing listens on (connection_error).
	closed string
	cfgs   map[string]*config
	ports  map[string]string // port -> placeholder
}

func newGoldenEnv(t *testing.T) *goldenEnv {
	t.Helper()
	env := &goldenEnv{ports: map[string]string{}}

	env.plain = httptest.NewServer(goldenTargetHandler())
	t.Cleanup(env.plain.Close)

	pair, leaf := goldenTLSCert(t)
	env.tls = httptest.NewUnstartedServer(goldenTargetHandler())
	env.tls.Config.ErrorLog = log.New(io.Discard, "", 0) // untrusted handshakes are expected
	env.tls.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	env.tls.StartTLS()
	t.Cleanup(env.tls.Close)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	env.closed = ln.Addr().String()
	ln.Close()

	env.ports[serverPort(t, env.plain)] = "<plain-port>"
	env.ports[serverPort(t, env.tls)] = "<tls-port>"
	_, closedPort, _ := net.SplitHostPort(env.closed)
	env.ports[closedPort] = "<closed-port>"

	roots := x509.NewCertPool()
	roots.AddCert(leaf)

	base := func() *config {
		return &config{
			allowedOrigins:   []string{goldenOrigin},
			sessionToken:     goldenToken,
			requestTimeout:   10 * time.Second,
			maxResponseBytes: 1 * 1024 * 1024,
		}
	}

	// main: loopback targets reachable, only "blocked.test" fails the
	// pre-check, the TLS target is trusted.
	mainCfg := base()
	mainCfg.ssrfCheck = func(host string) bool { return host == "blocked.test" }
	mainCfg.dialControl = allowAllDial
	mainCfg.rootCAs = roots

	// strict: no test hooks at all — the production pre-check and dialer.
	strict := base()

	// dialer: pre-check off, production dialer — the dialer blocks loopback.
	dialer := base()
	dialer.ssrfCheck = func(string) bool { return false }

	// untrusted: like main, but an empty trust store (tls_error).
	untrusted := base()
	untrusted.ssrfCheck = mainCfg.ssrfCheck
	untrusted.dialControl = allowAllDial
	untrusted.rootCAs = x509.NewCertPool()

	// timeout: like main, with a short upstream timeout.
	short := base()
	short.ssrfCheck = mainCfg.ssrfCheck
	short.dialControl = allowAllDial
	short.rootCAs = roots
	short.requestTimeout = 300 * time.Millisecond

	env.cfgs = map[string]*config{
		"main": mainCfg, "strict": strict, "dialer": dialer, "untrusted": untrusted, "timeout": short,
	}
	return env
}

// expand replaces {plain}, {tls} and {closed} with the target base URLs.
func (env *goldenEnv) expand(s string) string {
	return strings.NewReplacer(
		"{plain}", env.plain.URL,
		"{tls}", env.tls.URL,
		"{closed}", "http://"+env.closed,
	).Replace(s)
}

// -----------------------------------------------------------------------
// Request matrix
// -----------------------------------------------------------------------

// goldenCase is one request. Origin and X-Proxy-Token are sent with their
// valid values unless origin/token say otherwise ("-" omits the header).
type goldenCase struct {
	name   string // file name under testdata/golden, without ".golden"
	cfg    string // config variant (newGoldenEnv)
	method string
	path   string // "/proxy", "/inspect", "/page"
	target string // value of the url parameter, with placeholders; "-" omits it
	query  string // appended after the url parameter, e.g. "&follow=1"
	origin string
	token  string
	header [][2]string
	body   string
}

func goldenCases() []goldenCase {
	return []goldenCase{
		// ---- /proxy: the call patterns of the tools ----
		// source, wysiwyg, md, llms, robots-sitemap: GET with follow=1.
		{name: "proxy_get", path: "/proxy", target: "{plain}/ok"},
		{name: "proxy_get_follow", path: "/proxy", target: "{plain}/redirect-chain", query: "&follow=1"},
		{name: "proxy_get_follow_noredirect", path: "/proxy", target: "{plain}/ok", query: "&follow=1"},
		{name: "proxy_get_redirect_nofollow", path: "/proxy", target: "{plain}/redirect"},
		{name: "proxy_get_follow_limit", path: "/proxy", target: "{plain}/hop/0", query: "&follow=1"},
		{name: "proxy_get_follow_loop", path: "/proxy", target: "{plain}/loop", query: "&follow=1"},
		{name: "proxy_get_follow_ftp", path: "/proxy", target: "{plain}/redirect-ftp", query: "&follow=1"},
		// robots-sitemap.js / llms.js: HEAD with follow=1; plain HEAD.
		{name: "proxy_head", method: http.MethodHead, path: "/proxy", target: "{plain}/ok"},
		{name: "proxy_head_follow", method: http.MethodHead, path: "/proxy", target: "{plain}/redirect", query: "&follow=1"},
		{name: "proxy_head_refused", method: http.MethodHead, path: "/proxy", target: "{plain}/no-head"},
		// md/llms/seo Markdown probe.
		{name: "proxy_get_accept_markdown", path: "/proxy", target: "{plain}/markdown", query: "&follow=1",
			header: [][2]string{{"Accept", "text/markdown, text/plain;q=0.9, */*;q=0.1"}}},
		{name: "proxy_get_accept_html", path: "/proxy", target: "{plain}/markdown"},
		// Which browser headers reach the target.
		{name: "proxy_get_echo_headers", path: "/proxy", target: "{plain}/echo?x=1", query: "&follow=1",
			header: [][2]string{
				{"Accept", "text/html"},
				{"Accept-Language", "de-DE,de;q=0.9"},
				{"User-Agent", "GoldenBrowser/1.0"},
				{"Referer", "https://test.example.com/tools/seo/"},
				{"Cookie", "session=secret"},
				{"Sec-Fetch-Mode", "cors"},
				{"Sec-Fetch-Site", "cross-site"},
				{"X-Requested-With", "XMLHttpRequest"},
			}},
		{name: "proxy_get_gzip", path: "/proxy", target: "{plain}/gzip"},
		{name: "proxy_get_tls", path: "/proxy", target: "{tls}/ok", query: "&follow=1"},
		// POST is forwarded with its body; follow is ignored for POST.
		{name: "proxy_post", method: http.MethodPost, path: "/proxy", target: "{plain}/echo",
			header: [][2]string{{"Content-Type", "application/json"}}, body: `{"hello":"golden"}`},
		{name: "proxy_post_follow_ignored", method: http.MethodPost, path: "/proxy", target: "{plain}/redirect", query: "&follow=1",
			header: [][2]string{{"Content-Type", "text/plain"}}, body: "x"},
		// Difference 6: a target sending X-Upstream-* itself.
		{name: "proxy_get_upstream_headers", path: "/proxy", target: "{plain}/upstream-headers"},
		{name: "proxy_get_follow_upstream_headers", path: "/proxy", target: "{plain}/upstream-headers", query: "&follow=1"},
		// Difference 5: userinfo in the target URL.
		{name: "proxy_get_follow_userinfo", path: "/proxy", target: "http://user:pa55@{plainhost}/auth-redirect", query: "&follow=1"},
		{name: "proxy_get_follow_userinfo_direct", path: "/proxy", target: "http://user:pa55@{plainhost}/auth", query: "&follow=1"},
		{name: "proxy_get_userinfo", path: "/proxy", target: "http://user:pa55@{plainhost}/auth"},

		// ---- /inspect ----
		// seo.js LocalProxy.inspectFetch( currentUrl ): no options, HEAD.
		{name: "inspect_plain", path: "/inspect", target: "{plain}/ok"},
		{name: "inspect_head_refused", path: "/inspect", target: "{plain}/no-head"},
		{name: "inspect_redirect", path: "/inspect", target: "{plain}/redirect"},
		{name: "inspect_get", path: "/inspect", target: "{plain}/ok", query: "&get=1"},
		{name: "inspect_body", path: "/inspect", target: "{plain}/gzip", query: "&body=1"},
		{name: "inspect_body_echo", path: "/inspect", target: "{plain}/echo", query: "&body=1",
			header: [][2]string{{"Accept", "text/html"}, {"User-Agent", "GoldenBrowser/1.0"}}},
		{name: "inspect_diag", path: "/inspect", target: "{plain}/ok", query: "&diag=1"},
		{name: "inspect_diag_tls", path: "/inspect", target: "{tls}/ok", query: "&diag=1"},
		{name: "inspect_get_diag_tls", path: "/inspect", target: "{tls}/ok", query: "&get=1&diag=1"},
		{name: "inspect_upstream_headers", path: "/inspect", target: "{plain}/upstream-headers"},
		{name: "inspect_head_method", method: http.MethodHead, path: "/inspect", target: "{plain}/ok"},

		// ---- /page ----
		{name: "page_diag", path: "/page", target: "{plain}/ok", query: "&diag=1"},
		{name: "page_diag_redirects", path: "/page", target: "{plain}/redirect-chain", query: "&diag=1"},
		{name: "page_diag_head_refused", path: "/page", target: "{plain}/no-head", query: "&diag=1"},
		{name: "page_diag_gzip", path: "/page", target: "{plain}/gzip", query: "&diag=1"},
		{name: "page_diag_tls", path: "/page", target: "{tls}/ok", query: "&diag=1"},
		{name: "page_nodiag", path: "/page", target: "{plain}/redirect"},
		{name: "page_too_many_redirects", path: "/page", target: "{plain}/hop/0", query: "&diag=1"},
		{name: "page_redirect_loop", path: "/page", target: "{plain}/loop", query: "&diag=1"},
		{name: "page_redirect_blocked", path: "/page", target: "{plain}/redirect-blocked", query: "&diag=1"},
		{name: "page_redirect_ftp", path: "/page", target: "{plain}/redirect-ftp", query: "&diag=1"},
		{name: "page_upstream_headers", path: "/page", target: "{plain}/upstream-headers", query: "&diag=1"},
		{name: "page_userinfo", path: "/page", target: "http://user:pa55@{plainhost}/auth-redirect", query: "&diag=1"},
		{name: "page_userinfo_direct", path: "/page", target: "http://user:pa55@{plainhost}/auth", query: "&diag=1"},
		{name: "inspect_userinfo", path: "/inspect", target: "http://user:pa55@{plainhost}/auth", query: "&body=1"},

		// ---- OPTIONS preflight ----
		{name: "options_proxy", method: http.MethodOptions, path: "/proxy", target: "-", token: "-",
			header: [][2]string{{"Access-Control-Request-Method", "GET"}, {"Access-Control-Request-Headers", "x-proxy-token"}}},
		{name: "options_inspect", method: http.MethodOptions, path: "/inspect", target: "-", token: "-",
			header: [][2]string{{"Access-Control-Request-Method", "GET"}, {"Access-Control-Request-Headers", "x-proxy-token"}}},
		{name: "options_page", method: http.MethodOptions, path: "/page", target: "-", token: "-",
			header: [][2]string{{"Access-Control-Request-Method", "GET"}, {"Access-Control-Request-Headers", "x-proxy-token"}}},
		{name: "options_proxy_foreign_origin", method: http.MethodOptions, path: "/proxy", target: "-", token: "-",
			origin: "https://evil.example",
			header: [][2]string{{"Access-Control-Request-Method", "GET"}, {"Access-Control-Request-Headers", "x-proxy-token"}}},

		// ---- Error paths ----
		{name: "err_forbidden_missing_token", path: "/proxy", target: "{plain}/ok", token: "-"},
		{name: "err_forbidden_wrong_token", path: "/proxy", target: "{plain}/ok", token: "wrong-token"},
		{name: "err_forbidden_wrong_token_inspect", path: "/inspect", target: "{plain}/ok", token: "wrong-token"},
		{name: "err_forbidden_wrong_token_page", path: "/page", target: "{plain}/ok", token: "wrong-token"},
		{name: "err_wrong_origin", path: "/proxy", target: "{plain}/ok", origin: "https://evil.example"},
		{name: "err_wrong_origin_page", path: "/page", target: "{plain}/ok", origin: "https://evil.example"},
		{name: "err_bad_request_missing_url", path: "/proxy", target: "-"},
		{name: "err_bad_request_not_a_url", path: "/proxy", target: "not-a-url"},
		{name: "err_bad_request_ftp", path: "/inspect", target: "ftp://files.example/"},
		{name: "err_bad_request_page", path: "/page", target: "-"},
		{name: "err_method_not_allowed_proxy", method: http.MethodPut, path: "/proxy", target: "{plain}/ok"},
		{name: "err_method_not_allowed_inspect", method: http.MethodPost, path: "/inspect", target: "{plain}/ok"},
		{name: "err_method_not_allowed_page", method: http.MethodHead, path: "/page", target: "{plain}/ok"},
		// blocked_target from the pre-check (literal IPs, no DNS).
		{name: "err_blocked_private_proxy", cfg: "strict", path: "/proxy", target: "http://10.0.0.1/"},
		{name: "err_blocked_loopback_inspect", cfg: "strict", path: "/inspect", target: "http://127.0.0.1:9/", query: "&diag=1"},
		{name: "err_blocked_metadata_page", cfg: "strict", path: "/page", target: "http://169.254.169.254/latest/meta-data/", query: "&diag=1"},
		{name: "err_blocked_ipv6_proxy", cfg: "strict", path: "/proxy", target: "http://[::1]/"},
		// blocked_target from a redirect hop.
		{name: "err_blocked_redirect_proxy", path: "/proxy", target: "{plain}/redirect-blocked", query: "&follow=1"},
		{name: "proxy_redirect_blocked_nofollow", path: "/proxy", target: "{plain}/redirect-blocked"},
		// blocked_target from the dialer.
		{name: "err_blocked_dialer_proxy", cfg: "dialer", path: "/proxy", target: "{plain}/ok"},
		{name: "err_blocked_dialer_inspect", cfg: "dialer", path: "/inspect", target: "{plain}/ok"},
		{name: "err_blocked_dialer_inspect_diag", cfg: "dialer", path: "/inspect", target: "{plain}/ok", query: "&diag=1"},
		{name: "err_blocked_dialer_page", cfg: "dialer", path: "/page", target: "{plain}/ok", query: "&diag=1"},
		// timeout.
		{name: "err_timeout_proxy", cfg: "timeout", path: "/proxy", target: "{plain}/slow"},
		{name: "err_timeout_inspect", cfg: "timeout", path: "/inspect", target: "{plain}/slow"},
		{name: "err_timeout_inspect_diag", cfg: "timeout", path: "/inspect", target: "{plain}/slow", query: "&diag=1"},
		{name: "err_timeout_page", cfg: "timeout", path: "/page", target: "{plain}/slow", query: "&diag=1"},
		// tls_error.
		{name: "err_tls_proxy", cfg: "untrusted", path: "/proxy", target: "{tls}/ok", query: "&follow=1"},
		{name: "err_tls_inspect", cfg: "untrusted", path: "/inspect", target: "{tls}/ok"},
		{name: "err_tls_inspect_diag", cfg: "untrusted", path: "/inspect", target: "{tls}/ok", query: "&diag=1"},
		{name: "err_tls_page_diag", cfg: "untrusted", path: "/page", target: "{tls}/ok", query: "&diag=1"},
		{name: "err_tls_plain_http_on_https", path: "/proxy", target: "https://{plainhost}/ok"},
		// connection_error.
		{name: "err_connection_proxy", path: "/proxy", target: "{closed}/"},
		{name: "err_connection_page", path: "/page", target: "{closed}/", query: "&diag=1"},
	}
}

// -----------------------------------------------------------------------
// The test
// -----------------------------------------------------------------------

func TestCompat_Golden(t *testing.T) {
	// The handlers log every upstream failure; the error cases are the point.
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	env := newGoldenEnv(t)
	plainHost := strings.TrimPrefix(env.plain.URL, "http://")

	seen := map[string]bool{}
	for _, c := range goldenCases() {
		if seen[c.name] {
			t.Fatalf("duplicate golden case %q", c.name)
		}
		seen[c.name] = true

		t.Run(c.name, func(t *testing.T) {
			cfgName := c.cfg
			if cfgName == "" {
				cfgName = "main"
			}
			cfg := env.cfgs[cfgName]
			client := newUpstreamClient(cfg)
			mux := http.NewServeMux()
			mux.Handle("/proxy", proxyHandler(cfg, client))
			mux.Handle("/inspect", inspectHandler(cfg, client))
			mux.Handle("/page", pageHandler(cfg, client))

			method := c.method
			if method == "" {
				method = http.MethodGet
			}
			target := strings.ReplaceAll(c.target, "{plainhost}", plainHost)
			target = env.expand(target)
			uri := c.path
			shown := c.path
			if c.target != "-" {
				uri += "?url=" + url.QueryEscape(target) + c.query
				shown += "?url=" + target + c.query
			} else if c.query != "" {
				uri += "?" + strings.TrimPrefix(c.query, "&")
				shown += "?" + strings.TrimPrefix(c.query, "&")
			}

			var body io.Reader
			if c.body != "" {
				body = strings.NewReader(c.body)
			}
			req := httptest.NewRequest(method, uri, body)

			var reqHeaders [][2]string
			if c.origin != "-" {
				origin := c.origin
				if origin == "" {
					origin = goldenOrigin
				}
				req.Header.Set("Origin", origin)
				reqHeaders = append(reqHeaders, [2]string{"Origin", origin})
			}
			if c.token != "-" {
				token := c.token
				if token == "" {
					token = goldenToken
				}
				req.Header.Set("X-Proxy-Token", token)
				reqHeaders = append(reqHeaders, [2]string{"X-Proxy-Token", token})
			}
			for _, h := range c.header {
				req.Header.Add(h[0], h[1])
				reqHeaders = append(reqHeaders, h)
			}

			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			res := rr.Result()
			got := goldenRender(method, shown, reqHeaders, c.body, res.StatusCode, res.Header, rr.Body.Bytes(), env.ports)
			goldenCompare(t, c.name, got)
		})
	}

	t.Run("main", func(t *testing.T) { goldenMainCases(t) })
}

// goldenMainCases runs main() in a subprocess and records /ping, /version,
// their preflights, the Host check and one request through the full stack.
func goldenMainCases(t *testing.T) {
	addr, token := goldenStartMain(t, "-port", "0", "-origin", goldenOrigin, "-dns", "system")
	_, proxyPort, _ := net.SplitHostPort(addr)
	ports := map[string]string{proxyPort: "<proxy-port>"}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true, DisableCompression: true},
	}

	type mainCase struct {
		name   string
		method string
		uri    string
		host   string // Host header; "" means the listener address
		header [][2]string
	}
	preflight := [][2]string{
		{"Origin", goldenOrigin},
		{"Access-Control-Request-Method", "GET"},
		{"Access-Control-Request-Headers", "x-proxy-token"},
	}
	cases := []mainCase{
		{name: "main_ping", method: http.MethodGet, uri: "/ping", header: [][2]string{{"Origin", goldenOrigin}}},
		{name: "main_ping_no_origin", method: http.MethodGet, uri: "/ping"},
		{name: "main_ping_foreign_origin", method: http.MethodGet, uri: "/ping", header: [][2]string{{"Origin", "https://evil.example"}}},
		{name: "main_version", method: http.MethodGet, uri: "/version", header: [][2]string{{"Origin", goldenOrigin}}},
		{name: "main_options_ping", method: http.MethodOptions, uri: "/ping", header: preflight},
		{name: "main_options_version", method: http.MethodOptions, uri: "/version", header: preflight},
		{name: "main_options_proxy", method: http.MethodOptions, uri: "/proxy", header: preflight},
		{name: "main_host_check", method: http.MethodGet, uri: "/ping", host: "evil.example", header: [][2]string{{"Origin", goldenOrigin}}},
		{name: "main_proxy_blocked_metadata", method: http.MethodGet,
			uri:    "/proxy?url=" + url.QueryEscape("http://169.254.169.254/latest/meta-data/") + "&follow=1",
			header: [][2]string{{"Origin", goldenOrigin}, {"X-Proxy-Token", "<token>"}}},
		{name: "main_proxy_wrong_token", method: http.MethodGet,
			uri:    "/proxy?url=" + url.QueryEscape("https://example.com/"),
			header: [][2]string{{"Origin", goldenOrigin}, {"X-Proxy-Token", "wrong-token"}}},
		{name: "main_not_found", method: http.MethodGet, uri: "/nope", header: [][2]string{{"Origin", goldenOrigin}}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req, err := http.NewRequest(c.method, "http://"+addr+c.uri, nil)
			if err != nil {
				t.Fatal(err)
			}
			if c.host != "" {
				req.Host = c.host
			}
			for _, h := range c.header {
				v := h[1]
				if v == "<token>" {
					v = token
				}
				req.Header.Add(h[0], v)
			}
			res, err := client.Do(req)
			if err != nil {
				t.Fatalf("%s %s: %v", c.method, c.uri, err)
			}
			body, _ := io.ReadAll(res.Body)
			res.Body.Close()

			shown, _ := url.QueryUnescape(c.uri)
			reqHeaders := c.header
			if c.host != "" {
				reqHeaders = append([][2]string{{"Host", c.host}}, reqHeaders...)
			}
			got := goldenRender(c.method, shown, reqHeaders, "", res.StatusCode, res.Header, body, ports)
			goldenCompare(t, c.name, got)
		})
	}
}

// TestCompat_GoldenMainHelper is not a test of its own: goldenStartMain
// re-runs the test binary with goldenMainEnv set, and this then runs main()
// with those arguments.
func TestCompat_GoldenMainHelper(t *testing.T) {
	raw := os.Getenv(goldenMainEnv)
	if raw == "" {
		t.Skip("helper for TestCompat_Golden")
	}
	var args []string
	if err := json.Unmarshal([]byte(raw), &args); err != nil {
		fmt.Fprintln(os.Stderr, "bad args:", err)
		os.Exit(3)
	}
	os.Args = append([]string{"localproxy"}, args...)
	flag.CommandLine = flag.NewFlagSet("localproxy", flag.ExitOnError)
	main()
	os.Exit(0)
}

// goldenStartMain starts main() with args in a subprocess, waits for the
// banner and returns the listen address and the session token. The process
// is killed when the test ends.
func goldenStartMain(t *testing.T, args ...string) (addr, token string) {
	t.Helper()
	enc, _ := json.Marshal(args)
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCompat_GoldenMainHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), goldenMainEnv+"="+string(enc))
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
	})

	addrRe := regexp.MustCompile(`Address\s+:\s+http://(127\.0\.0\.1:\d+)`)
	tokenRe := regexp.MustCompile(`Token\s+:\s+([0-9a-f]+)`)
	found := make(chan struct{})
	go func() {
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			line := sc.Text()
			if m := addrRe.FindStringSubmatch(line); m != nil {
				addr = m[1]
			}
			if m := tokenRe.FindStringSubmatch(line); m != nil {
				token = m[1]
			}
			if strings.Contains(line, "Press Ctrl+C to stop.") {
				close(found)
				break
			}
		}
		_, _ = io.Copy(io.Discard, stdout)
	}()
	select {
	case <-found:
	case <-time.After(30 * time.Second):
		t.Fatal("main() did not print its banner within 30s")
	}
	if addr == "" || token == "" {
		t.Fatalf("banner without address or token (addr=%q token set=%t)", addr, token != "")
	}
	return addr, token
}

// -----------------------------------------------------------------------
// Rendering and normalisation
// -----------------------------------------------------------------------

var (
	goldenTimingRe   = regexp.MustCompile(`=\d+`)
	goldenRawDateRe  = regexp.MustCompile(`(?m)(^|\n)Date: [^\r\n]*`)
	goldenDaysKeys   = map[string]bool{"daysLeft": true, "certDaysLeft": true}
	goldenKeepTiming = map[string]bool{"downloadSize": true, "speed": true}
)

// goldenRender turns one exchange into the text stored in the golden file.
func goldenRender(method, uri string, reqHeaders [][2]string, reqBody string,
	status int, header http.Header, body []byte, ports map[string]string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "> %s %s\n", method, uri)
	for _, h := range reqHeaders {
		v := h[1]
		if h[0] == "X-Proxy-Token" && v != "wrong-token" {
			v = "<token>"
		}
		fmt.Fprintf(&sb, "> %s: %s\n", h[0], v)
	}
	if reqBody != "" {
		fmt.Fprintf(&sb, ">\n> %s\n", reqBody)
	}
	sb.WriteString("\n")
	fmt.Fprintf(&sb, "< %d\n", status)
	for _, name := range slices.Sorted(maps.Keys(header)) {
		for _, v := range header[name] {
			switch name {
			case "Date":
				v = "<date>"
			case "X-Upstream-Timing":
				v = goldenTimingRe.ReplaceAllString(v, "=<ms>")
			}
			fmt.Fprintf(&sb, "< %s: %s\n", name, v)
		}
	}
	sb.WriteString("\n")
	sb.WriteString(goldenBody(header.Get("Content-Type"), body))
	return goldenPorts(sb.String(), ports)
}

// goldenBody pretty-prints JSON bodies with volatile values replaced; other
// bodies stay as they are.
func goldenBody(contentType string, body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if strings.HasPrefix(contentType, "application/json") {
		dec := json.NewDecoder(bytes.NewReader(body))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err == nil {
			// No HTML escaping: "<ms>" and HTML bodies stay readable.
			var out bytes.Buffer
			enc := json.NewEncoder(&out)
			enc.SetEscapeHTML(false)
			enc.SetIndent("", "  ")
			if err := enc.Encode(goldenNormalizeJSON("", v)); err == nil {
				return out.String()
			}
		}
	}
	return goldenRawDateRe.ReplaceAllString(string(body), "${1}Date: <date>")
}

// goldenNormalizeJSON replaces timing values, certificate days and Date
// header values. key is the name v sits under in its parent object.
func goldenNormalizeJSON(key string, v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			switch {
			case k == "timing":
				x[k] = goldenNormalizeTiming(val)
			case goldenDaysKeys[k]:
				x[k] = "<days>"
			case k == "Date":
				x[k] = []any{"<date>"}
			default:
				x[k] = goldenNormalizeJSON(k, val)
			}
		}
		return x
	case []any:
		for i := range x {
			x[i] = goldenNormalizeJSON(key, x[i])
		}
		return x
	case string:
		return goldenRawDateRe.ReplaceAllString(x, "${1}Date: <date>")
	}
	return v
}

func goldenNormalizeTiming(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k := range x {
			if !goldenKeepTiming[k] {
				x[k] = "<ms>"
			}
		}
		return x
	case json.Number:
		return "<ms>"
	}
	return v
}

// goldenPorts replaces every listener port after "127.0.0.1:" with its name.
func goldenPorts(s string, ports map[string]string) string {
	for port, name := range ports {
		s = strings.ReplaceAll(s, "127.0.0.1:"+port, "127.0.0.1:"+name)
	}
	return s
}

// goldenCompare writes (with -update) or compares one golden file.
func goldenCompare(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join(goldenDir, name+".golden")
	if *goldenUpdate {
		if err := os.MkdirAll(goldenDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v (record with -update)", path, err)
	}
	if string(want) != got {
		t.Errorf("%s differs from v1.3.0:\n%s", path, goldenDiff(string(want), got))
	}
}

// goldenDiff is a minimal line diff: the lines only in want ("-") and only
// in got ("+"), in order, with their line numbers. Enough to review a
// response change without an external diff tool.
func goldenDiff(want, got string) string {
	w := strings.Split(want, "\n")
	g := strings.Split(got, "\n")
	// Longest common subsequence over lines.
	lcs := make([][]int, len(w)+1)
	for i := range lcs {
		lcs[i] = make([]int, len(g)+1)
	}
	for i := len(w) - 1; i >= 0; i-- {
		for j := len(g) - 1; j >= 0; j-- {
			if w[i] == g[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var sb strings.Builder
	i, j := 0, 0
	for i < len(w) || j < len(g) {
		switch {
		case i < len(w) && j < len(g) && w[i] == g[j]:
			i++
			j++
		case j < len(g) && (i == len(w) || lcs[i][j+1] >= lcs[i+1][j]):
			fmt.Fprintf(&sb, "  +%4d %s\n", j+1, g[j])
			j++
		default:
			fmt.Fprintf(&sb, "  -%4d %s\n", i+1, w[i])
			i++
		}
	}
	return sb.String()
}
