package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

// -----------------------------------------------------------------------
// generateToken
// -----------------------------------------------------------------------

func TestGenerateToken_Length(t *testing.T) {
	tok, err := generateToken(24)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(tok) != 48 {
		t.Errorf("expected 48 hex chars, got %d", len(tok))
	}
}

func TestGenerateToken_Unique(t *testing.T) {
	a, _ := generateToken(24)
	b, _ := generateToken(24)
	if a == b {
		t.Error("two consecutive tokens should not be equal")
	}
}

// -----------------------------------------------------------------------
// isOriginAllowed
// -----------------------------------------------------------------------

func TestIsOriginAllowed_EmptyList(t *testing.T) {
	if !isOriginAllowed("https://anything.example.com", nil) {
		t.Error("empty allowlist should permit any origin")
	}
}

func TestIsOriginAllowed_Match(t *testing.T) {
	allowed := []string{"https://foo.example.com", "https://bar.example.com"}
	if !isOriginAllowed("https://foo.example.com", allowed) {
		t.Error("exact match should be allowed")
	}
}

func TestIsOriginAllowed_CaseInsensitive(t *testing.T) {
	allowed := []string{"https://Foo.Example.COM"}
	if !isOriginAllowed("https://foo.example.com", allowed) {
		t.Error("origin comparison should be case-insensitive")
	}
}

func TestIsOriginAllowed_Rejected(t *testing.T) {
	allowed := []string{"https://foo.example.com"}
	if isOriginAllowed("https://evil.example.com", allowed) {
		t.Error("non-matching origin should be rejected")
	}
}

// -----------------------------------------------------------------------
// isPrivateHost
// -----------------------------------------------------------------------

func TestIsPrivateHost_Localhost(t *testing.T) {
	if !isPrivateHost(context.Background(), "127.0.0.1", nil) {
		t.Error("127.0.0.1 should be detected as private")
	}
}

func TestIsPrivateHost_PrivateRange(t *testing.T) {
	if !isPrivateHost(context.Background(), "192.168.1.1", nil) {
		t.Error("192.168.1.1 should be detected as private")
	}
}

func TestIsPrivateHost_Public(t *testing.T) {
	// Use a known public IP (Google DNS).
	if isPrivateHost(context.Background(), "8.8.8.8", nil) {
		t.Error("8.8.8.8 should not be detected as private")
	}
}

func TestIsPrivateHost_Unresolvable(t *testing.T) {
	// Unresolvable hosts should NOT be treated as private: failing open here is
	// safe because safeDialControl re-checks the real address before connecting.
	if isPrivateHost(context.Background(), "this-host-does-not-exist.invalid", nil) {
		t.Error("unresolvable host should not be treated as private")
	}
}

// A literal IP must be judged directly rather than going through the resolver,
// so it cannot dodge the check by being unresolvable.
func TestIsPrivateHost_LiteralIPNeedsNoResolver(t *testing.T) {
	failing := &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("resolver deliberately unavailable")
		},
	}
	if !isPrivateHost(context.Background(), "10.0.0.1", failing) {
		t.Error("literal private IP should be blocked without consulting DNS")
	}
	if !isPrivateHost(context.Background(), "[::1]", failing) {
		t.Error("literal IPv6 loopback should be blocked without consulting DNS")
	}
}

// -----------------------------------------------------------------------
// proxyHandler — HTTP-level tests
// -----------------------------------------------------------------------

func newTestConfig() *config {
	return &config{
		port:             0,
		allowedOrigins:   []string{"https://test.example.com"},
		sessionToken:     "test-token-abc",
		requestTimeout:   10 * time.Second,
		maxResponseBytes: 1 * 1024 * 1024,
	}
}

func TestProxy_MissingToken(t *testing.T) {
	cfg := newTestConfig()
	handler := proxyHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/proxy?url=https://example.com", nil)
	req.Header.Set("Origin", "https://test.example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestProxy_WrongOrigin(t *testing.T) {
	cfg := newTestConfig()
	handler := proxyHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/proxy?url=https://example.com", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestProxy_MissingURL(t *testing.T) {
	cfg := newTestConfig()
	handler := proxyHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/proxy", nil)
	req.Header.Set("Origin", "https://test.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestProxy_InvalidURL(t *testing.T) {
	cfg := newTestConfig()
	handler := proxyHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/proxy?url=not-a-url", nil)
	req.Header.Set("Origin", "https://test.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestProxy_SSRFBlocked(t *testing.T) {
	cfg := newTestConfig()
	handler := proxyHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/proxy?url=http://127.0.0.1:9999/secret", nil)
	req.Header.Set("Origin", "https://test.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for SSRF attempt, got %d", rr.Code)
	}
}

func TestProxy_MethodNotAllowed(t *testing.T) {
	cfg := newTestConfig()
	handler := proxyHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodPut, "/proxy?url=https://example.com", nil)
	req.Header.Set("Origin", "https://test.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for PUT, got %d", rr.Code)
	}
}

func TestProxy_OptionsCORS(t *testing.T) {
	cfg := newTestConfig()
	handler := proxyHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodOptions, "/proxy", nil)
	req.Header.Set("Origin", "https://test.example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for OPTIONS, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://test.example.com" {
		t.Errorf("expected CORS origin echo, got %q", got)
	}
	if got := rr.Header().Get("Access-Control-Allow-Private-Network"); got != "true" {
		t.Errorf("expected Access-Control-Allow-Private-Network=true, got %q", got)
	}
	// AUTH-1: exactly the two credential headers are added, nothing else.
	if got := rr.Header().Get("Access-Control-Allow-Headers"); got != "Content-Type, X-Proxy-Token, X-Target-Authorization, X-Target-Origin" {
		t.Errorf("unexpected Access-Control-Allow-Headers %q", got)
	}
}

func TestProxy_SuccessfulForward(t *testing.T) {
	// Spin up a fake upstream server.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "hello")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("upstream-body"))
	}))
	defer upstream.Close()

	cfg := newTestConfig()
	// Allow all origins so we don't need to match the test origin exactly.
	cfg.allowedOrigins = nil
	// Disable SSRF check because httptest.NewServer listens on 127.0.0.1.
	cfg.ssrfCheck = func(string) bool { return false }
	handler := proxyHandler(cfg, upstream.Client())

	req := httptest.NewRequest(http.MethodGet, "/proxy?url="+upstream.URL, nil)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}
	if rr.Body.String() != "upstream-body" {
		t.Errorf("expected upstream-body, got %q", rr.Body.String())
	}
	if got := rr.Header().Get("X-Custom"); got != "hello" {
		t.Errorf("expected upstream header X-Custom=hello, got %q", got)
	}
}

// -----------------------------------------------------------------------
// /ping endpoint
// -----------------------------------------------------------------------

func TestPing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("Origin", "https://test.example.com")
	rr := httptest.NewRecorder()

	// The real handler main registers (CAP-1); TestPingHandler has more.
	cfg := newTestConfig()
	mux := http.NewServeMux()
	mux.Handle("/ping", pingHandler(cfg))
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if body := rr.Body.String(); body != "localproxy ok\n" {
		t.Errorf("unexpected body: %q", body)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://test.example.com" {
		t.Errorf("expected CORS origin on /ping, got %q", got)
	}
}

// -----------------------------------------------------------------------
// classifyUpstreamError
// -----------------------------------------------------------------------

func TestClassifyUpstreamError_DNS(t *testing.T) {
	err := &net.DNSError{Err: "no such host", Name: "example.invalid"}
	code, _ := classifyUpstreamError(err)
	if code != "dns_error" {
		t.Errorf("expected dns_error, got %q", code)
	}
}

func TestClassifyUpstreamError_TLS(t *testing.T) {
	err := &tls.CertificateVerificationError{Err: errors.New("expired")}
	code, _ := classifyUpstreamError(err)
	if code != "tls_error" {
		t.Errorf("expected tls_error, got %q", code)
	}
}

func TestClassifyUpstreamError_TLS_UnknownAuthority(t *testing.T) {
	err := x509.UnknownAuthorityError{}
	code, _ := classifyUpstreamError(err)
	if code != "tls_error" {
		t.Errorf("expected tls_error, got %q", code)
	}
}

func TestClassifyUpstreamError_Connection(t *testing.T) {
	err := &net.OpError{Op: "dial", Err: fmt.Errorf("connection refused")}
	code, _ := classifyUpstreamError(err)
	if code != "connection_error" {
		t.Errorf("expected connection_error, got %q", code)
	}
}

// A TLS handshake that fails for a non-certificate reason (version, cipher
// suite, an alert from the peer) is still a TLS problem, not a connection
// problem. crypto/tls delivers those alerts wrapped in a *net.OpError whose Op
// is "remote error" or "local error", which the plain *net.OpError check would
// otherwise report as connection_error and hide the real cause.

func TestClassifyUpstreamError_TLS_RemoteAlert(t *testing.T) {
	// Shape produced by crypto/tls when the peer sends an alert.
	err := &net.OpError{Op: "remote error", Err: errors.New("tls: protocol version not supported")}
	code, msg := classifyUpstreamError(err)
	if code != "tls_error" {
		t.Errorf("expected tls_error, got %q", code)
	}
	if msg == "" {
		t.Error("expected a non-empty message")
	}
}

func TestClassifyUpstreamError_TLS_LocalAlert(t *testing.T) {
	err := &net.OpError{Op: "local error", Err: errors.New("tls: handshake failure")}
	code, _ := classifyUpstreamError(err)
	if code != "tls_error" {
		t.Errorf("expected tls_error, got %q", code)
	}
}

func TestClassifyUpstreamError_TLS_RecordHeader(t *testing.T) {
	// Sent by crypto/tls when the target speaks plain HTTP on an https:// port.
	err := tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}
	code, _ := classifyUpstreamError(err)
	if code != "tls_error" {
		t.Errorf("expected tls_error, got %q", code)
	}
}

// Guard the other direction: genuine socket failures must not be swept into
// tls_error just because they arrive as *net.OpError.
func TestClassifyUpstreamError_Connection_NotMistakenForTLS(t *testing.T) {
	for _, op := range []string{"dial", "read", "write"} {
		err := &net.OpError{Op: op, Err: errors.New("connection reset by peer")}
		code, _ := classifyUpstreamError(err)
		if code != "connection_error" {
			t.Errorf("op %q: expected connection_error, got %q", op, code)
		}
	}
}

// The shapes above are asserted against real handshakes rather than trusted
// from a comment — crypto/tls is free to change how it wraps these.
func TestClassifyUpstreamError_TLS_RealHandshakeFailures(t *testing.T) {
	tlsServer := func(cfg *tls.Config) *httptest.Server {
		s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		s.TLS = cfg
		s.StartTLS()
		return s
	}

	t.Run("plain HTTP on an https port", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer srv.Close()

		_, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			t.Fatal("expected the handshake to fail")
		}
		if code, _ := classifyUpstreamError(err); code != "tls_error" {
			t.Errorf("expected tls_error, got %q (err: %v)", code, err)
		}
	})

	t.Run("no mutually supported protocol version", func(t *testing.T) {
		srv := tlsServer(&tls.Config{MaxVersion: tls.VersionTLS12})
		defer srv.Close()

		_, err := tls.Dial("tcp", srv.Listener.Addr().String(),
			&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13})
		if err == nil {
			t.Fatal("expected the handshake to fail")
		}
		if code, _ := classifyUpstreamError(err); code != "tls_error" {
			t.Errorf("expected tls_error, got %q (err: %v)", code, err)
		}
	})

	t.Run("no mutually supported cipher suite", func(t *testing.T) {
		srv := tlsServer(&tls.Config{
			MaxVersion:   tls.VersionTLS12,
			CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		})
		defer srv.Close()

		_, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{
			InsecureSkipVerify: true,
			MaxVersion:         tls.VersionTLS12,
			CipherSuites:       []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384},
		})
		if err == nil {
			t.Fatal("expected the handshake to fail")
		}
		if code, _ := classifyUpstreamError(err); code != "tls_error" {
			t.Errorf("expected tls_error, got %q (err: %v)", code, err)
		}
	})

	t.Run("refused connection stays a connection error", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		addr := l.Addr().String()
		l.Close()

		_, err = tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true})
		if err == nil {
			t.Fatal("expected the dial to fail")
		}
		if code, _ := classifyUpstreamError(err); code != "connection_error" {
			t.Errorf("expected connection_error, got %q (err: %v)", code, err)
		}
	})
}

// crypto/tls reports most negotiation failures as a bare fmt.Errorf with no
// type to match on — only the package-wide "tls: " message prefix. The most
// likely one in practice is a server stuck on TLS 1.0/1.1, which modern Go
// clients refuse outright.
func TestClassifyUpstreamError_TLS_UntypedHandshakeError(t *testing.T) {
	for _, leaf := range []string{
		"tls: server selected unsupported protocol version 301",
		"tls: no supported versions satisfy MinVersion and MaxVersion",
		"tls: server chose an unconfigured cipher suite",
	} {
		err := &url.Error{Op: "Get", URL: "https://example.com/", Err: errors.New(leaf)}
		code, _ := classifyUpstreamError(err)
		if code != "tls_error" {
			t.Errorf("%q: expected tls_error, got %q", leaf, code)
		}
	}
}

// The prefix must be read off the leaf error, not the whole chain: the outer
// *url.Error carries the caller-supplied URL, so matching the flattened message
// would let a crafted query string forge a TLS verdict.
func TestClassifyUpstreamError_TLSPrefixInURLDoesNotForgeTLSError(t *testing.T) {
	err := &url.Error{
		Op:  "Get",
		URL: "https://example.com/?q=tls:+something",
		Err: errors.New("some unrelated failure"),
	}
	if code, _ := classifyUpstreamError(err); code != "upstream_error" {
		t.Errorf("expected upstream_error, got %q", code)
	}
}

// Every caller sits inside an `if err != nil`, but the function used to be
// nil-safe and unwrapping to a leaf error must not turn that into a panic in a
// long-running proxy.
func TestClassifyUpstreamError_NilIsNotAPanic(t *testing.T) {
	code, _ := classifyUpstreamError(nil)
	if code != "upstream_error" {
		t.Errorf("expected upstream_error, got %q", code)
	}
}

func TestClassifyUpstreamError_Unknown(t *testing.T) {
	err := errors.New("something weird")
	code, _ := classifyUpstreamError(err)
	if code != "upstream_error" {
		t.Errorf("expected upstream_error, got %q", code)
	}
}

// -----------------------------------------------------------------------
// JSON error response in proxy handler
// -----------------------------------------------------------------------

func TestProxy_UpstreamDNSError_ReturnsJSON(t *testing.T) {
	cfg := newTestConfig()
	cfg.allowedOrigins = nil

	// Target a domain that will definitely fail DNS resolution.
	handler := proxyHandler(cfg, &http.Client{Timeout: 5 * time.Second})

	req := httptest.NewRequest(http.MethodGet, "/proxy?url=http://this-host-does-not-exist-at-all.invalid/path", nil)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
	var errResp proxyError
	if err := json.NewDecoder(rr.Body).Decode(&errResp); err != nil {
		t.Fatalf("could not decode JSON error response: %v", err)
	}
	if errResp.Error != "dns_error" {
		t.Errorf("expected error code dns_error, got %q", errResp.Error)
	}
}

// -----------------------------------------------------------------------
// Version variable & /version endpoint
// -----------------------------------------------------------------------

func TestVersionDefault(t *testing.T) {
	if Version != "dev" {
		t.Errorf("expected default Version to be 'dev', got %q", Version)
	}
}

func TestVersionEndpoint(t *testing.T) {
	// The real handler main registers (CAP-1). Only the v1.3.0 keys are
	// checked here; TestVersionHandler_Capabilities covers the new ones.
	cfg := newTestConfig()
	mux := http.NewServeMux()
	mux.Handle("/version", versionHandler(cfg))

	req := httptest.NewRequest(http.MethodGet, "/version", nil)
	req.Header.Set("Origin", "https://test.example.com")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %q", ct)
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("could not decode version response: %v", err)
	}
	if resp["version"] != Version {
		t.Errorf("expected version=%q, got %q", Version, resp["version"])
	}
	if resp["license"] != License {
		t.Errorf("expected license=%q, got %q", License, resp["license"])
	}
	if resp["author"] != Author {
		t.Errorf("expected author=%q, got %q", Author, resp["author"])
	}
	if resp["repo"] != RepoURL {
		t.Errorf("expected repo=%q, got %q", RepoURL, resp["repo"])
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://test.example.com" {
		t.Errorf("expected CORS origin on /version, got %q", got)
	}
}

func TestVersionEndpoint_CORS_Preflight(t *testing.T) {
	cfg := newTestConfig()
	mux := http.NewServeMux()
	mux.Handle("/version", versionHandler(cfg))

	req := httptest.NewRequest(http.MethodOptions, "/version", nil)
	req.Header.Set("Origin", "https://test.example.com")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("expected 204 for OPTIONS, got %d", rr.Code)
	}
}

// -----------------------------------------------------------------------
// Access-Control-Expose-Headers
// -----------------------------------------------------------------------

func TestCORS_ExposeHeaders(t *testing.T) {
	// Expose-Headers must explicitly list headers (wildcard "*" only works
	// with "Access-Control-Allow-Origin: *", not with specific origins).
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig()
	cfg.allowedOrigins = []string{"https://test.example.com"}
	cfg.ssrfCheck = func(string) bool { return false }
	handler := proxyHandler(cfg, upstream.Client())

	req := httptest.NewRequest(http.MethodGet, "/proxy?url="+upstream.URL, nil)
	req.Header.Set("Origin", "https://test.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	req.Header.Set("Accept-Encoding", "gzip")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	expose := rr.Header().Get("Access-Control-Expose-Headers")
	if expose == "" {
		t.Fatal("expected Access-Control-Expose-Headers to be set")
	}
	// Must contain our custom metadata headers and upstream headers.
	for _, want := range []string{
		"X-Upstream-Protocol", "X-Upstream-Timing",
		"X-Upstream-Content-Encoding", "X-Upstream-Content-Length",
		"Server", "Strict-Transport-Security",
	} {
		if !strings.Contains(expose, want) {
			t.Errorf("Access-Control-Expose-Headers missing %q in %q", want, expose)
		}
	}
	// Must NOT be the wildcard "*".
	if expose == "*" {
		t.Error("Access-Control-Expose-Headers must not be wildcard when specific origin is set")
	}
}

// -----------------------------------------------------------------------
// X-Upstream-Protocol, X-Upstream-IP, X-Upstream-Timing, Content headers
// -----------------------------------------------------------------------

func TestProxy_UpstreamMetadataHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		w.Header().Set("Content-Length", "12345")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := newTestConfig()
	cfg.allowedOrigins = nil
	cfg.ssrfCheck = func(string) bool { return false }
	handler := proxyHandler(cfg, upstream.Client())

	// Set Accept-Encoding so Go's transport does not transparently decompress
	// and strip Content-Encoding from the upstream response.
	req := httptest.NewRequest(http.MethodGet, "/proxy?url="+upstream.URL, nil)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Protocol header should be present (HTTP/1.1 for httptest).
	if got := rr.Header().Get("X-Upstream-Protocol"); got == "" {
		t.Error("expected X-Upstream-Protocol to be set")
	}

	// Timing header should be present and contain expected keys.
	timing := rr.Header().Get("X-Upstream-Timing")
	if timing == "" {
		t.Error("expected X-Upstream-Timing to be set")
	}
	for _, key := range []string{"dns=", "tcp=", "ssl=", "ttfb=", "total="} {
		if !strings.Contains(timing, key) {
			t.Errorf("X-Upstream-Timing missing key %q in %q", key, timing)
		}
	}

	// Content-Encoding preservation.
	if got := rr.Header().Get("X-Upstream-Content-Encoding"); got != "br" {
		t.Errorf("expected X-Upstream-Content-Encoding=br, got %q", got)
	}
	if got := rr.Header().Get("X-Upstream-Content-Length"); got != "12345" {
		t.Errorf("expected X-Upstream-Content-Length=12345, got %q", got)
	}
}

// -----------------------------------------------------------------------
// /inspect endpoint
// -----------------------------------------------------------------------

func TestInspect_MissingToken(t *testing.T) {
	cfg := newTestConfig()
	handler := inspectHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/inspect?url=https://example.com", nil)
	req.Header.Set("Origin", "https://test.example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestInspect_MissingURL(t *testing.T) {
	cfg := newTestConfig()
	handler := inspectHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/inspect", nil)
	req.Header.Set("Origin", "https://test.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestInspect_SuccessfulWithBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer")
		w.Header().Set("X-Custom", "inspect-test")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>hello</html>"))
	}))
	defer upstream.Close()

	cfg := newTestConfig()
	cfg.allowedOrigins = nil
	cfg.ssrfCheck = func(string) bool { return false }
	handler := inspectHandler(cfg, upstream.Client())

	req := httptest.NewRequest(http.MethodGet, "/inspect?url="+upstream.URL+"&body=1", nil)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var resp inspectResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("could not decode inspect response: %v", err)
	}

	if resp.Status != 200 {
		t.Errorf("expected status 200 in response, got %d", resp.Status)
	}
	if resp.Protocol == "" {
		t.Error("expected protocol to be set")
	}
	if resp.Body != "<html>hello</html>" {
		t.Errorf("expected body in response, got %q", resp.Body)
	}
	if got := resp.Headers["Server"]; len(got) != 1 || got[0] != "TestServer" {
		t.Errorf("expected Server=[TestServer] in response, got %v", got)
	}
	if got := resp.Headers["X-Custom"]; len(got) != 1 || got[0] != "inspect-test" {
		t.Errorf("expected X-Custom=[inspect-test] in response, got %v", got)
	}
	// SSL should be nil for plain HTTP.
	if resp.SSL != nil {
		t.Error("expected SSL to be nil for HTTP upstream")
	}
	// Timing should have keys.
	if resp.Timing["total"] <= 0 {
		t.Error("expected timing.total > 0")
	}
}

func TestInspect_WithoutBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodHead {
			t.Errorf("expected HEAD request without body=1, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := newTestConfig()
	cfg.allowedOrigins = nil
	cfg.ssrfCheck = func(string) bool { return false }
	handler := inspectHandler(cfg, upstream.Client())

	req := httptest.NewRequest(http.MethodGet, "/inspect?url="+upstream.URL, nil)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	var resp inspectResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("could not decode inspect response: %v", err)
	}

	if resp.Body != "" {
		t.Errorf("expected empty body without body=1, got %q", resp.Body)
	}
}

// TestInspect_MultiValueSetCookie verifies that multiple Set-Cookie headers
// are preserved as a JSON array (RFC 6265 §3) — joining them with ", " is
// unsafe because cookie expiry dates contain literal commas.
func TestInspect_MultiValueSetCookie(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Set-Cookie", "be_typo_user=deleted; expires=Sun, 27 Apr 2025 14:03:58 GMT; Max-Age=0; path=/; httponly; samesite=lax")
		w.Header().Add("Set-Cookie", "__Secure-typo3nonce=eyJ0eXAi; path=/; secure; httponly; samesite=strict")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	cfg := newTestConfig()
	cfg.allowedOrigins = nil
	cfg.ssrfCheck = func(string) bool { return false }
	handler := inspectHandler(cfg, upstream.Client())

	req := httptest.NewRequest(http.MethodGet, "/inspect?url="+upstream.URL+"&body=1", nil)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var resp inspectResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}

	cookies := resp.Headers["Set-Cookie"]
	if len(cookies) != 2 {
		t.Fatalf("expected 2 Set-Cookie values, got %d: %v", len(cookies), cookies)
	}
	if !strings.Contains(cookies[0], "be_typo_user=deleted") {
		t.Errorf("first Set-Cookie should contain 'be_typo_user=deleted', got %q", cookies[0])
	}
	if !strings.Contains(cookies[1], "__Secure-typo3nonce") {
		t.Errorf("second Set-Cookie should contain '__Secure-typo3nonce', got %q", cookies[1])
	}
	// Ensure no value contains the join separator we used to apply.
	for i, c := range cookies {
		if strings.Contains(c, "be_typo_user") && strings.Contains(c, "__Secure-typo3nonce") {
			t.Errorf("cookie[%d] looks like a joined string (RFC 6265 §3 violation): %q", i, c)
		}
	}
}

// -----------------------------------------------------------------------
// extractSSLInfo
// -----------------------------------------------------------------------

func TestExtractSSLInfo_Nil(t *testing.T) {
	if info := extractSSLInfo(nil, ""); info != nil {
		t.Error("expected nil for nil TLS state")
	}
}

func TestExtractSSLInfo_NoCerts(t *testing.T) {
	state := &tls.ConnectionState{}
	if info := extractSSLInfo(state, ""); info != nil {
		t.Error("expected nil for empty PeerCertificates")
	}
}

// -----------------------------------------------------------------------
// tlsVersionName
// -----------------------------------------------------------------------

func TestTLSVersionName(t *testing.T) {
	tests := []struct {
		version  uint16
		expected string
	}{
		{tls.VersionTLS10, "TLS 1.0"},
		{tls.VersionTLS11, "TLS 1.1"},
		{tls.VersionTLS12, "TLS 1.2"},
		{tls.VersionTLS13, "TLS 1.3"},
		{0x0300, "TLS 0x0300"},
	}
	for _, tt := range tests {
		if got := tlsVersionName(tt.version); got != tt.expected {
			t.Errorf("tlsVersionName(0x%04x) = %q, want %q", tt.version, got, tt.expected)
		}
	}
}

// -----------------------------------------------------------------------
// connTrace
// -----------------------------------------------------------------------

func TestConnTrace_TimingHeader(t *testing.T) {
	ct := &connTrace{}
	start := time.Now()
	header := ct.timingHeader(start)

	// Should contain all 5 keys even with zero values.
	for _, key := range []string{"dns=", "tcp=", "ssl=", "ttfb=", "total="} {
		if !strings.Contains(header, key) {
			t.Errorf("timingHeader missing key %q in %q", key, header)
		}
	}
}

func TestConnTrace_RemoteIP_Empty(t *testing.T) {
	ct := &connTrace{}
	if ip := ct.remoteIP(); ip != "" {
		t.Errorf("expected empty IP, got %q", ip)
	}
}

func TestConnTrace_RemoteIP_WithPort(t *testing.T) {
	ct := &connTrace{remoteAddr: "93.184.216.34:443"}
	if ip := ct.remoteIP(); ip != "93.184.216.34" {
		t.Errorf("expected 93.184.216.34, got %q", ip)
	}
}

// -----------------------------------------------------------------------
// /page endpoint
// -----------------------------------------------------------------------

func TestPage_MissingToken(t *testing.T) {
	cfg := newTestConfig()
	handler := pageHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/page?url=https://example.com", nil)
	req.Header.Set("Origin", "https://test.example.com")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestPage_MissingURL(t *testing.T) {
	cfg := newTestConfig()
	handler := pageHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	req.Header.Set("Origin", "https://test.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestPage_MethodNotAllowed(t *testing.T) {
	cfg := newTestConfig()
	handler := pageHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodPost, "/page?url=https://example.com", nil)
	req.Header.Set("Origin", "https://test.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestPage_SuccessfulNoRedirect(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "TestServer")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html><head><title>Test</title></head></html>"))
	}))
	defer upstream.Close()

	cfg := newTestConfig()
	cfg.allowedOrigins = nil
	cfg.ssrfCheck = func(string) bool { return false }
	handler := pageHandler(cfg, upstream.Client())

	req := httptest.NewRequest(http.MethodGet, "/page?url="+upstream.URL, nil)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var resp pageResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("could not decode page response: %v", err)
	}

	if resp.URL != upstream.URL {
		t.Errorf("expected url=%s, got %s", upstream.URL, resp.URL)
	}
	if resp.FinalURL != upstream.URL {
		t.Errorf("expected finalUrl=%s, got %s", upstream.URL, resp.FinalURL)
	}
	if resp.Status != 200 {
		t.Errorf("expected status=200, got %d", resp.Status)
	}
	if !strings.Contains(resp.HTML, "<title>Test</title>") {
		t.Error("expected HTML to contain <title>Test</title>")
	}
	if resp.Size == 0 {
		t.Error("expected size > 0")
	}
	if resp.Error != nil {
		t.Errorf("expected no error, got %v", resp.Error)
	}
	// Redirect chain should contain exactly the final hop (no redirects).
	if len(resp.RedirectChain) != 1 {
		t.Errorf("expected 1 hop in redirect chain, got %d", len(resp.RedirectChain))
	}
	if got := resp.Headers["Server"]; len(got) != 1 || got[0] != "TestServer" {
		t.Errorf("expected Server=[TestServer] in headers, got %v", got)
	}
	if resp.RawHeaders == "" {
		t.Error("expected rawHeaders to be non-empty")
	}
	if resp.Timing["total"] == 0 {
		t.Error("expected timing.total > 0")
	}
}

func TestPage_WithRedirect(t *testing.T) {
	// Use a single server that redirects on first path and serves on second.
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/final")
		w.Header().Set("Server", "RedirectServer")
		w.WriteHeader(http.StatusMovedPermanently)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "FinalServer")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("<html>final</html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := newTestConfig()
	cfg.allowedOrigins = nil
	cfg.ssrfCheck = func(string) bool { return false }
	// Use a client that does not auto-follow redirects (like production).
	client := srv.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	handler := pageHandler(cfg, client)

	req := httptest.NewRequest(http.MethodGet, "/page?url="+srv.URL+"/start", nil)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", rr.Code, rr.Body.String())
	}

	var resp pageResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("could not decode page response: %v", err)
	}

	if resp.URL != srv.URL+"/start" {
		t.Errorf("expected url=%s/start, got %s", srv.URL, resp.URL)
	}
	if resp.FinalURL != srv.URL+"/final" {
		t.Errorf("expected finalUrl=%s/final, got %s", srv.URL, resp.FinalURL)
	}
	// Redirect chain: hop 1 (301 redirect) + hop 2 (final GET 200).
	if len(resp.RedirectChain) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(resp.RedirectChain))
	}
	if resp.RedirectChain[0].Status != 301 {
		t.Errorf("expected first hop status=301, got %d", resp.RedirectChain[0].Status)
	}
	if resp.RedirectChain[0].Server != "RedirectServer" {
		t.Errorf("expected first hop server=RedirectServer, got %q", resp.RedirectChain[0].Server)
	}
	if resp.RedirectChain[1].Status != 200 {
		t.Errorf("expected second hop status=200, got %d", resp.RedirectChain[1].Status)
	}
	if !strings.Contains(resp.HTML, "final") {
		t.Error("expected HTML to contain 'final'")
	}
}

func TestPage_FormatRawHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Type", "text/html")
	h.Set("Server", "Apache")
	raw := formatRawHeaders(h)
	if !strings.Contains(raw, "Content-Type: text/html") {
		t.Errorf("expected Content-Type in raw headers, got %q", raw)
	}
	if !strings.Contains(raw, "Server: Apache") {
		t.Errorf("expected Server in raw headers, got %q", raw)
	}
}

// -----------------------------------------------------------------------
// isBlockedIP — extended range coverage (S2)
// -----------------------------------------------------------------------

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
		why     string
	}{
		{"127.0.0.1", true, "loopback"},
		{"10.1.2.3", true, "RFC 1918"},
		{"172.16.0.1", true, "RFC 1918"},
		{"192.168.1.1", true, "RFC 1918"},
		{"169.254.169.254", true, "link-local cloud metadata"},
		{"100.64.0.1", true, "CGNAT"},
		{"0.0.0.0", true, "this network"},
		{"192.0.0.1", true, "IETF protocol assignments"},
		{"198.18.0.1", true, "benchmarking"},
		{"224.0.0.1", true, "multicast"},
		{"255.255.255.255", true, "broadcast"},
		{"::1", true, "IPv6 loopback"},
		{"::", true, "IPv6 unspecified"},
		{"fc00::1", true, "unique local"},
		{"fe80::1", true, "IPv6 link-local"},
		{"ff02::1", true, "IPv6 multicast"},

		// Addresses that embed an IPv4 target inside IPv6. These are the
		// bypasses a naive v4-only check misses entirely.
		{"::ffff:127.0.0.1", true, "IPv4-mapped loopback"},
		{"::ffff:192.168.1.1", true, "IPv4-mapped RFC 1918"},
		{"64:ff9b::7f00:1", true, "NAT64-encoded loopback"},
		{"2002:7f00:1::", true, "6to4-encoded loopback"},

		{"8.8.8.8", false, "public"},
		{"1.1.1.1", false, "public"},
		{"93.184.216.34", false, "public"},
		{"2606:4700:4700::1111", false, "public IPv6"},
	}

	for _, tc := range tests {
		ip := net.ParseIP(tc.ip)
		if ip == nil {
			t.Fatalf("test setup: %q is not a valid IP", tc.ip)
		}
		if got := isBlockedIP(ip); got != tc.blocked {
			t.Errorf("isBlockedIP(%s) = %v, want %v (%s)", tc.ip, got, tc.blocked, tc.why)
		}
	}
}

func TestIsBlockedIP_NilIsBlocked(t *testing.T) {
	if !isBlockedIP(nil) {
		t.Error("a nil IP must be refused rather than allowed through")
	}
}

// -----------------------------------------------------------------------
// safeDialControl — the authoritative SSRF boundary (S1)
// -----------------------------------------------------------------------

func TestSafeDialControl(t *testing.T) {
	if err := safeDialControl("tcp", "127.0.0.1:8080", nil); err == nil {
		t.Error("expected loopback dial to be refused")
	} else if !errors.Is(err, errBlockedTarget) {
		t.Errorf("expected errBlockedTarget, got %v", err)
	}

	if err := safeDialControl("tcp", "[::1]:8080", nil); !errors.Is(err, errBlockedTarget) {
		t.Errorf("expected IPv6 loopback to be refused, got %v", err)
	}

	if err := safeDialControl("tcp", "8.8.8.8:443", nil); err != nil {
		t.Errorf("expected public address to be allowed, got %v", err)
	}
}

// The pre-flight hostname check can be fooled by DNS rebinding because it
// resolves the name separately from the transport. This test pins the property
// that actually protects us: even with the pre-check disabled entirely, a
// connection to a loopback address is refused at dial time.
func TestUpstreamClient_BlocksLoopbackDespiteDisabledPreCheck(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("should never be reached"))
	}))
	defer upstream.Close()

	cfg := newTestConfig()
	// Simulates a successful rebinding attack: the pre-check saw a public
	// address and waved the request through.
	cfg.ssrfCheck = func(string) bool { return false }

	client := newUpstreamClient(cfg)
	resp, err := client.Get(upstream.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected the dialer to refuse a connection to 127.0.0.1")
	}
	if !errors.Is(err, errBlockedTarget) {
		t.Errorf("expected errBlockedTarget, got %v", err)
	}

	code, _ := classifyUpstreamError(err)
	if code != "blocked_target" {
		t.Errorf("expected error code blocked_target, got %q", code)
	}
}

func TestClassifyUpstreamError_BlockedTarget(t *testing.T) {
	// Mirrors how the error reaches us in production: wrapped by net.OpError
	// (which alone would be classified as a mere connection failure).
	wrapped := &net.OpError{
		Op:  "dial",
		Net: "tcp",
		Err: fmt.Errorf("%w: 127.0.0.1", errBlockedTarget),
	}
	code, msg := classifyUpstreamError(wrapped)
	if code != "blocked_target" {
		t.Errorf("expected blocked_target, got %q", code)
	}
	if strings.Contains(msg, "127.0.0.1") {
		t.Errorf("message must not leak the resolved address, got %q", msg)
	}
}

// -----------------------------------------------------------------------
// Host-header validation (S6)
// -----------------------------------------------------------------------

func TestIsLocalHostname(t *testing.T) {
	tests := []struct {
		host  string
		local bool
	}{
		{"127.0.0.1:8765", true},
		{"127.0.0.1", true},
		{"127.5.6.7:8765", true},
		{"localhost:8765", true},
		{"localhost", true},
		{"LOCALHOST:8765", true},
		{"[::1]:8765", true},
		{"attacker.example.com:8765", false},
		{"192.168.1.10:8765", false},
		{"", false},
	}
	for _, tc := range tests {
		if got := isLocalHostname(tc.host); got != tc.local {
			t.Errorf("isLocalHostname(%q) = %v, want %v", tc.host, got, tc.local)
		}
	}
}

func TestLocalhostOnly(t *testing.T) {
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	cfg := newTestConfig()
	handler := localhostOnly(cfg, next)

	// A hostname the attacker controls, pointed at 127.0.0.1.
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Host = "rebind.attacker.example:8765"
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403 for foreign Host, got %d", rr.Code)
	}
	if reached {
		t.Error("handler must not run for a non-local Host header")
	}

	// The address users actually type.
	reached = false
	req = httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Host = "localhost:8765"
	rr = httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if !reached {
		t.Error("localhost must be accepted — users type it by hand")
	}
}

func TestLocalhostOnly_EscapeHatch(t *testing.T) {
	reached := false
	cfg := newTestConfig()
	cfg.allowAnyHost = true
	handler := localhostOnly(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Host = "anything.example.com"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	if !reached {
		t.Error("--allow-any-host should bypass the check")
	}
}

// -----------------------------------------------------------------------
// Constant-time token comparison (S7)
// -----------------------------------------------------------------------

func TestConfigTokenValid(t *testing.T) {
	cfg := newTestConfig()

	tests := []struct {
		token string
		valid bool
	}{
		{cfg.sessionToken, true},
		{"", false},
		{"wrong-token", false},
		{cfg.sessionToken + "x", false},
		{cfg.sessionToken[:len(cfg.sessionToken)-1], false},
	}
	for _, tc := range tests {
		req := httptest.NewRequest(http.MethodGet, "/proxy", nil)
		if tc.token != "" {
			req.Header.Set("X-Proxy-Token", tc.token)
		}
		if got := cfg.tokenValid(req); got != tc.valid {
			t.Errorf("tokenValid(%q) = %v, want %v", tc.token, got, tc.valid)
		}
	}
}

// -----------------------------------------------------------------------
// CORS on 4xx responses (S9)
// -----------------------------------------------------------------------

// Without CORS headers the browser rejects the response before JavaScript can
// read it, so a wrong token is indistinguishable from an unreachable proxy.
func TestErrorResponses_AreReadableByTheCaller(t *testing.T) {
	cfg := newTestConfig()

	tests := []struct {
		name       string
		target     string
		token      string
		method     string
		wantStatus int
		wantCode   string
	}{
		{"bad token", "/proxy?url=https://example.com", "nope", http.MethodGet, http.StatusForbidden, "forbidden"},
		{"missing url", "/proxy", cfg.sessionToken, http.MethodGet, http.StatusBadRequest, "bad_request"},
		{"invalid url", "/proxy?url=ftp://example.com", cfg.sessionToken, http.MethodGet, http.StatusBadRequest, "bad_request"},
		{"bad method", "/proxy?url=https://example.com", cfg.sessionToken, http.MethodPut, http.StatusMethodNotAllowed, "method_not_allowed"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			handler := proxyHandler(cfg, http.DefaultClient)
			req := httptest.NewRequest(tc.method, tc.target, nil)
			req.Header.Set("Origin", "https://test.example.com")
			req.Header.Set("X-Proxy-Token", tc.token)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("expected %d, got %d", tc.wantStatus, rr.Code)
			}
			if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://test.example.com" {
				t.Errorf("error response is unreadable by the caller: Allow-Origin = %q", got)
			}

			var perr proxyError
			if err := json.Unmarshal(rr.Body.Bytes(), &perr); err != nil {
				t.Fatalf("expected a JSON error body, got %q", rr.Body.String())
			}
			if perr.Error != tc.wantCode {
				t.Errorf("expected code %q, got %q", tc.wantCode, perr.Error)
			}
			if perr.Status != tc.wantStatus {
				t.Errorf("expected status %d in body, got %d", tc.wantStatus, perr.Status)
			}
		})
	}
}

// A rejected origin must NOT receive CORS headers — the response is not meant
// to be readable by the origin that was just turned away.
func TestRejectedOrigin_GetsNoCORSHeaders(t *testing.T) {
	cfg := newTestConfig()
	handler := proxyHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/proxy?url=https://example.com", nil)
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("expected no Allow-Origin for a rejected origin, got %q", got)
	}
}

func TestSSRFBlock_ReturnsStructuredError(t *testing.T) {
	cfg := newTestConfig()
	cfg.ssrfCheck = func(string) bool { return true }
	handler := proxyHandler(cfg, http.DefaultClient)

	req := httptest.NewRequest(http.MethodGet, "/proxy?url=http://169.254.169.254/latest/meta-data/", nil)
	req.Header.Set("Origin", "https://test.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Code)
	}
	var perr proxyError
	if err := json.Unmarshal(rr.Body.Bytes(), &perr); err != nil {
		t.Fatalf("expected JSON body, got %q", rr.Body.String())
	}
	if perr.Error != "blocked_target" {
		t.Errorf("expected blocked_target, got %q", perr.Error)
	}
}

// -----------------------------------------------------------------------
// Vary: Origin (Q4)
// -----------------------------------------------------------------------

func TestVaryOrigin_SetEvenWithoutAllowOrigin(t *testing.T) {
	cfg := newTestConfig()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("Origin", "https://not-allowed.example.com")

	writeCORSHeaders(rr, req, cfg)

	if rr.Header().Get("Vary") != "Origin" {
		t.Errorf("Vary: Origin must be set regardless of the CORS decision, got %q", rr.Header().Get("Vary"))
	}
}

// -----------------------------------------------------------------------
// Request-header filtering (S5, Q9)
// -----------------------------------------------------------------------

func TestCopyRequestHeaders_StripsSensitiveHeaders(t *testing.T) {
	src := httptest.NewRequest(http.MethodGet, "/proxy?url=https://example.com", nil)
	src.Header.Set("Cookie", "session=secret")
	src.Header.Set("Authorization", "Bearer secret")
	src.Header.Set("Origin", "https://www.jpkc.com")
	src.Header.Set("Referer", "https://www.jpkc.com/tools/seo/")
	src.Header.Set("Sec-Fetch-Mode", "cors")
	src.Header.Set("X-Proxy-Token", "the-session-token")
	// Credential headers (AUTH-3) and underscore spellings of blocked names:
	// raw map keys, as a non-browser caller can send them.
	src.Header.Set("X-Target-Authorization", "Basic dGVzdA==")
	src.Header.Set("X-Target-Origin", "https://example.com")
	src.Header["X_Proxy_Token"] = []string{"the-session-token"}
	src.Header["X_Target_Authorization"] = []string{"Basic dGVzdA=="}
	// Headers the tools rely on and that must survive.
	src.Header.Set("Accept", "text/markdown")
	src.Header.Set("User-Agent", "Mozilla/5.0")
	src.Header.Set("Accept-Language", "de-DE")
	src.Header.Set("X-Requested-With", "XMLHttpRequest")

	dst := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	dst.Header = http.Header{}
	copyRequestHeaders(src, dst)

	for _, h := range []string{"Cookie", "Authorization", "Origin", "Referer", "Sec-Fetch-Mode", "X-Proxy-Token",
		"X-Target-Authorization", "X-Target-Origin"} {
		if v := dst.Header.Get(h); v != "" {
			t.Errorf("%s must not reach the upstream target, got %q", h, v)
		}
	}
	for _, h := range []string{"X_Proxy_Token", "X_Target_Authorization"} {
		if v, ok := dst.Header[h]; ok {
			t.Errorf("%s must not reach the upstream target, got %q", h, v)
		}
	}
	for h, want := range map[string]string{
		"Accept":           "text/markdown",
		"User-Agent":       "Mozilla/5.0",
		"Accept-Language":  "de-DE",
		"X-Requested-With": "XMLHttpRequest",
	} {
		if got := dst.Header.Get(h); got != want {
			t.Errorf("%s should be forwarded as %q, got %q", h, want, got)
		}
	}
}

func TestCopyRequestHeaders_DropsConnectionListedHeaders(t *testing.T) {
	src := httptest.NewRequest(http.MethodGet, "/proxy?url=https://example.com", nil)
	src.Header.Set("Connection", "X-Custom-Hop, Keep-Alive")
	src.Header.Set("X-Custom-Hop", "should-not-survive")
	src.Header.Set("X-Kept", "should-survive")

	dst := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	dst.Header = http.Header{}
	copyRequestHeaders(src, dst)

	if v := dst.Header.Get("X-Custom-Hop"); v != "" {
		t.Errorf("headers named in Connection are hop-by-hop, got %q", v)
	}
	if v := dst.Header.Get("X-Kept"); v != "should-survive" {
		t.Errorf("unrelated headers must survive, got %q", v)
	}
}

// -----------------------------------------------------------------------
// Decompression (Q1)
// -----------------------------------------------------------------------

func TestNewDecompressor(t *testing.T) {
	const payload = "<html><body>Hallo Welt</body></html>"

	// "deflate" is ambiguous in the wild: RFC 7230 says zlib, many servers
	// send raw DEFLATE. Both must decode.
	var zlibBuf bytes.Buffer
	zw := zlib.NewWriter(&zlibBuf)
	zw.Write([]byte(payload))
	zw.Close()

	var flateBuf bytes.Buffer
	fw, _ := flate.NewWriter(&flateBuf, flate.DefaultCompression)
	fw.Write([]byte(payload))
	fw.Close()

	tests := []struct {
		name     string
		data     []byte
		encoding string
	}{
		{"zlib-wrapped deflate", zlibBuf.Bytes(), "deflate"},
		{"raw deflate", flateBuf.Bytes(), "deflate"},
		{"uppercase encoding token", zlibBuf.Bytes(), "DEFLATE"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec, err := newDecompressor(bytes.NewReader(tc.data), tc.encoding)
			if err != nil {
				t.Fatalf("newDecompressor: %v", err)
			}
			if dec == nil {
				t.Fatal("expected a decoder for deflate")
			}
			defer dec.Close()

			got, err := io.ReadAll(dec)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if string(got) != payload {
				t.Errorf("expected %q, got %q", payload, string(got))
			}
		})
	}
}

func TestNewDecompressor_PassesThroughUnknownEncodings(t *testing.T) {
	// br and zstd cannot be decoded with the stdlib; the body is forwarded
	// verbatim rather than mangled.
	for _, enc := range []string{"", "identity", "br", "zstd"} {
		dec, err := newDecompressor(strings.NewReader("raw"), enc)
		if err != nil {
			t.Errorf("encoding %q: unexpected error %v", enc, err)
		}
		if dec != nil {
			t.Errorf("encoding %q: expected no decoder", enc)
		}
	}
}

// -----------------------------------------------------------------------
// Response truncation (S8)
// -----------------------------------------------------------------------

// Forwarding the upstream Content-Length while truncating the body promises
// more bytes than are delivered; net/http then aborts the connection and the
// caller sees a generic network error instead of a short body.
func TestProxy_TruncatedBodyDropsContentLength(t *testing.T) {
	const upstreamSize = 4096
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", upstreamSize))
		w.Write(bytes.Repeat([]byte("x"), upstreamSize))
	}))
	defer upstream.Close()

	cfg := newTestConfig()
	cfg.ssrfCheck = func(string) bool { return false }
	cfg.maxResponseBytes = 100

	handler := proxyHandler(cfg, &http.Client{Timeout: 5 * time.Second})
	req := httptest.NewRequest(http.MethodGet, "/proxy?url="+upstream.URL, nil)
	req.Header.Set("Origin", "https://test.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("Content-Length"); got != "" {
		t.Errorf("Content-Length must be dropped when the body is truncated, got %q", got)
	}
	if got := rr.Header().Get("X-Upstream-Truncated"); got != "1" {
		t.Errorf("expected X-Upstream-Truncated: 1, got %q", got)
	}
	if got := rr.Header().Get("X-Upstream-Content-Length"); got != fmt.Sprintf("%d", upstreamSize) {
		t.Errorf("expected the true upstream size to still be reported, got %q", got)
	}
	if rr.Body.Len() != int(cfg.maxResponseBytes) {
		t.Errorf("expected body capped at %d, got %d", cfg.maxResponseBytes, rr.Body.Len())
	}
}

func TestProxy_UntruncatedBodyKeepsContentLength(t *testing.T) {
	body := "small enough"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.Write([]byte(body))
	}))
	defer upstream.Close()

	cfg := newTestConfig()
	cfg.ssrfCheck = func(string) bool { return false }

	handler := proxyHandler(cfg, &http.Client{Timeout: 5 * time.Second})
	req := httptest.NewRequest(http.MethodGet, "/proxy?url="+upstream.URL, nil)
	req.Header.Set("Origin", "https://test.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if got := rr.Header().Get("X-Upstream-Truncated"); got != "" {
		t.Errorf("did not expect a truncation marker, got %q", got)
	}
	if rr.Body.String() != body {
		t.Errorf("expected %q, got %q", body, rr.Body.String())
	}
}

// A compressed body without Content-Length (chunked) is buffered before the
// headers go out, so a cut there must be announced too — unlike the plain
// chunked stream, whose headers are already sent when the cap hits.
func TestProxy_TruncatedCompressedChunked(t *testing.T) {
	var page strings.Builder
	for i := 0; i < 5000; i++ {
		fmt.Fprintf(&page, "<p>paragraph %d</p>", i)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(page.String()))
	zw.Close()
	compressed := gz.Bytes()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush() // no Content-Length: chunked
		w.Write(compressed)
	}))
	defer upstream.Close()

	run := func(t *testing.T, limit int64) *httptest.ResponseRecorder {
		t.Helper()
		cfg := newTestConfig()
		cfg.ssrfCheck = func(string) bool { return false }
		cfg.maxResponseBytes = limit
		req := httptest.NewRequest(http.MethodGet, "/proxy?url="+upstream.URL, nil)
		req.Header.Set("Origin", "https://test.example.com")
		req.Header.Set("X-Proxy-Token", cfg.sessionToken)
		// Keeps Go's transport from decompressing transparently.
		req.Header.Set("Accept-Encoding", "gzip")
		rr := httptest.NewRecorder()
		proxyHandler(cfg, &http.Client{Timeout: 5 * time.Second}).ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if got := rr.Header().Get("X-Upstream-Content-Encoding"); got != "gzip" {
			t.Fatalf("upstream was not compressed: X-Upstream-Content-Encoding=%q", got)
		}
		if got := rr.Header().Get("Content-Length"); got != "" {
			t.Errorf("no Content-Length expected in the buffered branch, got %q", got)
		}
		return rr
	}

	t.Run("over the cap", func(t *testing.T) {
		const limit = 1000
		if len(compressed) <= limit {
			t.Fatalf("test body too small: %d bytes", len(compressed))
		}
		rr := run(t, limit)
		if got := rr.Header().Get("X-Upstream-Truncated"); got != "1" {
			t.Errorf("expected X-Upstream-Truncated: 1, got %q", got)
		}
		if rr.Body.Len() != limit || !bytes.Equal(rr.Body.Bytes(), compressed[:limit]) {
			t.Errorf("expected the first %d compressed bytes, got %d bytes", limit, rr.Body.Len())
		}
		if got := rr.Header().Get("X-Upstream-Content-Length"); got != fmt.Sprintf("%d", limit) {
			t.Errorf("X-Upstream-Content-Length = %q", got)
		}
	})

	t.Run("under the cap", func(t *testing.T) {
		rr := run(t, int64(len(compressed))+1)
		if got := rr.Header().Get("X-Upstream-Truncated"); got != "" {
			t.Errorf("did not expect a truncation marker, got %q", got)
		}
		if !bytes.Equal(rr.Body.Bytes(), compressed) {
			t.Errorf("body differs: got %d bytes, want %d", rr.Body.Len(), len(compressed))
		}
		if got := rr.Header().Get("X-Upstream-Content-Length"); got != fmt.Sprintf("%d", len(compressed)) {
			t.Errorf("X-Upstream-Content-Length = %q, want %d", got, len(compressed))
		}
	})

	t.Run("exactly the cap", func(t *testing.T) {
		rr := run(t, int64(len(compressed)))
		if got := rr.Header().Get("X-Upstream-Truncated"); got != "" {
			t.Errorf("a body of exactly the cap is not truncated, got %q", got)
		}
		if !bytes.Equal(rr.Body.Bytes(), compressed) {
			t.Errorf("body differs: got %d bytes, want %d", rr.Body.Len(), len(compressed))
		}
	})
}

// -----------------------------------------------------------------------
// /page time budget (S3)
// -----------------------------------------------------------------------

func TestPageBudget_IsBoundedButLargerThanASingleRequest(t *testing.T) {
	cfg := newTestConfig()
	if cfg.pageBudget() <= cfg.requestTimeout {
		t.Error("/page performs several upstream requests and needs more headroom than one")
	}
	if cfg.pageBudget() > 10*cfg.requestTimeout {
		t.Error("the budget must stay tightly bounded")
	}
}

// -----------------------------------------------------------------------
// SSL IP SANs (Q7)
// -----------------------------------------------------------------------

func TestExtractSSLInfo_IncludesIPSANs(t *testing.T) {
	cert := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "example.com"},
		Issuer:      pkix.Name{CommonName: "Test CA"},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().Add(24 * time.Hour),
		DNSNames:    []string{"example.com", "www.example.com"},
		IPAddresses: []net.IP{net.ParseIP("93.184.216.34")},
	}
	state := &tls.ConnectionState{
		Version:          tls.VersionTLS13,
		PeerCertificates: []*x509.Certificate{cert},
	}

	info := extractSSLInfo(state, "")
	if info == nil {
		t.Fatal("expected SSL info")
	}
	joined := strings.Join(info.SANs, ",")
	for _, want := range []string{"example.com", "www.example.com", "93.184.216.34"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected SAN %q in %q", want, joined)
		}
	}
}

// -----------------------------------------------------------------------
// HTTP/3 detection via Alt-Svc
// -----------------------------------------------------------------------

func TestAltSvcAdvertisesHTTP3(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   bool
		why    string
	}{
		{
			name:   "cloudflare",
			values: []string{`h3=":443"; ma=86400`},
			want:   true,
		},
		{
			name:   "google advertises final and draft",
			values: []string{`h3=":443"; ma=2592000,h3-29=":443"; ma=2592000`},
			want:   true,
		},
		{
			name:   "h3 listed after another protocol",
			values: []string{`h2=":443"; ma=3600, h3=":443"; ma=3600`},
			want:   true,
		},
		{
			name:   "repeated header fields",
			values: []string{`h2=":443"`, `h3=":443"`},
			want:   true,
		},
		{
			name:   "alternative host and port",
			values: []string{`h3="alt.example.com:8443"; ma=3600`},
			want:   true,
		},
		{
			name:   "token case is insensitive",
			values: []string{`H3=":443"`},
			want:   true,
		},

		{
			name:   "draft only",
			values: []string{`h3-29=":443"; ma=2592000, h3-Q050=":443"`},
			want:   false,
			why:    "pre-RFC drafts are not negotiated by current browsers",
		},
		{
			name:   "clear",
			values: []string{"clear"},
			want:   false,
		},
		{
			name:   "no alt-svc at all",
			values: nil,
			want:   false,
		},
		{
			name:   "http2 only",
			values: []string{`h2=":443"; ma=3600`},
			want:   false,
		},
		{
			name:   "h3 only as a parameter value, not a protocol id",
			values: []string{`h2=":443"; note="h3"`},
			want:   false,
			why:    "the protocol id is the part before the first =",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			for _, v := range tc.values {
				h.Add("Alt-Svc", v)
			}
			if got := altSvcAdvertisesHTTP3(h); got != tc.want {
				msg := tc.why
				if msg == "" {
					msg = "unexpected result"
				}
				t.Errorf("altSvcAdvertisesHTTP3(%q) = %v, want %v — %s", tc.values, got, tc.want, msg)
			}
		})
	}
}

// A comma inside the quoted alt-authority must not be mistaken for the
// separator between alt-values.
func TestSplitAltSvcValues_RespectsQuotes(t *testing.T) {
	got := splitAltSvcValues(`h2="a,b:443"; ma=1, h3=":443"`)
	if len(got) != 2 {
		t.Fatalf("expected 2 alt-values, got %d: %q", len(got), got)
	}
	if !strings.Contains(got[0], "a,b:443") {
		t.Errorf("quoted comma was split, got %q", got[0])
	}
	if !strings.Contains(got[1], "h3") {
		t.Errorf("expected h3 in the second value, got %q", got[1])
	}
}

func TestInspect_ReportsHTTP3(t *testing.T) {
	for _, tc := range []struct {
		name   string
		altSvc string
		want   bool
	}{
		{"advertised", `h3=":443"; ma=86400`, true},
		{"not advertised", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.altSvc != "" {
					w.Header().Set("Alt-Svc", tc.altSvc)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			cfg := newTestConfig()
			cfg.ssrfCheck = func(string) bool { return false }

			handler := inspectHandler(cfg, &http.Client{Timeout: 5 * time.Second})
			req := httptest.NewRequest(http.MethodGet, "/inspect?url="+upstream.URL, nil)
			req.Header.Set("Origin", "https://test.example.com")
			req.Header.Set("X-Proxy-Token", cfg.sessionToken)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rr.Code)
			}
			var result inspectResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if result.HTTP3 != tc.want {
				t.Errorf("expected http3 = %v, got %v", tc.want, result.HTTP3)
			}
		})
	}
}

func TestPage_ReportsHTTP3(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Alt-Svc", `h3=":443"; ma=86400,h3-29=":443"; ma=86400`)
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>ok</body></html>"))
	}))
	defer upstream.Close()

	cfg := newTestConfig()
	cfg.ssrfCheck = func(string) bool { return false }

	handler := pageHandler(cfg, &http.Client{Timeout: 5 * time.Second})
	req := httptest.NewRequest(http.MethodGet, "/page?url="+upstream.URL, nil)
	req.Header.Set("Origin", "https://test.example.com")
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var result pageResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !result.HTTP3 {
		t.Error("expected http3 = true")
	}
	// http3 describes the target's capability, not the protocol we just used.
	if strings.Contains(result.HTTPVersion, "3") {
		t.Errorf("httpVersion should still report the transport actually used, got %q", result.HTTPVersion)
	}
}

// =======================================================================
// v1.3.0 — certificate report, TLS diagnosis, /inspect additions
// =======================================================================

// -----------------------------------------------------------------------
// Test PKI helpers
// -----------------------------------------------------------------------

// certOpts describes a test certificate. Zero values get sensible defaults:
// valid from an hour ago for 90 days, a P-256 key, a random serial.
type certOpts struct {
	cn, org             string
	extraNames          []pkix.AttributeTypeAndValue // full subject in DER order; overrides cn/org
	dns                 []string
	ips                 []net.IP
	notBefore, notAfter time.Time
	isCA                bool
	key                 string // "rsa2048", "rsa1024", "p256" (default), "p384", "ed25519"
	sigAlg              x509.SignatureAlgorithm
	serial              *big.Int
}

var (
	testKeysMu sync.Mutex
	testKeys   = map[string]crypto.Signer{}
)

// testKey returns a cached key of the given kind. slot keeps keys of different
// certificates apart — two certificates sharing a key would make a wrong
// issuer look like a valid signer.
func testKey(t *testing.T, kind, slot string) crypto.Signer {
	t.Helper()
	testKeysMu.Lock()
	defer testKeysMu.Unlock()
	if k, ok := testKeys[kind+"/"+slot]; ok {
		return k
	}
	var (
		k   crypto.Signer
		err error
	)
	switch kind {
	case "rsa2048":
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	case "rsa1024":
		k, err = rsa.GenerateKey(rand.Reader, 1024)
	case "p384":
		k, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case "ed25519":
		_, k, err = ed25519.GenerateKey(rand.Reader)
	default:
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatalf("generate %s key: %v", kind, err)
	}
	testKeys[kind+"/"+slot] = k
	return k
}

// newCert creates a certificate signed by parent/parentKey, or self-signed
// when parent is nil. Returns the parsed certificate, its key and the DER.
func newCert(t *testing.T, o certOpts, parent *x509.Certificate, parentKey crypto.Signer) (*x509.Certificate, crypto.Signer, []byte) {
	t.Helper()
	slot := o.cn + "|" + o.org
	if len(o.extraNames) > 0 {
		slot = fmt.Sprint(o.extraNames)
	}
	key := testKey(t, o.key, slot)

	if o.notBefore.IsZero() {
		o.notBefore = time.Now().Add(-time.Hour)
	}
	if o.notAfter.IsZero() {
		o.notAfter = time.Now().Add(90 * 24 * time.Hour)
	}
	if o.serial == nil {
		o.serial, _ = rand.Int(rand.Reader, big.NewInt(1<<62))
	}
	subject := pkix.Name{CommonName: o.cn}
	if o.org != "" {
		subject.Organization = []string{o.org}
	}
	if len(o.extraNames) > 0 {
		subject = pkix.Name{ExtraNames: o.extraNames}
	}

	tpl := &x509.Certificate{
		SerialNumber:          o.serial,
		Subject:               subject,
		NotBefore:             o.notBefore,
		NotAfter:              o.notAfter,
		DNSNames:              o.dns,
		IPAddresses:           o.ips,
		SignatureAlgorithm:    o.sigAlg,
		BasicConstraintsValid: true,
		IsCA:                  o.isCA,
	}
	if o.isCA {
		tpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
	} else {
		tpl.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	signer, issuer := key, tpl
	if parent != nil {
		signer, issuer = parentKey, parent
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, issuer, key.Public(), signer)
	if err != nil {
		t.Fatalf("create certificate %q: %v", o.cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate %q: %v", o.cn, err)
	}
	return cert, key, der
}

// testPKI is a root CA and an intermediate signed by it.
type testPKI struct {
	root, inter       *x509.Certificate
	rootKey, interKey crypto.Signer
	rootDER, interDER []byte
	pool              *x509.CertPool // contains the root only
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	p := &testPKI{}
	p.root, p.rootKey, p.rootDER = newCert(t, certOpts{cn: "Test Root CA", org: "Test PKI", isCA: true,
		notAfter: time.Now().Add(10 * 365 * 24 * time.Hour)}, nil, nil)
	p.inter, p.interKey, p.interDER = newCert(t, certOpts{cn: "Test Intermediate CA", org: "Test PKI", isCA: true,
		notAfter: time.Now().Add(5 * 365 * 24 * time.Hour)}, p.root, p.rootKey)
	p.pool = x509.NewCertPool()
	p.pool.AddCert(p.root)
	return p
}

// leaf issues a server certificate from the intermediate. Defaults to
// localhost / 127.0.0.1, which is what httptest servers listen on.
func (p *testPKI) leaf(t *testing.T, o certOpts) ([]byte, crypto.Signer) {
	t.Helper()
	if o.cn == "" {
		o.cn = "localhost"
	}
	if o.dns == nil && o.ips == nil {
		o.dns = []string{"localhost"}
		o.ips = []net.IP{net.ParseIP("127.0.0.1")}
	}
	_, key, der := newCert(t, o, p.inter, p.interKey)
	return der, key
}

// tlsServerWith starts an HTTPS test server presenting exactly chainDER.
func tlsServerWith(t *testing.T, chainDER [][]byte, key crypto.Signer, tweak func(*tls.Config), h http.Handler) *httptest.Server {
	t.Helper()
	if h == nil {
		h = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // failed handshakes are the point here
	cfg := &tls.Config{Certificates: []tls.Certificate{{Certificate: chainDER, PrivateKey: key}}}
	if tweak != nil {
		tweak(cfg)
	}
	srv.TLS = cfg
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

// allowAllDial stands in for safeDialControl so tests can reach 127.0.0.1.
func allowAllDial(_, _ string, _ syscall.RawConn) error { return nil }

// testCfg is newTestConfig with every origin allowed, the SSRF pre-check off,
// a dialer that may reach loopback and roots as the trust store.
func testCfg(t *testing.T, roots *x509.CertPool) *config {
	t.Helper()
	cfg := newTestConfig()
	cfg.allowedOrigins = nil
	cfg.ssrfCheck = func(string) bool { return false }
	cfg.dialControl = allowAllDial
	cfg.rootCAs = roots
	return cfg
}

// doInspect runs one /inspect request through the real upstream client.
func doInspect(t *testing.T, cfg *config, target, extra string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/inspect?url="+url.QueryEscape(target)+extra, nil)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()
	inspectHandler(cfg, newUpstreamClient(cfg)).ServeHTTP(rr, req)
	return rr
}

func decodeInspect(t *testing.T, rr *httptest.ResponseRecorder) inspectResponse {
	t.Helper()
	var resp inspectResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode inspect response: %v — body: %s", err, rr.Body.String())
	}
	return resp
}

func serverPort(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	return port
}

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

func fmtBoolPtr(b *bool) string {
	if b == nil {
		return "null"
	}
	return fmt.Sprint(*b)
}

// md5CertPEM is a self-signed certificate with an md5WithRSAEncryption
// signature (RSA 1024). crypto/x509 can no longer create such certificates, so
// it was generated once with:
//
//	openssl req -x509 -newkey rsa:1024 -md5 -nodes -subj /CN=md5.test -days 36500
const md5CertPEM = `-----BEGIN CERTIFICATE-----
MIICBDCCAW2gAwIBAgIUS9zUXYhVSMHifaSKCwIaasS2mMcwDQYJKoZIhvcNAQEE
BQAwEzERMA8GA1UEAwwIbWQ1LnRlc3QwIBcNMjYxMDIxMTA0MzE5WhgPMjEyNjA5
MjcxMDQzMTlaMBMxETAPBgNVBAMMCG1kNS50ZXN0MIGfMA0GCSqGSIb3DQEBAQUA
A4GNADCBiQKBgQDrPidON5lkzt7nyISRKrvbWSos/jvAfsPWEocA/aCyphySu776
VmWqtKJEIcQyIYe3NIZrg18de5yBlm6gCzBqERvqqVKMF+nXyKSPcSxYGA+jKXDU
oSDgmXBGW08kxxHmq3lPisPkPhPPjTPaqPArH2kv8fL2hi+DWAIwCHGtIQIDAQAB
o1MwUTAdBgNVHQ4EFgQURY8shMedW9VDY98CLzQF6wR3zfkwHwYDVR0jBBgwFoAU
RY8shMedW9VDY98CLzQF6wR3zfkwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0B
AQQFAAOBgQDdQU+1mRJWxvWMDiPF1oNZPPYDk8j/e2TiAyayjE4o8KZsf1OMplrS
JC8F4SFPwoOOLoFA80CoCczhHDcdww8Itor0pihOaPOF5lCMjt+PfhBtLG4v8g9q
mkK3Hw8uUV27sr6g9XOJHrwSaiqIswhqo8PmChi8v51RZRKm3/Nb4w==
-----END CERTIFICATE-----
`

// -----------------------------------------------------------------------
// Pure certificate helpers
// -----------------------------------------------------------------------

func TestTLSProtocolName(t *testing.T) {
	for v, want := range map[uint16]string{
		0x0300:           "SSLv3",
		tls.VersionTLS10: "TLSv1",
		tls.VersionTLS11: "TLSv1.1",
		tls.VersionTLS12: "TLSv1.2",
		tls.VersionTLS13: "TLSv1.3",
		0x7f1c:           "",
	} {
		if got := tlsProtocolName(v); got != want {
			t.Errorf("tlsProtocolName(0x%04x) = %q, want %q", v, got, want)
		}
	}
}

// Every suite Go can negotiate — including the insecure ones the probe offers
// — must have an OpenSSL name and a strength, or the report silently falls
// back to IANA names for exactly the legacy servers it exists to describe.
func TestOpenSSLCipherName(t *testing.T) {
	suites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
	for _, s := range suites {
		name, bits := openSSLCipherName(s.ID)
		if bits <= 0 {
			t.Errorf("%s: no strength in the OpenSSL table", s.Name)
		}
		if name == s.Name && !strings.HasPrefix(s.Name, "TLS_AES_") && !strings.HasPrefix(s.Name, "TLS_CHACHA20_") {
			t.Errorf("%s: no OpenSSL name in the table", s.Name)
		}
	}

	for id, want := range map[uint16]openSSLCipher{
		tls.TLS_AES_128_GCM_SHA256:                {"TLS_AES_128_GCM_SHA256", 128},
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: {"ECDHE-RSA-AES128-GCM-SHA256", 128},
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:          {"AES128-SHA", 128},
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:         {"DES-CBC3-SHA", 112},
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:        {"ECDHE-RSA-RC4-SHA", 128},
	} {
		if name, bits := openSSLCipherName(id); name != want.name || bits != want.bits {
			t.Errorf("openSSLCipherName(0x%04x) = %q/%d, want %q/%d", id, name, bits, want.name, want.bits)
		}
	}

	if name, bits := openSSLCipherName(0x00ff); name != tls.CipherSuiteName(0x00ff) || bits != 0 {
		t.Errorf("unknown suite: got %q/%d, want the IANA fallback and 0 bits", name, bits)
	}
}

func TestOpenSSLSigAlgName(t *testing.T) {
	for alg, want := range map[x509.SignatureAlgorithm]string{
		x509.MD2WithRSA:       "md2WithRSAEncryption",
		x509.MD5WithRSA:       "md5WithRSAEncryption",
		x509.SHA1WithRSA:      "sha1WithRSAEncryption",
		x509.SHA256WithRSA:    "sha256WithRSAEncryption",
		x509.SHA384WithRSA:    "sha384WithRSAEncryption",
		x509.SHA512WithRSA:    "sha512WithRSAEncryption",
		x509.SHA256WithRSAPSS: "rsassaPss",
		x509.SHA384WithRSAPSS: "rsassaPss",
		x509.SHA512WithRSAPSS: "rsassaPss",
		x509.DSAWithSHA1:      "dsaWithSHA1",
		x509.DSAWithSHA256:    "dsa_with_SHA256",
		x509.ECDSAWithSHA1:    "ecdsa-with-SHA1",
		x509.ECDSAWithSHA256:  "ecdsa-with-SHA256",
		x509.ECDSAWithSHA384:  "ecdsa-with-SHA384",
		x509.ECDSAWithSHA512:  "ecdsa-with-SHA512",
		x509.PureEd25519:      "ED25519",
	} {
		if got := openSSLSigAlgName(alg); got != want {
			t.Errorf("openSSLSigAlgName(%v) = %q, want %q", alg, got, want)
		}
	}
	if got := openSSLSigAlgName(x509.UnknownSignatureAlgorithm); got != x509.UnknownSignatureAlgorithm.String() {
		t.Errorf("unknown algorithm: got %q, want Go's own name", got)
	}
}

func TestFormatDN(t *testing.T) {
	oid := func(ids ...int) asn1.ObjectIdentifier { return ids }
	atv := func(o asn1.ObjectIdentifier, v string) pkix.AttributeTypeAndValue {
		return pkix.AttributeTypeAndValue{Type: o, Value: v}
	}

	// Parsed name: DER order, PHP's grouping of a repeated key at its first
	// position, and a dotted OID for an attribute without a short name.
	cert, _, _ := newCert(t, certOpts{extraNames: []pkix.AttributeTypeAndValue{
		atv(oid(2, 5, 4, 6), "US"),
		atv(oid(2, 5, 4, 11), "Domain Control Validated"),
		atv(oid(2, 5, 4, 3), "*.badssl.com"),
		atv(oid(2, 5, 4, 11), "PositiveSSL Wildcard"),
		atv(oid(1, 2, 3, 4), "custom"),
	}}, nil, nil)
	want := "C=US, OU=Domain Control Validated, OU=PositiveSSL Wildcard, CN=*.badssl.com, 1.2.3.4=custom"
	if got := formatDN(cert.Subject); got != want {
		t.Errorf("formatDN(parsed) = %q\n want %q", got, want)
	}

	// A name built in code has no Names; the convenience fields still count.
	built := pkix.Name{Country: []string{"DE"}, Organization: []string{"Example"}, CommonName: "example.com"}
	if got := formatDN(built); got != "C=DE, O=Example, CN=example.com" {
		t.Errorf("formatDN(built) = %q", got)
	}
	if got := formatDN(pkix.Name{}); got != "" {
		t.Errorf("formatDN(empty) = %q, want empty", got)
	}
}

func TestDaysUntil(t *testing.T) {
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		t    time.Time
		want int
	}{
		{now, 0},
		{now.Add(time.Second), 0},
		{now.Add(-time.Second), -1}, // floor, not truncation toward zero
		{now.Add(24 * time.Hour), 1},
		{now.Add(-24 * time.Hour), -1},
		{now.Add(-24*time.Hour - time.Second), -2},
		{time.Date(2049, 1, 1, 0, 0, 0, 0, time.UTC), 8108},
		{time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC), -28052},
		// RFC 5280's "no expiration": beyond time.Duration's ~292 years,
		// where t.Sub(now) would saturate at 106751 days.
		{time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC), 2912149},
		{time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC), -739909},
	} {
		if got := daysUntil(tc.t, now); got != tc.want {
			t.Errorf("daysUntil(%s) = %d, want %d", tc.t, got, tc.want)
		}
	}
}

func TestSetHopCert_FirstCN(t *testing.T) {
	cn := asn1.ObjectIdentifier{2, 5, 4, 3}
	leaf, _, _ := newCert(t, certOpts{extraNames: []pkix.AttributeTypeAndValue{
		{Type: cn, Value: "a.example"},
		{Type: cn, Value: "b.example"},
	}}, nil, nil)
	if leaf.Subject.CommonName != "b.example" {
		t.Fatalf("precondition: pkix.Name.CommonName = %q, expected Go to keep the last CN", leaf.Subject.CommonName)
	}
	now := time.Now()
	var hop pageHop
	setHopCert(&hop, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}, now)
	if hop.CertCN != "a.example" {
		t.Errorf("certCN = %q, want the first CN a.example (like PHP and chain[0].subject)", hop.CertCN)
	}
	if hop.CertDaysLeft == nil || *hop.CertDaysLeft != daysUntil(leaf.NotAfter, now) {
		t.Errorf("certDaysLeft = %v", hop.CertDaysLeft)
	}

	// No CN at all: omitted, no O fallback.
	orgOnly, _, _ := newCert(t, certOpts{org: "Only Org"}, nil, nil)
	hop = pageHop{}
	setHopCert(&hop, &tls.ConnectionState{PeerCertificates: []*x509.Certificate{orgOnly}}, now)
	if hop.CertCN != "" {
		t.Errorf("certCN = %q for a certificate without CN, want empty", hop.CertCN)
	}
}

func TestDescribeCertificate(t *testing.T) {
	now := time.Now()

	t.Run("fields and formats", func(t *testing.T) {
		cert, _, _ := newCert(t, certOpts{cn: "example.com", org: "Example Org",
			dns: []string{"example.com", "www.example.com"}, ips: []net.IP{net.ParseIP("2001:db8::1")},
			serial: big.NewInt(0x01EEE6)}, nil, nil)
		link := describeCertificate(cert, now)

		if link.Subject != "example.com" || link.SubjectOrg == nil || *link.SubjectOrg != "Example Org" {
			t.Errorf("subject = %q / %v", link.Subject, link.SubjectOrg)
		}
		if link.SubjectDN != "O=Example Org, CN=example.com" {
			t.Errorf("subjectDN = %q", link.SubjectDN)
		}
		if !link.SelfIssued || link.IsCA {
			t.Errorf("selfIssued/isCA = %v/%v, want true/false", link.SelfIssued, link.IsCA)
		}
		if link.Serial != "01:EE:E6" {
			t.Errorf("serial = %q, want 01:EE:E6", link.Serial)
		}
		sum := sha256.Sum256(cert.Raw)
		if link.SHA256 != colonHex(sum[:]) || len(link.SHA256) != 95 || link.SHA256 != strings.ToUpper(link.SHA256) {
			t.Errorf("sha256 = %q", link.SHA256)
		}
		if len(link.SHA1) != 59 {
			t.Errorf("sha1 = %q", link.SHA1)
		}
		block, rest := pem.Decode([]byte(link.PEM))
		if block == nil || !bytes.Equal(block.Bytes, cert.Raw) || len(rest) != 0 || !strings.HasSuffix(link.PEM, "\n") {
			t.Error("PEM does not round-trip to the certificate's DER")
		}
		dateRE := regexp.MustCompile(`^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC$`)
		if !dateRE.MatchString(link.ValidFrom) || !dateRE.MatchString(link.ValidUntil) {
			t.Errorf("dates = %q / %q", link.ValidFrom, link.ValidUntil)
		}
		if link.ValidUntilTs != cert.NotAfter.Unix() || link.ValidFromTs != cert.NotBefore.Unix() {
			t.Error("timestamps do not match the certificate")
		}
		if strings.Join(link.SANs, ",") != "example.com,www.example.com,2001:db8::1" {
			t.Errorf("sans = %v", link.SANs)
		}
		if link.SignatureAlgorithm != "ecdsa-with-SHA256" {
			t.Errorf("signatureAlgorithm = %q", link.SignatureAlgorithm)
		}
	})

	t.Run("subject falls back CN, O, Unknown", func(t *testing.T) {
		orgOnly, _, _ := newCert(t, certOpts{org: "Only Org"}, nil, nil)
		if got := describeCertificate(orgOnly, now).Subject; got != "Only Org" {
			t.Errorf("O fallback: got %q", got)
		}
		nameless, _, _ := newCert(t, certOpts{dns: []string{"x.test"}}, nil, nil)
		link := describeCertificate(nameless, now)
		if link.Subject != "Unknown" || link.SubjectOrg != nil {
			t.Errorf("no CN/O: got %q / %v", link.Subject, link.SubjectOrg)
		}
	})

	t.Run("keys", func(t *testing.T) {
		for _, tc := range []struct {
			kind, want string
			bits       *int
		}{
			{"rsa2048", "RSA 2048 bit", intPtr(2048)},
			{"rsa1024", "RSA 1024 bit", intPtr(1024)},
			{"p256", "EC P-256 (256 bit)", nil},
			{"p384", "EC P-384 (384 bit)", nil},
			{"ed25519", "Ed25519", nil},
		} {
			cert, _, _ := newCert(t, certOpts{cn: "key-" + tc.kind, key: tc.kind}, nil, nil)
			link := describeCertificate(cert, now)
			if link.Key != tc.want {
				t.Errorf("%s: key = %q, want %q", tc.kind, link.Key, tc.want)
			}
			if (link.KeyBits == nil) != (tc.bits == nil) || (link.KeyBits != nil && *link.KeyBits != *tc.bits) {
				t.Errorf("%s: keyBits = %v, want %v", tc.kind, link.KeyBits, tc.bits)
			}
		}
	})

	t.Run("daysLeft is floored", func(t *testing.T) {
		expired, _, _ := newCert(t, certOpts{cn: "just-expired", notBefore: now.Add(-48 * time.Hour), notAfter: now.Add(-time.Hour)}, nil, nil)
		if got := describeCertificate(expired, now).DaysLeft; got != -1 {
			t.Errorf("an hour past NotAfter: daysLeft = %d, want -1", got)
		}
		soon, _, _ := newCert(t, certOpts{cn: "almost-two-days", notAfter: now.Add(47 * time.Hour)}, nil, nil)
		if got := describeCertificate(soon, now).DaysLeft; got != 1 {
			t.Errorf("47h left: daysLeft = %d, want 1", got)
		}
	})

	t.Run("struct literal does not panic", func(t *testing.T) {
		link := describeCertificate(&x509.Certificate{Subject: pkix.Name{CommonName: "literal"}}, now)
		if link.Subject != "literal" || link.Serial != "" || link.Key != "Unknown" || link.PEM != "" || link.SelfIssued {
			t.Errorf("got %+v", link)
		}
		if link.SANs == nil {
			t.Error("sans must be [] rather than null")
		}
	})
}

func TestBuildCertificateChain(t *testing.T) {
	now := time.Now()
	p := newTestPKI(t)
	leafDER, _ := p.leaf(t, certOpts{cn: "chain.test"})
	leaf, _ := x509.ParseCertificate(leafDER)

	labels := func(chain []chainLink) string {
		var parts []string
		for _, c := range chain {
			parts = append(parts, fmt.Sprintf("%d:%s:%s", c.Position, c.Label, fmtBoolPtr(c.SignatureValid)))
		}
		return strings.Join(parts, " | ")
	}

	t.Run("leaf, intermediate, self-signed root", func(t *testing.T) {
		got := labels(buildCertificateChain([]*x509.Certificate{leaf, p.inter, p.root}, now))
		want := "1:Server certificate:true | 2:Intermediate CA:true | 3:Root CA (self-signed):true"
		if got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
	})

	t.Run("issuer of the last certificate not sent", func(t *testing.T) {
		got := labels(buildCertificateChain([]*x509.Certificate{leaf, p.inter}, now))
		if want := "1:Server certificate:true | 2:Intermediate CA:null"; got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
	})

	t.Run("cross-signed root", func(t *testing.T) {
		other, otherKey, _ := newCert(t, certOpts{cn: "Other Root CA", isCA: true}, nil, nil)
		cross, crossKey, _ := newCert(t, certOpts{cn: "Example Root X2", isCA: true}, other, otherKey)
		xleaf, _, _ := newCert(t, certOpts{cn: "cross.test"}, cross, crossKey)
		got := labels(buildCertificateChain([]*x509.Certificate{xleaf, cross}, now))
		if want := "1:Server certificate:true | 2:Cross-signed root (acts as intermediate):null"; got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
	})

	t.Run("wrong order", func(t *testing.T) {
		chain := buildCertificateChain([]*x509.Certificate{leaf, p.root, p.inter}, now)
		got := labels(chain)
		if want := "1:Server certificate:false | 2:Root CA (self-signed):true | 3:Intermediate CA:null"; got != want {
			t.Errorf("got  %s\nwant %s", got, want)
		}
	})

	t.Run("self-signed leaf alone", func(t *testing.T) {
		self, _, _ := newCert(t, certOpts{cn: "self.test"}, nil, nil)
		info := buildSSLInfo([]*x509.Certificate{self}, nil, "self.test", false, nil, nil, "probe", now)
		if got := labels(info.Chain); got != "1:Server certificate:true" {
			t.Errorf("got %s", got)
		}
		if !info.SelfSigned {
			t.Error("expected selfSigned")
		}
	})

	t.Run("capped at ten", func(t *testing.T) {
		certs := make([]*x509.Certificate, 12)
		for i := range certs {
			certs[i] = p.inter
		}
		if n := len(buildCertificateChain(certs, now)); n != maxChainCerts {
			t.Errorf("chain length %d, want %d", n, maxChainCerts)
		}
	})
}

func TestSignatureValid_LegacyAlgorithms(t *testing.T) {
	sha1Cert, _, _ := newCert(t, certOpts{cn: "sha1.test", key: "rsa2048", sigAlg: x509.SHA1WithRSA}, nil, nil)
	if !signatureValid(sha1Cert, sha1Cert) {
		t.Error("a valid SHA-1 RSA signature must verify (OpenSSL parity)")
	}

	block, _ := pem.Decode([]byte(md5CertPEM))
	md5Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse MD5 fixture: %v", err)
	}
	if md5Cert.SignatureAlgorithm != x509.MD5WithRSA {
		t.Fatalf("fixture algorithm = %v", md5Cert.SignatureAlgorithm)
	}
	if !signatureValid(md5Cert, md5Cert) {
		t.Error("a valid MD5 RSA signature must verify through the fallback")
	}
	if got := describeCertificate(md5Cert, time.Now()).SignatureAlgorithm; got != "md5WithRSAEncryption" {
		t.Errorf("signatureAlgorithm = %q", got)
	}

	for name, c := range map[string]*x509.Certificate{"sha1": sha1Cert, "md5": md5Cert} {
		tampered := *c
		tampered.Signature = append([]byte(nil), c.Signature...)
		tampered.Signature[len(tampered.Signature)-1] ^= 0xff
		if signatureValid(&tampered, c) {
			t.Errorf("%s: a tampered signature must not verify", name)
		}
	}

	if signatureValid(sha1Cert, &x509.Certificate{}) {
		t.Error("a parent without a public key must not verify (and must not panic)")
	}
}

func TestCertMatchesHost(t *testing.T) {
	for _, tc := range []struct {
		host string
		sans []string
		cn   string
		want *bool
	}{
		{"a.b.example.com", []string{"*.example.com"}, "", boolPtr(false)},
		{"example.com", []string{"*.example.com"}, "", boolPtr(false)},
		{"www.example.com", []string{"*.example.com"}, "", boolPtr(true)},
		{"Foo.Example.com.", []string{"foo.example.com"}, "", boolPtr(true)},
		{"foo.example.com", []string{"f*.example.com"}, "", boolPtr(false)},
		{"foo.example.com", []string{"FOO.EXAMPLE.COM."}, "", boolPtr(true)},
		{"93.184.216.34", []string{"93.184.216.34"}, "", boolPtr(true)},
		{"93.184.216.34", []string{"*.184.216.34"}, "", boolPtr(false)},
		{"[2001:db8::1]", []string{"2001:DB8:0:0:0:0:0:1"}, "", boolPtr(true)},
		{"2001:db8::1", []string{"2001:db8::2"}, "", boolPtr(false)},
		{"example.com", nil, "example.com", boolPtr(true)},
		{"example.com", []string{}, "Unknown", boolPtr(false)},
		{"", []string{"example.com"}, "", nil},
		{"bücher.de", []string{"xn--bcher-kva.de"}, "", nil},
	} {
		got := certMatchesHost(tc.host, tc.sans, tc.cn)
		if fmtBoolPtr(got) != fmtBoolPtr(tc.want) {
			t.Errorf("certMatchesHost(%q, %v, %q) = %s, want %s", tc.host, tc.sans, tc.cn, fmtBoolPtr(got), fmtBoolPtr(tc.want))
		}
	}
}

func TestCertificateIssues(t *testing.T) {
	now := time.Now()
	day := int64(86400)
	link := func(pos int, subject string, mods ...func(*chainLink)) chainLink {
		c := chainLink{
			Position: pos, Subject: subject,
			ValidFromTs: now.Unix() - 30*day, ValidUntilTs: now.Unix() + 60*day, DaysLeft: 60,
			SignatureAlgorithm: "sha256WithRSAEncryption", KeyBits: intPtr(2048),
		}
		for _, m := range mods {
			m(&c)
		}
		return c
	}
	sigOK := func(c *chainLink) { c.SignatureValid = boolPtr(true) }
	sigBad := func(c *chainLink) { c.SignatureValid = boolPtr(false) }
	msgs := func(issues []certIssue) []string {
		out := []string{}
		for _, i := range issues {
			out = append(out, i.Type+": "+i.Msg)
		}
		return out
	}
	healthy := []chainLink{link(1, "leaf", sigOK), link(2, "inter")}

	for _, tc := range []struct {
		name       string
		chain      []chainLink
		hostMatch  *bool
		selfSigned bool
		want       []string
	}{
		{"healthy chain", healthy, boolPtr(true), false, []string{}},
		{"expired", []chainLink{link(1, "leaf", sigOK, func(c *chainLink) {
			c.ValidUntilTs, c.DaysLeft = now.Unix()-10*day, -10
		}), link(2, "inter")}, nil, false,
			[]string{"error: The certificate expired 10 days ago."}},
		{"not yet valid, not also expiring", []chainLink{link(1, "leaf", sigOK, func(c *chainLink) {
			c.ValidFromTs, c.DaysLeft = now.Unix()+day, 5
		}), link(2, "inter")}, nil, false,
			[]string{"error: The certificate is not valid yet."}},
		{"expiring soon", []chainLink{link(1, "leaf", sigOK, func(c *chainLink) { c.DaysLeft = 14 }), link(2, "inter")}, nil, false,
			[]string{"warning: The certificate expires in 14 days."}},
		{"host not covered", healthy, boolPtr(false), false,
			[]string{"error: The host name is not covered by the certificate (CN/SAN)."}},
		{"self-signed leaf alone", []chainLink{link(1, "self", func(c *chainLink) {
			c.SelfIssued, c.SignatureValid = true, boolPtr(true)
		})}, boolPtr(true), true,
			[]string{"error: The certificate is self-signed — browsers will not trust it."}},
		{"weak algorithms and keys", []chainLink{
			link(1, "leaf", sigOK, func(c *chainLink) { c.SignatureAlgorithm = "sha1WithRSAEncryption" }),
			link(2, "inter", sigOK, func(c *chainLink) { c.SignatureAlgorithm, c.KeyBits = "ecdsa-with-SHA1", nil }),
			link(3, "md5 inter", sigOK, func(c *chainLink) { c.SignatureAlgorithm, c.KeyBits = "md5WithRSAEncryption", intPtr(1024) }),
			link(4, "old root", sigOK, func(c *chainLink) { c.SignatureAlgorithm, c.SelfIssued = "sha1WithRSAEncryption", true }),
		}, nil, false, []string{
			"warning: leaf: weak signature algorithm (sha1WithRSAEncryption).",
			"warning: inter: weak signature algorithm (ecdsa-with-SHA1).",
			"warning: md5 inter: weak signature algorithm (md5WithRSAEncryption).",
			"warning: md5 inter: RSA key with only 1024 bit.",
		}},
		{"no intermediate sent", []chainLink{link(1, "leaf")}, nil, false,
			[]string{"warning: The server sends no intermediate certificate — some clients cannot build the chain."}},
		{"broken self-signature at the end", []chainLink{link(1, "leaf", sigOK), link(2, "root", sigBad, func(c *chainLink) { c.SelfIssued = true })}, nil, false,
			[]string{"error: The chain is broken: root is not signed by the next certificate."}},
		{"misordered, reported once", []chainLink{link(1, "leaf", sigBad), link(2, "root", sigBad), link(3, "inter")}, nil, false,
			[]string{"error: Chain order or content is wrong: leaf is not signed by the following certificate."}},
	} {
		got := msgs(certificateIssues(tc.chain, tc.hostMatch, tc.selfSigned, now))
		if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
			t.Errorf("%s:\n got  %q\n want %q", tc.name, got, tc.want)
		}
	}

	if issues := certificateIssues(nil, nil, false, now); issues == nil || len(issues) != 0 {
		t.Error("an empty chain must yield [] rather than null")
	}
}

// -----------------------------------------------------------------------
// Redirect targets, capped bodies
// -----------------------------------------------------------------------

func TestResolveRedirect(t *testing.T) {
	base, _ := url.Parse("http://a/b/c/d;p?q")
	// RFC 3986 §5.4.1 (normal) and §5.4.2 (abnormal) examples.
	for ref, want := range map[string]string{
		"g": "http://a/b/c/g", "./g": "http://a/b/c/g", "g/": "http://a/b/c/g/", "/g": "http://a/g",
		"//g": "http://g", "?y": "http://a/b/c/d;p?y", "g?y": "http://a/b/c/g?y", "#s": "http://a/b/c/d;p?q#s",
		"g#s": "http://a/b/c/g#s", "g?y#s": "http://a/b/c/g?y#s", ";x": "http://a/b/c/;x", "g;x": "http://a/b/c/g;x",
		"g;x?y#s": "http://a/b/c/g;x?y#s", "": "http://a/b/c/d;p?q", ".": "http://a/b/c/", "./": "http://a/b/c/",
		"..": "http://a/b/", "../": "http://a/b/", "../g": "http://a/b/g", "../..": "http://a/",
		"../../": "http://a/", "../../g": "http://a/g",

		"../../../g": "http://a/g", "../../../../g": "http://a/g", "/./g": "http://a/g", "/../g": "http://a/g",
		"g.": "http://a/b/c/g.", ".g": "http://a/b/c/.g", "g..": "http://a/b/c/g..", "..g": "http://a/b/c/..g",
		"./../g": "http://a/b/g", "./g/.": "http://a/b/c/g/", "g/./h": "http://a/b/c/g/h", "g/../h": "http://a/b/c/h",
		"g;x=1/./y": "http://a/b/c/g;x=1/y", "g;x=1/../y": "http://a/b/c/y", "g?y/./x": "http://a/b/c/g?y/./x",
		"g?y/../x": "http://a/b/c/g?y/../x", "g#s/./x": "http://a/b/c/g#s/./x", "g#s/../x": "http://a/b/c/g#s/../x",
		"http:g": "http:g",
	} {
		got, err := resolveRedirect(base, ref)
		if err != nil {
			t.Errorf("%q: unexpected error %v", ref, err)
			continue
		}
		if got.String() != want {
			t.Errorf("%q: got %q, want %q", ref, got.String(), want)
		}
	}

	for _, tc := range []struct{ base, loc, want string }{
		{"https://user:pw@h/a", "/b", "https://h/b"},                                         // userinfo dropped
		{"https://h/a", "https://u:p@x.example/", "https://x.example/"},                      // also from the target
		{"https://[2001:db8::1]:8443/a/b", "../c", "https://[2001:db8::1]:8443/c"},           // IPv6 base
		{"https://h/a/b", "  HTTPS://Example.com/x  ", "https://Example.com/x"},              // trimmed, scheme normalised
		{"http://h/robots.txt", "//cdn.example/robots.txt", "http://cdn.example/robots.txt"}, // scheme-relative
	} {
		b, _ := url.Parse(tc.base)
		got, err := resolveRedirect(b, tc.loc)
		if err != nil || got.String() != tc.want {
			t.Errorf("resolveRedirect(%q, %q) = %v, %v; want %q", tc.base, tc.loc, got, err, tc.want)
		}
	}

	for _, loc := range []string{"g:h", "javascript:alert(1)", "data:text/html,x", "ftp://h/x"} {
		if _, err := resolveRedirect(base, loc); !errors.Is(err, errUnsupportedRedirectScheme) {
			t.Errorf("%q: expected errUnsupportedRedirectScheme, got %v", loc, err)
		}
	}

	h := http.Header{}
	if lastLocation(h) != "" {
		t.Error("no Location must give an empty string")
	}
	h.Add("Location", "/first")
	h.Add("Location", "/second")
	if got := lastLocation(h); got != "/second" {
		t.Errorf("lastLocation = %q, want the last value", got)
	}
}

func TestReadCapped(t *testing.T) {
	for _, tc := range []struct {
		body      string
		limit     int64
		want      string
		truncated bool
	}{
		{"abcd", 4, "abcd", false},
		{"abcde", 4, "abcd", true},
		{"ab", 4, "ab", false},
		{"abcdef", 0, "abcdef", false}, // 0 = unlimited
	} {
		got, truncated, err := readCapped(strings.NewReader(tc.body), tc.limit)
		if err != nil || string(got) != tc.want || truncated != tc.truncated {
			t.Errorf("readCapped(%q, %d) = %q, %v, %v; want %q, %v", tc.body, tc.limit, got, truncated, err, tc.want, tc.truncated)
		}
	}
}

func TestTrimPartialUTF8(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"abc", "abc"},
		{"ab\xc3", "ab"},         // first byte of ü
		{"ab\xe2\x82", "ab"},     // two of three bytes of €
		{"ab\xf0\x9f\x98", "ab"}, // three of four bytes of 😀
		{"abü", "abü"},           // complete
		{"ab😀", "ab😀"},           // complete four-byte rune
		{"ab\xff", "ab\xff"},     // invalid, not partial: left alone
		{"", ""},
	} {
		if got := string(trimPartialUTF8([]byte(tc.in))); got != tc.want {
			t.Errorf("trimPartialUTF8(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestReadDecodedBody(t *testing.T) {
	gz := func(s string) []byte {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		w.Write([]byte(s))
		w.Close()
		return buf.Bytes()
	}

	t.Run("gzip decoded", func(t *testing.T) {
		raw := gz("<html>hello</html>")
		b := readDecodedBody(bytes.NewReader(raw), "gzip", 1024)
		if string(b.data) != "<html>hello</html>" || b.truncated || b.decodeError || b.rawSize != len(raw) {
			t.Errorf("got %+v", b)
		}
	})

	t.Run("undecodable encoding never yields raw bytes", func(t *testing.T) {
		b := readDecodedBody(bytes.NewReader([]byte{0x1b, 0x2a, 0x00, 0xff}), "br", 1024)
		if len(b.data) != 0 || !b.decodeError {
			t.Errorf("got %+v", b)
		}
	})

	t.Run("corrupt gzip", func(t *testing.T) {
		b := readDecodedBody(bytes.NewReader([]byte("\x1f\x8bthis is not gzip at all")), "gzip", 1024)
		if !b.decodeError || bytes.HasPrefix(b.data, []byte{0x1f, 0x8b}) {
			t.Errorf("got %+v", b)
		}
	})

	t.Run("gzip cut by the cap is truncation, not corruption", func(t *testing.T) {
		raw := gz(strings.Repeat("Grüße ", 5000))
		b := readDecodedBody(bytes.NewReader(raw), "gzip", int64(len(raw)/2))
		if !b.truncated || b.decodeError || len(b.data) == 0 || !utf8.Valid(b.data) {
			t.Errorf("truncated=%v decodeError=%v len=%d valid=%v", b.truncated, b.decodeError, len(b.data), utf8.Valid(b.data))
		}
	})

	t.Run("decoded text capped and cut on a rune boundary", func(t *testing.T) {
		text := strings.Repeat("ü", 100) // 200 bytes
		b := readDecodedBody(bytes.NewReader(gz(text)), "gzip", 101)
		if !b.truncated || len(b.data) != 100 || !utf8.Valid(b.data) {
			t.Errorf("truncated=%v len=%d valid=%v", b.truncated, len(b.data), utf8.Valid(b.data))
		}
	})

	t.Run("empty body with an encoding", func(t *testing.T) {
		if b := readDecodedBody(bytes.NewReader(nil), "gzip", 1024); b.decodeError || b.truncated {
			t.Errorf("got %+v", b)
		}
	})
	// Misconfigured servers label plain bodies with tokens that are no
	// content coding at all; v1.2.4 returned those pages, so must v1.3.0.
	t.Run("unknown token with a plain UTF-8 body passes through", func(t *testing.T) {
		const html = "<html><body>Grüße</body></html>"
		for _, enc := range []string{"none", "UTF-8", "utf8", "text/html", "binary", "None, identity"} {
			b := readDecodedBody(strings.NewReader(html), enc, 1024)
			if string(b.data) != html || b.decodeError || b.truncated || b.rawSize != len(html) {
				t.Errorf("%q: got data=%q decodeError=%v truncated=%v", enc, b.data, b.decodeError, b.truncated)
			}
		}
	})

	t.Run("unknown token with binary bytes is never passed on", func(t *testing.T) {
		b := readDecodedBody(bytes.NewReader([]byte{0x1f, 0x8b, 0x08, 0x00, 0xff, 0xfe, 0x00}), "none", 1024)
		if len(b.data) != 0 || !b.decodeError {
			t.Errorf("got %+v", b)
		}
	})

	t.Run("unknown token, UTF-8 body cut inside a character by the cap", func(t *testing.T) {
		text := strings.Repeat("ü", 100) // 200 bytes
		b := readDecodedBody(strings.NewReader(text), "UTF-8", 101)
		if !b.truncated || b.decodeError || len(b.data) != 100 || !utf8.Valid(b.data) {
			t.Errorf("truncated=%v decodeError=%v len=%d", b.truncated, b.decodeError, len(b.data))
		}
	})

	t.Run("registered codings the stdlib cannot decode", func(t *testing.T) {
		// Even a body that happens to be valid UTF-8 is not trusted here.
		for _, enc := range []string{"br", "BR", "zstd", "compress", "x-compress", "dcb", "dcz", "aes128gcm", "exi", "pack200-gzip"} {
			b := readDecodedBody(strings.NewReader("looks like text"), enc, 1024)
			if len(b.data) != 0 || !b.decodeError {
				t.Errorf("%q: got data=%q decodeError=%v", enc, b.data, b.decodeError)
			}
		}
	})

	t.Run("stacked codings are not decoded", func(t *testing.T) {
		for _, enc := range []string{"gzip, br", "deflate, gzip", "none, gzip"} {
			b := readDecodedBody(bytes.NewReader(gz("<html>x</html>")), enc, 1024)
			if len(b.data) != 0 || !b.decodeError {
				t.Errorf("%q: got data=%q decodeError=%v", enc, b.data, b.decodeError)
			}
		}
	})

	t.Run("identity in any spelling is plain", func(t *testing.T) {
		for _, enc := range []string{"identity", " Identity ", ""} {
			b := readDecodedBody(strings.NewReader("<p>x</p>"), enc, 1024)
			if string(b.data) != "<p>x</p>" || b.decodeError {
				t.Errorf("%q: got %+v", enc, b)
			}
		}
	})
}

// -----------------------------------------------------------------------
// Error classification: timeouts, typed errors
// -----------------------------------------------------------------------

type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string   { return "i/o timeout" }
func (fakeTimeoutError) Timeout() bool   { return true }
func (fakeTimeoutError) Temporary() bool { return true }

func TestClassifyUpstreamError_Timeout(t *testing.T) {
	for name, err := range map[string]error{
		"expired request context": &url.Error{Op: "Get", URL: "https://example.com/", Err: context.DeadlineExceeded},
		"dial timeout":            &url.Error{Op: "Get", URL: "https://example.com/", Err: &net.OpError{Op: "dial", Net: "tcp", Err: fakeTimeoutError{}}},
	} {
		if code, _ := classifyUpstreamError(err); code != "timeout" {
			t.Errorf("%s: expected timeout, got %q", name, code)
		}
	}
	// A socket error that is not a timeout stays a connection error.
	err := &url.Error{Op: "Get", URL: "https://example.com/", Err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}}
	if code, _ := classifyUpstreamError(err); code != "connection_error" {
		t.Errorf("expected connection_error, got %q", code)
	}
}

// The specific x509 messages used to be unreachable: the
// *tls.CertificateVerificationError wrapping them was matched first.
func TestClassifyUpstreamError_UnwrapsCertificateVerificationError(t *testing.T) {
	for inner, want := range map[error]string{
		x509.HostnameError{}:            "TLS certificate hostname mismatch",
		x509.UnknownAuthorityError{}:    "TLS certificate signed by unknown authority",
		x509.CertificateInvalidError{}:  "TLS certificate invalid",
		errors.New("platform verifier"): "TLS certificate verification failed",
	} {
		code, msg := classifyUpstreamError(&tls.CertificateVerificationError{Err: inner})
		if code != "tls_error" || msg != want {
			t.Errorf("inner %T: got %q / %q, want tls_error / %q", inner, code, msg, want)
		}
	}
}

func TestUpstreamFailure(t *testing.T) {
	for _, tc := range []struct {
		err    error
		code   string
		status int
		typ    string
	}{
		{&net.DNSError{Err: "no such host", Name: "x.invalid"}, "dns_error", 502, "Could not resolve host"},
		{&net.OpError{Op: "dial", Err: errors.New("refused")}, "connection_error", 502, "Could not connect to host"},
		{context.DeadlineExceeded, "timeout", 504, "Connection timeout"},
		{fmt.Errorf("%w: 10.0.0.1", errBlockedTarget), "blocked_target", 502, "Blocked target"},
		{errors.New("weird"), "upstream_error", 502, "Upstream error"},
		{&tls.CertificateVerificationError{Err: x509.HostnameError{}}, "tls_error", 502, "Host name does not match the certificate"},
		{tls.RecordHeaderError{Msg: "not TLS"}, "tls_error", 502, "TLS protocol not supported"},
	} {
		pe := upstreamFailure(context.Background(), tc.err)
		if pe.Error != tc.code || pe.Status != tc.status || pe.Type != tc.typ || pe.Message == "" {
			t.Errorf("%v: got %+v, want %s/%d/%q", tc.err, pe, tc.code, tc.status, tc.typ)
		}
	}

	// An expired request context wins over whatever shape the transport chose.
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	if pe := upstreamFailure(ctx, errors.New("net/http: request canceled")); pe.Error != "timeout" || pe.Status != 504 {
		t.Errorf("expired context: got %+v", pe)
	}
}

// -----------------------------------------------------------------------
// TLS failure classification against real handshakes
// -----------------------------------------------------------------------

func TestClassifyTLSFailure_RealHandshakes(t *testing.T) {
	p := newTestPKI(t)
	now := time.Now()

	type tc struct {
		name           string
		srv            func(t *testing.T) *httptest.Server
		roots          *x509.CertPool
		wantType       string
		wantVerifyText string
	}
	leafServer := func(o certOpts, withInter bool) func(t *testing.T) *httptest.Server {
		return func(t *testing.T) *httptest.Server {
			der, key := p.leaf(t, o)
			chain := [][]byte{der}
			if withInter {
				chain = append(chain, p.interDER)
			}
			return tlsServerWith(t, chain, key, nil, nil)
		}
	}

	cases := []tc{
		{"expired leaf", leafServer(certOpts{cn: "expired.test", notBefore: now.Add(-60 * 24 * time.Hour), notAfter: now.Add(-24 * time.Hour)}, true),
			p.pool, "Certificate expired", "Certificate has expired"},
		{"leaf not yet valid", leafServer(certOpts{cn: "future.test", notBefore: now.Add(24 * time.Hour), notAfter: now.Add(90 * 24 * time.Hour)}, true),
			p.pool, "Certificate not yet valid", "Certificate is not yet valid"},
		{"host mismatch", leafServer(certOpts{cn: "mismatch.test", ips: []net.IP{net.ParseIP("10.0.0.1")}}, true),
			p.pool, "Host name does not match the certificate", "Hostname mismatch"},
		{"self-signed leaf", func(t *testing.T) *httptest.Server {
			_, key, der := newCert(t, certOpts{cn: "self-signed.test", ips: []net.IP{net.ParseIP("127.0.0.1")}}, nil, nil)
			return tlsServerWith(t, [][]byte{der}, key, nil, nil)
		}, x509.NewCertPool(), "Self-signed certificate", "Self-signed certificate"},
		{"untrusted root sent", func(t *testing.T) *httptest.Server {
			der, key := p.leaf(t, certOpts{cn: "untrusted-root.test"})
			return tlsServerWith(t, [][]byte{der, p.interDER, p.rootDER}, key, nil, nil)
		}, x509.NewCertPool(), "Untrusted root certificate in the chain", "Self-signed certificate in chain"},
		{"intermediate not sent", leafServer(certOpts{cn: "incomplete.test"}, false),
			p.pool, "Incomplete chain or unknown issuer", "Unable to get local issuer certificate"},
		// The root is sent, but the leaf cannot reach it: OpenSSL's error 20,
		// not 19 — whether the root is trusted or not.
		{"root sent, intermediate missing", func(t *testing.T) *httptest.Server {
			der, key := p.leaf(t, certOpts{cn: "root-no-inter.test"})
			return tlsServerWith(t, [][]byte{der, p.rootDER}, key, nil, nil)
		}, p.pool, "Incomplete chain or unknown issuer", "Unable to get local issuer certificate"},
		{"untrusted root sent, intermediate missing", func(t *testing.T) *httptest.Server {
			der, key := p.leaf(t, certOpts{cn: "untrusted-root-no-inter.test"})
			return tlsServerWith(t, [][]byte{der, p.rootDER}, key, nil, nil)
		}, x509.NewCertPool(), "Incomplete chain or unknown issuer", "Unable to get local issuer certificate"},
		{"wrong intermediate and root sent", func(t *testing.T) *httptest.Server {
			_, _, otherDER := newCert(t, certOpts{cn: "Other Intermediate CA", org: "Test PKI", isCA: true}, p.root, p.rootKey)
			der, key := p.leaf(t, certOpts{cn: "wrong-inter.test"})
			return tlsServerWith(t, [][]byte{der, otherDER, p.rootDER}, key, nil, nil)
		}, p.pool, "Incomplete chain or unknown issuer", "Unable to get local issuer certificate"},
		{"untrusted root sent out of order", func(t *testing.T) *httptest.Server {
			der, key := p.leaf(t, certOpts{cn: "out-of-order.test"})
			return tlsServerWith(t, [][]byte{der, p.rootDER, p.interDER}, key, nil, nil)
		}, x509.NewCertPool(), "Untrusted root certificate in the chain", "Self-signed certificate in chain"},
		{"TLS 1.0 only", func(t *testing.T) *httptest.Server {
			der, key := p.leaf(t, certOpts{cn: "tls10.test", key: "rsa2048"})
			return tlsServerWith(t, [][]byte{der, p.interDER}, key, func(c *tls.Config) {
				c.MinVersion, c.MaxVersion = tls.VersionTLS10, tls.VersionTLS10
				c.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}
			}, nil)
		}, p.pool, "TLS protocol not supported", "TLS protocol not supported"},
		{"plain HTTP on the https port", func(t *testing.T) *httptest.Server {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
			t.Cleanup(srv.Close)
			srv.URL = strings.Replace(srv.URL, "http://", "https://", 1)
			return srv
		}, p.pool, "TLS protocol not supported", "TLS protocol not supported"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := c.srv(t)
			cfg := testCfg(t, c.roots)
			resp, err := newUpstreamClient(cfg).Get(srv.URL)
			if err == nil {
				resp.Body.Close()
				t.Fatal("expected the verified content request to fail")
			}
			if code, _ := classifyUpstreamError(err); code != "tls_error" {
				t.Fatalf("classifyUpstreamError = %q, want tls_error (err: %v)", code, err)
			}

			// As in production: the chain comes from the probe.
			var certs []*x509.Certificate
			if cs, perr := probeTLS(context.Background(), cfg, "127.0.0.1", serverPort(t, srv), "127.0.0.1"); perr == nil {
				certs = cs.PeerCertificates
			}
			errorType, verifyText := classifyTLSFailure(err, certs, time.Now())
			if errorType != c.wantType || verifyText != c.wantVerifyText {
				t.Errorf("got %q / %q, want %q / %q (err: %v)", errorType, verifyText, c.wantType, c.wantVerifyText, err)
			}
			// The 502 contract's "type" has no probe, only the chain crypto/tls
			// attached to the error — which is the served chain, so it agrees.
			if typ := proxyErrorType("tls_error", err); typ != errorType {
				t.Errorf("proxyErrorType = %q, want %q", typ, errorType)
			}
		})
	}
}

// -----------------------------------------------------------------------
// The handshake-only probe
// -----------------------------------------------------------------------

func TestProbeTLS_NoApplicationData(t *testing.T) {
	var requests atomic.Int32
	_, key, der := newCert(t, certOpts{cn: "probe.test"}, nil, nil)
	srv := tlsServerWith(t, [][]byte{der}, key, nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))

	cs, err := probeTLS(context.Background(), testCfg(t, nil), "probe.test", serverPort(t, srv), "127.0.0.1")
	if err != nil {
		t.Fatalf("probe failed: %v", err)
	}
	if len(cs.PeerCertificates) != 1 || cs.PeerCertificates[0].Subject.CommonName != "probe.test" {
		t.Errorf("unexpected peer certificates: %v", cs.PeerCertificates)
	}
	time.Sleep(50 * time.Millisecond) // a request, had one been sent, would have arrived by now
	if n := requests.Load(); n != 0 {
		t.Errorf("the probe must never send a request; the handler ran %d times", n)
	}
}

func TestProbeTLS_SNI(t *testing.T) {
	var mu sync.Mutex
	var seen []string
	_, key, der := newCert(t, certOpts{cn: "sni.test"}, nil, nil)
	srv := tlsServerWith(t, [][]byte{der}, key, func(c *tls.Config) {
		c.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			seen = append(seen, hello.ServerName)
			mu.Unlock()
			return nil, nil
		}
	}, nil)
	cfg := testCfg(t, nil)
	port := serverPort(t, srv)

	for _, host := range []string{"sni.test", "127.0.0.1", "bücher.de"} {
		if _, err := probeTLS(context.Background(), cfg, host, port, "127.0.0.1"); err != nil {
			t.Fatalf("probe %q: %v", host, err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(seen, ",") != "sni.test,," {
		t.Errorf("server names seen = %q, want the host name, then none for an IP and a non-ASCII host", seen)
	}
}

func TestProbeTLS_DefaultDialControlBlocksLoopback(t *testing.T) {
	_, key, der := newCert(t, certOpts{cn: "blocked.test"}, nil, nil)
	srv := tlsServerWith(t, [][]byte{der}, key, nil, nil)

	cfg := newTestConfig() // dialControl nil: production's safeDialControl
	_, err := probeTLS(context.Background(), cfg, "blocked.test", serverPort(t, srv), "127.0.0.1")
	if !errors.Is(err, errBlockedTarget) {
		t.Errorf("expected errBlockedTarget, got %v", err)
	}
}

// Mirrors the empirical check behind the probe design: servers that only
// speak legacy suites still yield protocol, cipher and chain.
func TestProbeTLS_LegacyCiphers(t *testing.T) {
	_, key, der := newCert(t, certOpts{cn: "legacy.test", key: "rsa2048"}, nil, nil)
	for _, tc := range []struct {
		name              string
		minV, maxV, suite uint16
		protocol, cipher  string
		bits              int
	}{
		{"TLS 1.0 RSA key exchange", tls.VersionTLS10, tls.VersionTLS10, tls.TLS_RSA_WITH_AES_128_CBC_SHA, "TLSv1", "AES128-SHA", 128},
		{"TLS 1.1 3DES", tls.VersionTLS10, tls.VersionTLS11, tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "TLSv1.1", "DES-CBC3-SHA", 112},
		{"TLS 1.2 RC4", tls.VersionTLS12, tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA, "TLSv1.2", "ECDHE-RSA-RC4-SHA", 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := tlsServerWith(t, [][]byte{der}, key, func(c *tls.Config) {
				c.MinVersion, c.MaxVersion, c.CipherSuites = tc.minV, tc.maxV, []uint16{tc.suite}
			}, nil)
			cs, err := probeTLS(context.Background(), testCfg(t, nil), "legacy.test", serverPort(t, srv), "127.0.0.1")
			if err != nil {
				t.Fatalf("probe failed: %v", err)
			}
			info := buildSSLInfo(cs.PeerCertificates, cs, "legacy.test", false, nil, nil, "probe", time.Now())
			if info.Protocol != tc.protocol || info.Cipher != tc.cipher || info.Bits != tc.bits {
				t.Errorf("got %s / %s / %d, want %s / %s / %d", info.Protocol, info.Cipher, info.Bits, tc.protocol, tc.cipher, tc.bits)
			}
			if info.CipherSuite != tls.CipherSuiteName(tc.suite) {
				t.Errorf("cipherSuite = %q", info.CipherSuite)
			}
		})
	}
}

// The content client must never skip verification — with the test-only trust
// store override or without it.
func TestUpstreamClient_NeverSkipsVerification(t *testing.T) {
	entries, err := parseAllowLocal([]string{"wp.test"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	for name, cfg := range map[string]*config{
		"production":              {},
		"test roots":              {rootCAs: x509.NewCertPool()},
		"allow-local":             {allowLocal: entries},
		"allow-local, test roots": {allowLocal: entries, rootCAs: x509.NewCertPool()},
	} {
		for _, tr := range upstreamTransports(t, newUpstreamClient(cfg)) {
			if tr.TLSClientConfig != nil && tr.TLSClientConfig.InsecureSkipVerify {
				t.Errorf("%s: the upstream client skips TLS verification", name)
			}
		}
	}
}

// upstreamTransports returns the *http.Transport values behind an upstream
// client: one without --allow-local, the local and the public one with it.
func upstreamTransports(t *testing.T, c *http.Client) []*http.Transport {
	t.Helper()
	switch tr := c.Transport.(type) {
	case *http.Transport:
		return []*http.Transport{tr}
	case *localSplitTransport:
		if tr.local == nil || tr.public == nil || tr.local == tr.public {
			t.Fatal("localSplitTransport needs two distinct transports")
		}
		return []*http.Transport{tr.local, tr.public}
	}
	t.Fatalf("unexpected transport type %T", c.Transport)
	return nil
}

func TestConnTrace_IgnoresFailedConnect(t *testing.T) {
	ct := &connTrace{}
	trace := httptrace.ContextClientTrace(ct.attach(context.Background()))
	trace.ConnectDone("tcp", "192.0.2.1:443", nil)
	trace.ConnectDone("tcp", "198.51.100.1:443", errors.New("lost the race"))
	if ip := ct.remoteIP(); ip != "192.0.2.1" {
		t.Errorf("remoteIP = %q, want the address that actually connected", ip)
	}
}

// -----------------------------------------------------------------------
// /inspect: TLS failures and diag=1
// -----------------------------------------------------------------------

func selfSignedServer(t *testing.T) *httptest.Server {
	t.Helper()
	_, key, der := newCert(t, certOpts{cn: "self-signed.test", ips: []net.IP{net.ParseIP("127.0.0.1")}}, nil, nil)
	return tlsServerWith(t, [][]byte{der}, key, nil, nil)
}

func TestInspect_TLSFailure_NoDiag_ContractUnchanged(t *testing.T) {
	srv := selfSignedServer(t)
	rr := doInspect(t, testCfg(t, x509.NewCertPool()), srv.URL, "")

	if rr.Code != http.StatusBadGateway {
		t.Fatalf("expected 502, got %d — %s", rr.Code, rr.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "tls_error" || body["status"] != float64(502) || body["message"] == "" {
		t.Errorf("unexpected error body: %v", body)
	}
	if body["type"] != "Self-signed certificate" {
		t.Errorf("type = %v", body["type"])
	}
	for key := range body {
		if key != "error" && key != "message" && key != "status" && key != "type" {
			t.Errorf("unexpected key %q in the error contract", key)
		}
	}
}

func TestInspect_TLSFailure_Diag(t *testing.T) {
	srv := selfSignedServer(t)
	rr := doInspect(t, testCfg(t, x509.NewCertPool()), srv.URL, "&diag=1")

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", rr.Code, rr.Body.String())
	}
	resp := decodeInspect(t, rr)
	if resp.Error == nil || resp.Error.Error != "tls_error" || resp.Error.Type != "Self-signed certificate" || resp.Error.Status != 502 {
		t.Fatalf("error = %+v", resp.Error)
	}
	if resp.Status != 0 || resp.Method != "HEAD" || resp.IP != "127.0.0.1" || resp.Timing == nil || resp.Headers == nil {
		t.Errorf("status=%d method=%q ip=%q timing=%v", resp.Status, resp.Method, resp.IP, resp.Timing)
	}
	s := resp.SSL
	if s == nil {
		t.Fatal("expected the certificate details of the failing server")
	}
	if s.Verified || s.Valid || s.CertSource != "probe" || s.ProbeError != "" {
		t.Errorf("verified=%v valid=%v certSource=%q probeError=%q", s.Verified, s.Valid, s.CertSource, s.ProbeError)
	}
	if s.ErrorType == nil || *s.ErrorType != "Self-signed certificate" || s.Error == nil || *s.Error != "Self-signed certificate" {
		t.Errorf("errorType=%v error=%v", s.ErrorType, s.Error)
	}
	if s.Protocol != "TLSv1.3" || s.Cipher == "" || s.Bits == 0 {
		t.Errorf("protocol=%q cipher=%q bits=%d", s.Protocol, s.Cipher, s.Bits)
	}
	if len(s.Chain) != 1 || s.Chain[0].PEM == "" || s.Chain[0].Label != "Server certificate" {
		t.Errorf("chain = %+v", s.Chain)
	}
	if s.HostMatch == nil || !*s.HostMatch || !s.SelfSigned {
		t.Errorf("hostMatch=%s selfSigned=%v", fmtBoolPtr(s.HostMatch), s.SelfSigned)
	}
	found := false
	for _, i := range s.Issues {
		if i.Type == "error" && strings.Contains(i.Msg, "self-signed") {
			found = true
		}
	}
	if !found {
		t.Errorf("issues lack the self-signed error: %+v", s.Issues)
	}
}

// closeNthListener closes the n-th accepted connection (1-based) right away.
type closeNthListener struct {
	net.Listener
	n     int32
	count atomic.Int32
}

func (l *closeNthListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.count.Add(1) == l.n {
			c.Close()
			continue
		}
		return c, nil
	}
}

func TestInspect_Diag_ProbeFails_FallsBackToVerifyError(t *testing.T) {
	_, key, der := newCert(t, certOpts{cn: "flaky.test", ips: []net.IP{net.ParseIP("127.0.0.1")}}, nil, nil)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	srv.Listener = &closeNthListener{Listener: srv.Listener, n: 2} // the probe is the second connection
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
	srv.StartTLS()
	defer srv.Close()

	resp := decodeInspect(t, doInspect(t, testCfg(t, x509.NewCertPool()), srv.URL, "&diag=1"))
	s := resp.SSL
	if s == nil {
		t.Fatalf("expected certificate details from the verification error; error=%+v", resp.Error)
	}
	if s.CertSource != "verify-error" || s.ProbeError == "" || s.Protocol != "" || s.Cipher != "" {
		t.Errorf("certSource=%q probeError=%q protocol=%q cipher=%q", s.CertSource, s.ProbeError, s.Protocol, s.Cipher)
	}
	if len(s.Chain) != 1 || s.Chain[0].Subject != "flaky.test" || s.ErrorType == nil || *s.ErrorType != "Self-signed certificate" {
		t.Errorf("chain=%+v errorType=%v", s.Chain, s.ErrorType)
	}
}

// The probe works against the real shape of a legacy server end to end: the
// verified content request cannot even negotiate, yet the report carries
// protocol, cipher and the trusted chain.
func TestInspect_Diag_LegacyTLS10Server(t *testing.T) {
	p := newTestPKI(t)
	der, key := p.leaf(t, certOpts{cn: "tls10.test", key: "rsa2048"})
	srv := tlsServerWith(t, [][]byte{der, p.interDER}, key, func(c *tls.Config) {
		c.MinVersion, c.MaxVersion = tls.VersionTLS10, tls.VersionTLS10
		c.CipherSuites = []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}
	}, nil)

	resp := decodeInspect(t, doInspect(t, testCfg(t, p.pool), srv.URL, "&diag=1"))
	if resp.Error == nil || resp.Error.Error != "tls_error" || resp.Error.Type != "TLS protocol not supported" {
		t.Fatalf("error = %+v", resp.Error)
	}
	s := resp.SSL
	if s == nil {
		t.Fatal("expected certificate details from the probe")
	}
	if s.Protocol != "TLSv1" || s.Cipher != "AES128-SHA" || s.Bits != 128 || s.Version != "TLS 1.0" || s.CertSource != "probe" {
		t.Errorf("protocol=%q cipher=%q bits=%d version=%q source=%q", s.Protocol, s.Cipher, s.Bits, s.Version, s.CertSource)
	}
	if s.Verified || s.ErrorType == nil || *s.ErrorType != "TLS protocol not supported" {
		t.Errorf("verified=%v errorType=%v", s.Verified, s.ErrorType)
	}
	if len(s.Chain) != 2 || s.Chain[1].Label != "Intermediate CA" || s.Chain[0].Key != "RSA 2048 bit" {
		t.Errorf("chain = %+v", s.Chain)
	}
}

func TestInspect_Diag_NonTLSFailure(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()

	rr := doInspect(t, testCfg(t, nil), "http://"+addr+"/", "&diag=1")
	resp := decodeInspect(t, rr)
	if rr.Code != http.StatusOK || resp.Error == nil || resp.Error.Error != "connection_error" || resp.Error.Type != "Could not connect to host" {
		t.Errorf("code=%d error=%+v", rr.Code, resp.Error)
	}
	if resp.SSL != nil {
		t.Error("no certificate report for a non-TLS failure")
	}
}

func TestInspect_Timeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer upstream.Close()

	cfg := testCfg(t, nil)
	cfg.requestTimeout = 200 * time.Millisecond

	rr := doInspect(t, cfg, upstream.URL, "")
	var pe proxyError
	json.Unmarshal(rr.Body.Bytes(), &pe)
	if rr.Code != http.StatusGatewayTimeout || pe.Error != "timeout" || pe.Type != "Connection timeout" {
		t.Errorf("without diag: code=%d body=%+v", rr.Code, pe)
	}

	rr = doInspect(t, cfg, upstream.URL, "&diag=1")
	resp := decodeInspect(t, rr)
	if rr.Code != http.StatusOK || resp.Error == nil || resp.Error.Error != "timeout" || resp.Error.Status != 504 {
		t.Errorf("with diag: code=%d error=%+v", rr.Code, resp.Error)
	}
}

// -----------------------------------------------------------------------
// /inspect: success path additions
// -----------------------------------------------------------------------

func TestInspect_Success_NewFields(t *testing.T) {
	p := newTestPKI(t)
	der, key := p.leaf(t, certOpts{cn: "trusted.test"})
	srv := tlsServerWith(t, [][]byte{der, p.interDER}, key, nil, nil)
	cfg := testCfg(t, p.pool)

	rr := doInspect(t, cfg, srv.URL, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", rr.Code, rr.Body.String())
	}

	// Golden list: every key an old frontend reads is still there.
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"status", "headers", "ssl", "timing", "ip", "protocol", "http3", "method", "truncated", "maxBodySize"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("missing top-level key %q", k)
		}
	}
	if _, ok := raw["error"]; ok {
		t.Error("a successful response must not carry an error key")
	}
	rawSSL, _ := raw["ssl"].(map[string]any)
	for _, k := range []string{"version", "subject", "issuer", "issuerOrg", "organization", "validFrom", "validTo",
		"daysLeft", "sans", "chain", "signatureAlgorithm", "publicKeyAlgorithm",
		"protocol", "cipher", "cipherSuite", "bits", "verified", "valid", "error", "errorType", "hostMatch",
		"selfSigned", "issues", "certSource"} {
		if _, ok := rawSSL[k]; !ok {
			t.Errorf("missing ssl key %q", k)
		}
	}
	if issues, ok := rawSSL["issues"].([]any); !ok || len(issues) != 0 {
		t.Errorf("issues = %v, want []", rawSSL["issues"])
	}

	resp := decodeInspect(t, rr)
	s := resp.SSL
	if resp.Method != "HEAD" || resp.MaxBodySize != cfg.maxResponseBytes || resp.Truncated {
		t.Errorf("method=%q maxBodySize=%d truncated=%v", resp.Method, resp.MaxBodySize, resp.Truncated)
	}
	if !s.Verified || !s.Valid || s.Error != nil || s.ErrorType != nil || s.CertSource != "connection" {
		t.Errorf("verified=%v valid=%v error=%v errorType=%v source=%q", s.Verified, s.Valid, s.Error, s.ErrorType, s.CertSource)
	}
	if s.Protocol != "TLSv1.3" || s.Cipher == "" || s.Cipher != s.CipherSuite || s.Bits < 128 || s.Version != "TLS 1.3" {
		t.Errorf("protocol=%q cipher=%q cipherSuite=%q bits=%d", s.Protocol, s.Cipher, s.CipherSuite, s.Bits)
	}
	if s.HostMatch == nil || !*s.HostMatch || s.SelfSigned {
		t.Errorf("hostMatch=%s selfSigned=%v", fmtBoolPtr(s.HostMatch), s.SelfSigned)
	}
	if len(s.Chain) != 2 ||
		s.Chain[0].Position != 1 || s.Chain[0].Label != "Server certificate" || fmtBoolPtr(s.Chain[0].SignatureValid) != "true" ||
		s.Chain[1].Position != 2 || s.Chain[1].Label != "Intermediate CA" || s.Chain[1].SignatureValid != nil {
		t.Errorf("chain = %+v", s.Chain)
	}
	if s.Subject != "trusted.test" || s.Chain[0].Subject != "trusted.test" || s.Chain[0].Issuer != "Test Intermediate CA" {
		t.Errorf("subject=%q chain[0]=%q/%q", s.Subject, s.Chain[0].Subject, s.Chain[0].Issuer)
	}
}

func TestInspect_HeadFallback(t *testing.T) {
	for _, headStatus := range []int{http.StatusMethodNotAllowed, http.StatusNotImplemented} {
		t.Run(strconv.Itoa(headStatus), func(t *testing.T) {
			var getDone atomic.Bool
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.WriteHeader(headStatus)
					return
				}
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusOK)
				w.(http.Flusher).Flush()
				// A body that never ends: reading it would hang until the timeout.
				for i := 0; i < 1000; i++ {
					if _, err := w.Write(bytes.Repeat([]byte("x"), 64*1024)); err != nil {
						break
					}
					select {
					case <-r.Context().Done():
						getDone.Store(true)
						return
					case <-time.After(10 * time.Millisecond):
					}
				}
				getDone.Store(true)
			}))
			defer upstream.Close()

			start := time.Now()
			rr := doInspect(t, testCfg(t, nil), upstream.URL, "")
			elapsed := time.Since(start)

			resp := decodeInspect(t, rr)
			if rr.Code != http.StatusOK || resp.Status != http.StatusOK || resp.Method != "GET" {
				t.Errorf("code=%d status=%d method=%q", rr.Code, resp.Status, resp.Method)
			}
			if ct := resp.Headers["Content-Type"]; len(ct) != 1 || ct[0] != "text/html" {
				t.Errorf("headers of the GET expected, got %v", resp.Headers)
			}
			if resp.Body != "" {
				t.Error("the GET body must not be returned")
			}
			if elapsed > 3*time.Second {
				t.Errorf("took %v: the GET body was read instead of closed", elapsed)
			}
		})
	}

	t.Run("404 is not retried", func(t *testing.T) {
		var gets atomic.Int32
		upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				gets.Add(1)
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer upstream.Close()

		resp := decodeInspect(t, doInspect(t, testCfg(t, nil), upstream.URL, ""))
		if resp.Status != http.StatusNotFound || resp.Method != "HEAD" || gets.Load() != 0 {
			t.Errorf("status=%d method=%q gets=%d", resp.Status, resp.Method, gets.Load())
		}
	})
}

// get=1 asks for the headers of a GET (PHP fetchUrl headersOnly = cURL
// CUSTOMREQUEST GET + NOBODY), because some servers answer HEAD with fewer
// headers — www.google.com sends HSTS only on GET. The body stays unread.
func TestInspect_HeadersViaGET(t *testing.T) {
	var heads, gets atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			heads.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		gets.Add(1)
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		// A body that never ends: reading it would hang until the timeout.
		for i := 0; i < 1000; i++ {
			if _, err := w.Write(bytes.Repeat([]byte("x"), 64*1024)); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(10 * time.Millisecond):
			}
		}
	}))
	defer upstream.Close()

	start := time.Now()
	rr := doInspect(t, testCfg(t, nil), upstream.URL, "&get=1")
	elapsed := time.Since(start)

	resp := decodeInspect(t, rr)
	if rr.Code != http.StatusOK || resp.Status != http.StatusOK || resp.Method != "GET" {
		t.Errorf("code=%d status=%d method=%q", rr.Code, resp.Status, resp.Method)
	}
	if heads.Load() != 0 || gets.Load() != 1 {
		t.Errorf("want exactly one GET and no HEAD, got heads=%d gets=%d", heads.Load(), gets.Load())
	}
	if v := resp.Headers["Strict-Transport-Security"]; len(v) != 1 {
		t.Errorf("headers of the GET expected, got %v", resp.Headers)
	}
	if resp.Body != "" || resp.Truncated {
		t.Errorf("the GET body must not be returned (body=%d bytes, truncated=%v)", len(resp.Body), resp.Truncated)
	}
	if elapsed > 3*time.Second {
		t.Errorf("took %v: the GET body was read instead of closed", elapsed)
	}

	t.Run("without get=1 the request stays HEAD", func(t *testing.T) {
		heads.Store(0)
		gets.Store(0)
		resp := decodeInspect(t, doInspect(t, testCfg(t, nil), upstream.URL, ""))
		if resp.Method != "HEAD" || heads.Load() != 1 || gets.Load() != 0 {
			t.Errorf("method=%q heads=%d gets=%d", resp.Method, heads.Load(), gets.Load())
		}
		if _, ok := resp.Headers["Strict-Transport-Security"]; ok {
			t.Error("HEAD response must not carry the GET-only header")
		}
	})

	t.Run("body=1 wins over get=1", func(t *testing.T) {
		small := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, "hello")
		}))
		defer small.Close()
		resp := decodeInspect(t, doInspect(t, testCfg(t, nil), small.URL, "&get=1&body=1"))
		if resp.Method != "GET" || resp.Body != "hello" {
			t.Errorf("method=%q body=%q", resp.Method, resp.Body)
		}
	})
}

func TestInspect_Location(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a/b/c":
			w.Header().Add("Location", "/ignored")
			w.Header().Add("Location", "../x?y=1")
			w.WriteHeader(http.StatusFound)
		case "/js":
			w.Header().Set("Location", "javascript:alert(1)")
			w.WriteHeader(http.StatusMovedPermanently)
		default:
			w.Header().Set("Location", "/not-a-redirect")
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer upstream.Close()
	cfg := testCfg(t, nil)

	resp := decodeInspect(t, doInspect(t, cfg, upstream.URL+"/a/b/c", ""))
	if resp.Status != http.StatusFound || resp.Location != upstream.URL+"/a/x?y=1" {
		t.Errorf("status=%d location=%q", resp.Status, resp.Location)
	}
	if got := resp.Headers["Location"]; len(got) != 2 {
		t.Errorf("raw Location values must stay in headers, got %v", got)
	}
	if resp := decodeInspect(t, doInspect(t, cfg, upstream.URL+"/js", "")); resp.Location != "" {
		t.Errorf("unsupported scheme: location = %q, want empty", resp.Location)
	}
	if resp := decodeInspect(t, doInspect(t, cfg, upstream.URL+"/ok", "")); resp.Location != "" {
		t.Errorf("non-3xx: location = %q, want empty", resp.Location)
	}
}

func TestInspect_BodyTruncated(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(bytes.Repeat([]byte("a"), 4096))
	}))
	defer upstream.Close()
	cfg := testCfg(t, nil)
	cfg.maxResponseBytes = 1024

	resp := decodeInspect(t, doInspect(t, cfg, upstream.URL, "&body=1"))
	if !resp.Truncated || len(resp.Body) != 1024 || resp.MaxBodySize != 1024 || resp.Method != "GET" {
		t.Errorf("truncated=%v len=%d maxBodySize=%d method=%q", resp.Truncated, len(resp.Body), resp.MaxBodySize, resp.Method)
	}

	cfg.maxResponseBytes = 4096
	if resp := decodeInspect(t, doInspect(t, cfg, upstream.URL, "&body=1")); resp.Truncated || len(resp.Body) != 4096 {
		t.Errorf("exactly at the cap: truncated=%v len=%d", resp.Truncated, len(resp.Body))
	}
}

// A server that ignores the restricted Accept-Encoding must not get its
// compressed bytes passed off as the page text.
func TestInspect_BodyUndecodableEncoding(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "br")
		w.Write([]byte{0x1b, 0x2a, 0x00, 0xf8, 0xff, 0x00})
	}))
	defer upstream.Close()

	resp := decodeInspect(t, doInspect(t, testCfg(t, nil), upstream.URL, "&body=1"))
	if !resp.DecodeError || resp.Body != "" {
		t.Errorf("decodeError=%v body=%q", resp.DecodeError, resp.Body)
	}
	if ce := resp.Headers["Content-Encoding"]; len(ce) != 1 || ce[0] != "br" {
		t.Errorf("Content-Encoding = %v", ce)
	}
}

// With body=1 the reported timing and IP belong to the GET alone; the HEAD
// encoding probe before it is not traced.
func TestInspect_BodyTimingIsTheGET(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			time.Sleep(300 * time.Millisecond)
		}
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	resp := decodeInspect(t, doInspect(t, testCfg(t, nil), upstream.URL, "&body=1"))
	if resp.Timing["ttfb"] >= 300 || resp.Timing["total"] >= 300 {
		t.Errorf("timing includes the HEAD probe: %v", resp.Timing)
	}
	if resp.IP != "127.0.0.1" {
		t.Errorf("ip = %q", resp.IP)
	}
}

// -----------------------------------------------------------------------
// /page: redirect chain, TLS diagnosis, body handling
// -----------------------------------------------------------------------

// doPage runs one /page request through the real upstream client.
func doPage(t *testing.T, cfg *config, target, extra string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/page?url="+url.QueryEscape(target)+extra, nil)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()
	pageHandler(cfg, newUpstreamClient(cfg)).ServeHTTP(rr, req)
	return rr
}

func decodePage(t *testing.T, rr *httptest.ResponseRecorder) pageResponse {
	t.Helper()
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — %s", rr.Code, rr.Body.String())
	}
	var resp pageResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode page response: %v — body: %s", err, rr.Body.String())
	}
	return resp
}

// closedPortURL returns an http URL on 127.0.0.1 nothing listens on.
func closedPortURL(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := l.Addr().String()
	l.Close()
	return "http://" + addr + "/"
}

func TestPage_ChainHeadFallback(t *testing.T) {
	for _, headStatus := range []int{http.StatusMethodNotAllowed, http.StatusNotImplemented} {
		t.Run(strconv.Itoa(headStatus), func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodHead {
					w.WriteHeader(headStatus)
					return
				}
				w.Header().Set("Location", "/final")
				w.WriteHeader(http.StatusMovedPermanently)
				w.Write(bytes.Repeat([]byte("x"), 256*1024)) // closed unread
			})
			mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte("<html>final</html>"))
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			resp := decodePage(t, doPage(t, testCfg(t, nil), srv.URL+"/start", ""))
			if resp.Error != nil {
				t.Fatalf("error = %+v", resp.Error)
			}
			if len(resp.RedirectChain) != 2 {
				t.Fatalf("expected 2 hops, got %+v", resp.RedirectChain)
			}
			first, last := resp.RedirectChain[0], resp.RedirectChain[1]
			if first.Method != "GET" || first.Status != http.StatusMovedPermanently || first.Location != srv.URL+"/final" {
				t.Errorf("hop 1: method=%q status=%d location=%q", first.Method, first.Status, first.Location)
			}
			if last.Method != "GET" || last.Status != http.StatusOK || last.URL != srv.URL+"/final" {
				t.Errorf("final hop: method=%q status=%d url=%q", last.Method, last.Status, last.URL)
			}
			if resp.FinalURL != srv.URL+"/final" || !strings.Contains(resp.HTML, "final") {
				t.Errorf("finalUrl=%q html=%q", resp.FinalURL, resp.HTML)
			}
		})
	}

	t.Run("HEAD 404 is not retried", func(t *testing.T) {
		var gets atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet {
				gets.Add(1)
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		defer srv.Close()

		resp := decodePage(t, doPage(t, testCfg(t, nil), srv.URL, ""))
		// Exactly one GET: the final page fetch, none from the tracer.
		if resp.Status != http.StatusNotFound || len(resp.RedirectChain) != 1 || gets.Load() != 1 {
			t.Errorf("status=%d hops=%d gets=%d", resp.Status, len(resp.RedirectChain), gets.Load())
		}
	})
}

func TestPage_TLSFailure(t *testing.T) {
	tlsSrv := selfSignedServer(t)
	secureURL := tlsSrv.URL + "/secure"
	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, secureURL, http.StatusMovedPermanently)
	}))
	defer start.Close()
	cfg := testCfg(t, x509.NewCertPool())

	t.Run("without diag", func(t *testing.T) {
		resp := decodePage(t, doPage(t, cfg, start.URL, ""))
		pe := resp.Error
		if pe == nil || pe.Error != "tls_error" || pe.Status != http.StatusBadGateway || pe.Type != "Self-signed certificate" ||
			!strings.HasPrefix(pe.Message, "tls_error: ") {
			t.Fatalf("error = %+v", pe)
		}
		if resp.SSL != nil {
			t.Error("without diag=1 a failed chain must not carry a certificate report")
		}
		if len(resp.RedirectChain) != 2 {
			t.Fatalf("expected 2 hops, got %+v", resp.RedirectChain)
		}
		first, failed := resp.RedirectChain[0], resp.RedirectChain[1]
		if first.Location != secureURL || first.CertCN != "" || first.CertDaysLeft != nil {
			t.Errorf("hop 1 = %+v", first)
		}
		if failed.ErrorCategory != "tls_error" || failed.ErrorType != "Self-signed certificate" || failed.Error != pe.Message ||
			failed.Method != "HEAD" || failed.IP != "127.0.0.1" || !failed.SSL || failed.URL != secureURL {
			t.Errorf("failed hop = %+v", failed)
		}
		if resp.IP != "127.0.0.1" {
			t.Errorf("ip = %q", resp.IP)
		}
	})

	t.Run("with diag", func(t *testing.T) {
		resp := decodePage(t, doPage(t, cfg, start.URL, "&diag=1"))
		if resp.Error == nil || resp.Error.Error != "tls_error" {
			t.Fatalf("error = %+v", resp.Error)
		}
		if resp.FinalURL != secureURL {
			t.Errorf("finalUrl = %q, want the failing URL %q", resp.FinalURL, secureURL)
		}
		s := resp.SSL
		if s == nil {
			t.Fatal("expected the certificate details of the failing server")
		}
		if s.Valid || s.Verified || s.CertSource != "probe" || s.ErrorType == nil || *s.ErrorType != "Self-signed certificate" {
			t.Errorf("valid=%v verified=%v source=%q errorType=%v", s.Valid, s.Verified, s.CertSource, s.ErrorType)
		}
		if len(s.Chain) != 1 || s.Chain[0].Subject != "self-signed.test" || s.HostMatch == nil || !*s.HostMatch {
			t.Errorf("chain=%+v hostMatch=%s", s.Chain, fmtBoolPtr(s.HostMatch))
		}
	})
}

func TestPage_TooManyRedirects(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/r/"))
		w.Header().Set("Location", fmt.Sprintf("/r/%d", n+1))
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	resp := decodePage(t, doPage(t, testCfg(t, nil), srv.URL+"/r/0", ""))
	if resp.Error == nil || resp.Error.Error != "too_many_redirects" || resp.Error.Type != "Too many redirects" ||
		resp.Error.Status != http.StatusBadGateway {
		t.Fatalf("error = %+v", resp.Error)
	}
	if len(resp.RedirectChain) != 22 {
		t.Fatalf("expected 21 redirect hops + the error hop, got %d", len(resp.RedirectChain))
	}
	last := resp.RedirectChain[21]
	if last.Hop != 22 || last.ErrorCategory != "too_many_redirects" || last.Error != "too_many_redirects: more than 20 redirects" ||
		last.URL != srv.URL+"/r/21" || last.Method != "" || last.Status != 0 {
		t.Errorf("error hop = %+v", last)
	}
	if hop := resp.RedirectChain[20]; hop.Status != http.StatusFound || hop.Location != srv.URL+"/r/21" {
		t.Errorf("hop 21 = %+v", hop)
	}
	// The URL after the 21st redirect is reported, never requested — and
	// there is no final GET.
	if n := requests.Load(); n != 21 {
		t.Errorf("upstream saw %d requests, want 21", n)
	}
}

// Exactly 20 redirects are allowed, like the Fetch standard's limit.
func TestPage_TwentyRedirectsSucceed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/r/"))
		if n == 20 {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte("<html>done</html>"))
			return
		}
		w.Header().Set("Location", fmt.Sprintf("/r/%d", n+1))
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	resp := decodePage(t, doPage(t, testCfg(t, nil), srv.URL+"/r/0", ""))
	if resp.Error != nil {
		t.Fatalf("error = %+v, want success after exactly 20 redirects", resp.Error)
	}
	if resp.FinalURL != srv.URL+"/r/20" || !strings.Contains(resp.HTML, "done") {
		t.Errorf("finalUrl = %q, html = %q", resp.FinalURL, resp.HTML)
	}
	if len(resp.RedirectChain) != 21 {
		t.Errorf("chain length = %d, want 20 redirects + the final hop", len(resp.RedirectChain))
	}
}

// A redirect hop that passed the SSRF pre-check but whose connection the
// dialer blocks (DNS rebinding) keeps the v1.2.x contract: 502 blocked_target,
// with the type.
func TestProxy_FollowDialerBlock(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the blocked hop must never be reached")
	}))
	defer target.Close()
	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/secret")
		w.WriteHeader(http.StatusFound)
	}))
	defer start.Close()

	cfg := testCfg(t, nil) // pre-check allows everything
	blockedAddr := strings.TrimPrefix(target.URL, "http://")
	cfg.dialControl = func(network, address string, c syscall.RawConn) error {
		if address == blockedAddr {
			return safeDialControl(network, address, c) // 127.0.0.1: blocked
		}
		return nil
	}

	rr := doProxy(t, cfg, http.MethodGet, start.URL+"/", "&follow=1", nil)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", rr.Code)
	}
	var pe proxyError
	if err := json.Unmarshal(rr.Body.Bytes(), &pe); err != nil {
		t.Fatalf("decode error body: %v — %s", err, rr.Body.String())
	}
	if pe.Error != "blocked_target" || pe.Status != http.StatusBadGateway || pe.Type != "Blocked target" {
		t.Errorf("error body = %+v", pe)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("dialer-block error carries no CORS headers")
	}
}

// Every way a chain can stop yields a non-empty error code that matches the
// failed hop's errorCategory.
func TestPage_ChainStopCategories(t *testing.T) {
	refused := closedPortURL(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	mux.HandleFunc("/blocked", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://blocked.test/x", http.StatusFound)
	})
	mux.HandleFunc("/js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "javascript:alert(1)")
		w.WriteHeader(http.StatusFound)
	})
	mux.HandleFunc("/refused", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, refused, http.StatusFound)
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := testCfg(t, nil)
	cfg.ssrfCheck = func(host string) bool { return host == "blocked.test" }
	cfg.requestTimeout = 300 * time.Millisecond

	tests := []struct {
		path, code, typ, lastURL string
		status, hops             int
	}{
		{"/loop", "redirect_loop", "Redirect loop detected", srv.URL + "/loop", 502, 2},
		{"/blocked", "blocked_target", "Blocked target", "http://blocked.test/x", 502, 2},
		{"/js", "blocked_target", "Blocked target", "javascript:alert(1)", 502, 2},
		{"/refused", "connection_error", "Could not connect to host", refused, 502, 2},
		{"/slow", "timeout", "Connection timeout", srv.URL + "/slow", 504, 1},
	}
	for _, tc := range tests {
		t.Run(tc.path, func(t *testing.T) {
			resp := decodePage(t, doPage(t, cfg, srv.URL+tc.path, ""))
			if resp.Error == nil || resp.Error.Error != tc.code || resp.Error.Type != tc.typ || resp.Error.Status != tc.status {
				t.Fatalf("error = %+v", resp.Error)
			}
			if len(resp.RedirectChain) != tc.hops {
				t.Fatalf("hops = %+v", resp.RedirectChain)
			}
			last := resp.RedirectChain[len(resp.RedirectChain)-1]
			if last.ErrorCategory != tc.code || last.Error != resp.Error.Message || last.URL != tc.lastURL {
				t.Errorf("last hop = %+v", last)
			}
			if last.ErrorType != "" {
				t.Errorf("errorType is for tls_error only, got %q", last.ErrorType)
			}
		})
	}
}

func TestPage_FinalGETTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			return // the redirect trace and the encoding probe pass
		}
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}))
	defer upstream.Close()

	cfg := testCfg(t, nil)
	cfg.requestTimeout = 200 * time.Millisecond

	start := time.Now()
	resp := decodePage(t, doPage(t, cfg, upstream.URL, ""))
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %v", elapsed)
	}
	if resp.Error == nil || resp.Error.Error != "timeout" || resp.Error.Status != http.StatusGatewayTimeout ||
		resp.Error.Type != "Connection timeout" {
		t.Fatalf("error = %+v", resp.Error)
	}
	if resp.IP != "127.0.0.1" || resp.SSL != nil || resp.HTML != "" {
		t.Errorf("ip=%q ssl=%v html=%q", resp.IP, resp.SSL, resp.HTML)
	}
	// No fake hop for the failed GET.
	if len(resp.RedirectChain) != 0 {
		t.Errorf("redirectChain = %+v", resp.RedirectChain)
	}
}

func TestPage_Truncated(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/utf8" {
			w.Write([]byte(strings.Repeat("ä", 2048))) // 2 bytes per rune
			return
		}
		w.Write(bytes.Repeat([]byte("a"), 4096))
	}))
	defer upstream.Close()
	cfg := testCfg(t, nil)
	cfg.maxResponseBytes = 1024

	resp := decodePage(t, doPage(t, cfg, upstream.URL, ""))
	if !resp.Truncated || resp.MaxBodySize != 1024 || len(resp.HTML) != 1024 || resp.Size != 1024 {
		t.Errorf("truncated=%v maxBodySize=%d len=%d size=%d", resp.Truncated, resp.MaxBodySize, len(resp.HTML), resp.Size)
	}

	cfg.maxResponseBytes = 1025 // cuts through the 513th "ä"
	resp = decodePage(t, doPage(t, cfg, upstream.URL+"/utf8", ""))
	if !resp.Truncated || len(resp.HTML) != 1024 || !utf8.ValidString(resp.HTML) {
		t.Errorf("truncated=%v len=%d valid=%v", resp.Truncated, len(resp.HTML), utf8.ValidString(resp.HTML))
	}

	cfg.maxResponseBytes = 4096
	if resp := decodePage(t, doPage(t, cfg, upstream.URL, "")); resp.Truncated || len(resp.HTML) != 4096 {
		t.Errorf("exactly at the cap: truncated=%v len=%d", resp.Truncated, len(resp.HTML))
	}
}

func TestPage_CorruptGzipNeverRaw(t *testing.T) {
	var page strings.Builder
	page.WriteString("<html><body>")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&page, "<p>paragraph %d</p>", i)
	}
	page.WriteString("</body></html>")
	original := page.String()

	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(original))
	zw.Close()
	compressed := gz.Bytes()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/corrupt":
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(compressed[:len(compressed)/2])
		case "/br":
			w.Header().Set("Content-Encoding", "br")
			w.Write([]byte{0x1b, 0x2a, 0x00, 0xf8, 0xff, 0x00})
		default:
			w.Header().Set("Content-Encoding", "gzip")
			w.Write(compressed)
		}
	}))
	defer upstream.Close()
	cfg := testCfg(t, nil)

	resp := decodePage(t, doPage(t, cfg, upstream.URL+"/corrupt", ""))
	if !resp.DecodeError || strings.HasPrefix(resp.HTML, "\x1f\x8b") || !strings.HasPrefix(original, resp.HTML) {
		t.Errorf("corrupt gzip: decodeError=%v html starts %q", resp.DecodeError, resp.HTML[:min(len(resp.HTML), 16)])
	}

	resp = decodePage(t, doPage(t, cfg, upstream.URL+"/br", ""))
	if !resp.DecodeError || resp.HTML != "" || resp.ContentEncoding != "br" {
		t.Errorf("br: decodeError=%v html=%q contentEncoding=%q", resp.DecodeError, resp.HTML, resp.ContentEncoding)
	}

	resp = decodePage(t, doPage(t, cfg, upstream.URL+"/ok", ""))
	if resp.DecodeError || resp.HTML != original || resp.Size != len(original) || resp.TransferSize != len(compressed) {
		t.Errorf("valid gzip: decodeError=%v size=%d transferSize=%d", resp.DecodeError, resp.Size, resp.TransferSize)
	}
}

// Regression against v1.2.4: a plain page behind a bogus Content-Encoding
// ("none", "UTF-8") must still arrive as html; real but undecodable codings
// and binary bytes behind a bogus token never do.
func TestPage_UnknownContentEncoding(t *testing.T) {
	const html = "<html><head><title>Grüße</title></head><body>ok</body></html>"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/none":
			w.Header().Set("Content-Encoding", "none")
			w.Write([]byte(html))
		case "/utf8":
			w.Header().Set("Content-Encoding", "UTF-8")
			w.Write([]byte(html))
		case "/br":
			w.Header().Set("Content-Encoding", "br")
			w.Write([]byte{0x1b, 0x2a, 0x00, 0xf8, 0xff, 0x00})
		case "/binary":
			w.Header().Set("Content-Encoding", "x-custom")
			w.Write([]byte{0x00, 0x9c, 0xff, 0xfe, 0x80, 0x81})
		}
	}))
	defer upstream.Close()
	cfg := testCfg(t, nil)

	for _, path := range []string{"/none", "/utf8"} {
		resp := decodePage(t, doPage(t, cfg, upstream.URL+path, ""))
		if resp.DecodeError || resp.HTML != html {
			t.Errorf("%s: decodeError=%v html=%q", path, resp.DecodeError, resp.HTML)
		}
	}
	for _, path := range []string{"/br", "/binary"} {
		resp := decodePage(t, doPage(t, cfg, upstream.URL+path, ""))
		if !resp.DecodeError || resp.HTML != "" {
			t.Errorf("%s: decodeError=%v html=%q", path, resp.DecodeError, resp.HTML)
		}
	}

	// Same rule on /inspect?body=1.
	ins := decodeInspect(t, doInspect(t, cfg, upstream.URL+"/none", "&body=1"))
	if ins.DecodeError || ins.Body != html {
		t.Errorf("/inspect none: decodeError=%v body=%q", ins.DecodeError, ins.Body)
	}
}

func TestPage_HopCertSummary(t *testing.T) {
	p := newTestPKI(t)
	der, key := p.leaf(t, certOpts{cn: "hop.test"})
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>secure</html>"))
	})
	srv := tlsServerWith(t, [][]byte{der, p.interDER}, key, nil, mux)

	rr := doPage(t, testCfg(t, p.pool), srv.URL+"/start", "")
	resp := decodePage(t, rr)
	if resp.Error != nil || len(resp.RedirectChain) != 2 {
		t.Fatalf("error=%+v hops=%+v", resp.Error, resp.RedirectChain)
	}
	wantExpiry := leaf.NotAfter.UTC().Format("2006-01-02")
	// NotAfter is now+90 days at whole seconds, like PHP's time(): 90 while
	// the clock is still in the second the leaf was issued, 89 after that.
	for i, hop := range resp.RedirectChain {
		if hop.CertCN != "hop.test" || hop.CertExpiry != wantExpiry || hop.CertDaysLeft == nil ||
			(*hop.CertDaysLeft != 89 && *hop.CertDaysLeft != 90) {
			t.Errorf("hop %d: certCN=%q certExpiry=%q certDaysLeft=%v", i+1, hop.CertCN, hop.CertExpiry, hop.CertDaysLeft)
		}
	}
	s := resp.SSL
	if s == nil || !s.Verified || s.CertSource != "connection" || s.HostMatch == nil || !*s.HostMatch {
		t.Fatalf("ssl = %+v", s)
	}

	// New keys present on success, decodeError only when set.
	var raw map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, k := range []string{"truncated", "maxBodySize"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("missing key %q", k)
		}
	}
	if _, ok := raw["decodeError"]; ok {
		t.Error("decodeError must be omitted when false")
	}
}

func TestPage_RawHeadersStatusLine(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Zeta", "z")
		w.Header().Set("X-Alpha", "a")
		w.Header().Set("Location", "/final")
		w.WriteHeader(http.StatusMovedPermanently)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "FinalServer")
		w.Write([]byte("<html>final</html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resp := decodePage(t, doPage(t, testCfg(t, nil), srv.URL+"/start", ""))
	if len(resp.RedirectChain) != 2 {
		t.Fatalf("hops = %+v", resp.RedirectChain)
	}
	lines := strings.Split(strings.TrimSuffix(resp.RedirectChain[0].RawHeaders, "\n"), "\n")
	if lines[0] != "HTTP/1.1 301 Moved Permanently" {
		t.Errorf("status line = %q", lines[0])
	}
	var keys []string
	for _, l := range lines[1:] {
		k, _, ok := strings.Cut(l, ": ")
		if !ok {
			t.Errorf("malformed header line %q", l)
		}
		keys = append(keys, k)
	}
	if !slices.IsSorted(keys) || !slices.Contains(keys, "X-Alpha") || !slices.Contains(keys, "Location") {
		t.Errorf("header keys = %v, want sorted", keys)
	}
	if !strings.HasPrefix(resp.RawHeaders, "HTTP/1.1 200 OK\n") || resp.RedirectChain[1].RawHeaders != resp.RawHeaders {
		t.Errorf("page rawHeaders = %q", resp.RawHeaders)
	}
}

func TestStatusLine(t *testing.T) {
	tests := []struct {
		resp *http.Response
		want string
	}{
		{&http.Response{Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Status: "301 Moved Permanently", StatusCode: 301}, "HTTP/1.1 301 Moved Permanently"},
		{&http.Response{Proto: "HTTP/1.0", ProtoMajor: 1, Status: "404 Not Found", StatusCode: 404}, "HTTP/1.0 404 Not Found"},
		{&http.Response{Proto: "HTTP/2.0", ProtoMajor: 2, Status: "200 OK", StatusCode: 200}, "HTTP/2 200"},
		{&http.Response{StatusCode: 204}, "HTTP/1.1 204 No Content"},
		{&http.Response{StatusCode: 599}, "HTTP/1.1 599"},
	}
	for _, tc := range tests {
		if got := statusLine(tc.resp); got != tc.want {
			t.Errorf("statusLine(%s/%d) = %q, want %q", tc.resp.Proto, tc.resp.StatusCode, got, tc.want)
		}
	}
}

func TestFormatRawHeaders_SortedAndKeepsValueOrder(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "b=2")
	h.Add("Set-Cookie", "a=1")
	h.Set("Age", "5")
	if got, want := formatRawHeaders(h), "Age: 5\nSet-Cookie: b=2\nSet-Cookie: a=1\n"; got != want {
		t.Errorf("formatRawHeaders = %q, want %q", got, want)
	}
}

// -----------------------------------------------------------------------
// /proxy redirects: Location, X-Upstream-Location and follow=1
// -----------------------------------------------------------------------

// doProxy runs one /proxy request through the real upstream client.
func doProxy(t *testing.T, cfg *config, method, target, extra string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/proxy?url="+url.QueryEscape(target)+extra, body)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	rr := httptest.NewRecorder()
	proxyHandler(cfg, newUpstreamClient(cfg)).ServeHTTP(rr, req)
	return rr
}

// exposed reports whether name is listed in Access-Control-Expose-Headers.
func exposed(rr *httptest.ResponseRecorder, name string) bool {
	for _, h := range strings.Split(rr.Header().Get("Access-Control-Expose-Headers"), ",") {
		if strings.EqualFold(strings.TrimSpace(h), name) {
			return true
		}
	}
	return false
}

func TestProxy_LocationNotForwarded(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a/b":
			w.Header().Set("Location", "../x")
			w.WriteHeader(http.StatusFound)
		case "/multi":
			// Several Location values: the last one wins, as in PHP.
			w.Header().Add("Location", "/first")
			w.Header().Add("Location", "/last")
			w.WriteHeader(http.StatusMovedPermanently)
		case "/ok":
			// A Location on a non-3xx is dropped as well, with no replacement.
			w.Header().Set("Location", "/elsewhere")
			w.WriteHeader(http.StatusCreated)
		default:
			t.Errorf("unexpected upstream request %s — redirects must not be followed without follow=1", r.URL.Path)
		}
	}))
	defer upstream.Close()
	cfg := testCfg(t, nil)

	tests := []struct {
		path       string
		wantStatus int
		wantLoc    string
	}{
		{"/a/b", http.StatusFound, upstream.URL + "/x"},
		{"/multi", http.StatusMovedPermanently, upstream.URL + "/last"},
		{"/ok", http.StatusCreated, ""},
	}
	for _, tc := range tests {
		rr := doProxy(t, cfg, http.MethodGet, upstream.URL+tc.path, "", nil)
		if rr.Code != tc.wantStatus {
			t.Errorf("%s: status %d, want %d", tc.path, rr.Code, tc.wantStatus)
		}
		if got := rr.Header().Values("Location"); len(got) != 0 {
			t.Errorf("%s: Location forwarded to the browser: %q", tc.path, got)
		}
		if got := rr.Header().Get("X-Upstream-Location"); got != tc.wantLoc {
			t.Errorf("%s: X-Upstream-Location = %q, want %q", tc.path, got, tc.wantLoc)
		}
		if exposed(rr, "Location") {
			t.Errorf("%s: Location listed in Access-Control-Expose-Headers", tc.path)
		}
		if !exposed(rr, "X-Upstream-Location") {
			t.Errorf("%s: X-Upstream-Location not exposed: %q", tc.path, rr.Header().Get("Access-Control-Expose-Headers"))
		}
		// Without follow=1 there is no follow report.
		if got := rr.Header().Get("X-Upstream-Final-URL"); got != "" {
			t.Errorf("%s: X-Upstream-Final-URL = %q without follow=1", tc.path, got)
		}
		if got := rr.Header().Get("X-Upstream-Redirects"); got != "" {
			t.Errorf("%s: X-Upstream-Redirects = %q without follow=1", tc.path, got)
		}
	}
}

func TestProxy_Follow(t *testing.T) {
	var hits atomic.Int32
	var lastMethod, lastBody atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		lastMethod.Store(r.Method)
		b, _ := io.ReadAll(r.Body)
		lastBody.Store(string(b))
		w.Header().Set("X-Hop", r.URL.Path)
		switch {
		case r.URL.Path == "/start":
			w.Header().Set("Location", "final") // relative to /start
			w.WriteHeader(http.StatusMovedPermanently)
		case r.URL.Path == "/final":
			w.Header().Set("Content-Type", "text/plain")
			if r.Method != http.MethodHead {
				w.Write([]byte("final-body"))
			}
		case r.URL.Path == "/to-blocked":
			w.Header().Set("Location", "http://blocked.test/secret")
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/loop-a":
			w.Header().Set("Location", "/loop-b")
			w.WriteHeader(http.StatusFound)
		case r.URL.Path == "/loop-b":
			w.Header().Set("Location", "/loop-a")
			w.WriteHeader(http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/chain/"):
			n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/chain/"))
			w.Header().Set("Location", fmt.Sprintf("/chain/%d", n+1))
			w.WriteHeader(http.StatusTemporaryRedirect)
		case r.URL.Path == "/post":
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusSeeOther)
		case r.URL.Path == "/js":
			w.Header().Set("Location", "javascript:alert(1)")
			w.WriteHeader(http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	cfg := testCfg(t, nil)
	cfg.ssrfCheck = func(host string) bool { return host == "blocked.test" }

	run := func(t *testing.T, method, path, extra, body string) *httptest.ResponseRecorder {
		t.Helper()
		hits.Store(0)
		var rb io.Reader
		if body != "" {
			rb = strings.NewReader(body)
		}
		return doProxy(t, cfg, method, upstream.URL+path, extra, rb)
	}

	t.Run("relative 301 is followed", func(t *testing.T) {
		rr := run(t, http.MethodGet, "/start", "&follow=1", "")
		if rr.Code != http.StatusOK || rr.Body.String() != "final-body" {
			t.Fatalf("got %d %q, want 200 final-body", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("X-Upstream-Final-URL"); got != upstream.URL+"/final" {
			t.Errorf("X-Upstream-Final-URL = %q", got)
		}
		if got := rr.Header().Get("X-Upstream-Redirects"); got != "1" {
			t.Errorf("X-Upstream-Redirects = %q, want 1", got)
		}
		// Headers and metadata describe the final hop.
		if got := rr.Header().Get("X-Hop"); got != "/final" {
			t.Errorf("X-Hop = %q, want the final hop's headers", got)
		}
		if got := rr.Header().Get("X-Upstream-IP"); got != "127.0.0.1" {
			t.Errorf("X-Upstream-IP = %q", got)
		}
		if got := rr.Header().Get("X-Upstream-Location"); got != "" {
			t.Errorf("X-Upstream-Location = %q on a 200", got)
		}
		for _, h := range []string{"X-Upstream-Location", "X-Upstream-Final-URL", "X-Upstream-Redirects"} {
			if !exposed(rr, h) {
				t.Errorf("%s not exposed: %q", h, rr.Header().Get("Access-Control-Expose-Headers"))
			}
		}
		if n := hits.Load(); n != 2 {
			t.Errorf("upstream hits = %d, want 2", n)
		}
	})

	t.Run("no redirect reports zero", func(t *testing.T) {
		rr := run(t, http.MethodGet, "/final", "&follow=1", "")
		if got := rr.Header().Get("X-Upstream-Final-URL"); got != upstream.URL+"/final" {
			t.Errorf("X-Upstream-Final-URL = %q", got)
		}
		if got := rr.Header().Get("X-Upstream-Redirects"); got != "0" {
			t.Errorf("X-Upstream-Redirects = %q, want 0", got)
		}
	})

	t.Run("HEAD keeps its method", func(t *testing.T) {
		rr := run(t, http.MethodHead, "/start", "&follow=1", "")
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d, want 200", rr.Code)
		}
		if got := lastMethod.Load(); got != http.MethodHead {
			t.Errorf("final hop method = %v, want HEAD", got)
		}
	})

	t.Run("blocked hop", func(t *testing.T) {
		rr := run(t, http.MethodGet, "/to-blocked", "&follow=1", "")
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", rr.Code)
		}
		var pe proxyError
		if err := json.Unmarshal(rr.Body.Bytes(), &pe); err != nil {
			t.Fatalf("decode error body: %v — %s", err, rr.Body.String())
		}
		if pe.Error != "blocked_target" || pe.Status != http.StatusForbidden || pe.Type != "Blocked target" {
			t.Errorf("error body = %+v", pe)
		}
		if rr.Header().Get("Access-Control-Allow-Origin") == "" {
			t.Error("blocked-hop error carries no CORS headers")
		}
		if n := hits.Load(); n != 1 {
			t.Errorf("upstream hits = %d, want 1", n)
		}
	})

	t.Run("loop returns the last 3xx", func(t *testing.T) {
		rr := run(t, http.MethodGet, "/loop-a", "&follow=1", "")
		if rr.Code != http.StatusFound {
			t.Fatalf("status %d, want 302", rr.Code)
		}
		if got := rr.Header().Get("X-Upstream-Location"); got != upstream.URL+"/loop-a" {
			t.Errorf("X-Upstream-Location = %q", got)
		}
		if got := rr.Header().Get("X-Upstream-Final-URL"); got != upstream.URL+"/loop-b" {
			t.Errorf("X-Upstream-Final-URL = %q", got)
		}
		if got := rr.Header().Get("X-Upstream-Redirects"); got != "1" {
			t.Errorf("X-Upstream-Redirects = %q, want 1", got)
		}
		if n := hits.Load(); n != 2 {
			t.Errorf("upstream hits = %d, want 2", n)
		}
	})

	t.Run("more than five redirects", func(t *testing.T) {
		rr := run(t, http.MethodGet, "/chain/0", "&follow=1", "")
		if rr.Code != http.StatusTemporaryRedirect {
			t.Fatalf("status %d, want 307", rr.Code)
		}
		if got := rr.Header().Get("X-Upstream-Redirects"); got != strconv.Itoa(maxProxyRedirects) {
			t.Errorf("X-Upstream-Redirects = %q, want %d", got, maxProxyRedirects)
		}
		if got := rr.Header().Get("X-Upstream-Final-URL"); got != upstream.URL+"/chain/5" {
			t.Errorf("X-Upstream-Final-URL = %q", got)
		}
		if got := rr.Header().Get("X-Upstream-Location"); got != upstream.URL+"/chain/6" {
			t.Errorf("X-Upstream-Location = %q", got)
		}
		if n := hits.Load(); n != maxProxyRedirects+1 {
			t.Errorf("upstream hits = %d, want %d", n, maxProxyRedirects+1)
		}
	})

	t.Run("unsupported scheme is not followed", func(t *testing.T) {
		rr := run(t, http.MethodGet, "/js", "&follow=1", "")
		if rr.Code != http.StatusFound {
			t.Fatalf("status %d, want 302", rr.Code)
		}
		if got := rr.Header().Get("X-Upstream-Location"); got != "" {
			t.Errorf("X-Upstream-Location = %q for a javascript: target", got)
		}
		if got := rr.Header().Get("X-Upstream-Redirects"); got != "0" {
			t.Errorf("X-Upstream-Redirects = %q, want 0", got)
		}
	})

	t.Run("POST is not followed", func(t *testing.T) {
		rr := run(t, http.MethodPost, "/post", "&follow=1", "payload")
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("status %d, want 303", rr.Code)
		}
		if got := lastBody.Load(); got != "payload" {
			t.Errorf("upstream body = %v, want the POST payload", got)
		}
		if got := rr.Header().Get("X-Upstream-Location"); got != upstream.URL+"/final" {
			t.Errorf("X-Upstream-Location = %q", got)
		}
		if got := rr.Header().Get("X-Upstream-Final-URL"); got != "" {
			t.Errorf("X-Upstream-Final-URL = %q for a POST", got)
		}
		if n := hits.Load(); n != 1 {
			t.Errorf("upstream hits = %d, want 1", n)
		}
	})
}

// -----------------------------------------------------------------------
// --allow-local (LOCAL-1 to LOCAL-9)
// -----------------------------------------------------------------------

// localCfg is newTestConfig with the real SSRF guard (no ssrfCheck, no
// dialControl), the --allow-local entries (empty = flag off), every origin
// allowed and roots as trust store. hosts answers the lookup hook: name →
// comma-separated IPs; any other name is NXDOMAIN. The counter counts lookups.
func localCfg(t *testing.T, entries string, hosts map[string]string, roots *x509.CertPool) (*config, *atomic.Int32) {
	t.Helper()
	cfg := newTestConfig()
	cfg.allowedOrigins = nil
	cfg.rootCAs = roots
	if entries != "" {
		list, err := parseAllowLocal([]string{entries}, 0)
		if err != nil {
			t.Fatalf("parseAllowLocal(%q): %v", entries, err)
		}
		cfg.allowLocal = list
	}
	lookups := &atomic.Int32{}
	cfg.lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		lookups.Add(1)
		v, ok := hosts[strings.ToLower(host)]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		var addrs []net.IPAddr
		for _, s := range strings.Split(v, ",") {
			addrs = append(addrs, net.IPAddr{IP: net.ParseIP(s)})
		}
		return addrs, nil
	}
	return cfg, lookups
}

// countingServer is a plain HTTP test server that counts its requests.
func countingServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if h != nil {
			h(w, r)
			return
		}
		w.Write([]byte("local ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, hits
}

// decodeProxyError decodes a top-level JSON error body.
func decodeProxyError(t *testing.T, rr *httptest.ResponseRecorder) proxyError {
	t.Helper()
	var pe proxyError
	if err := json.Unmarshal(rr.Body.Bytes(), &pe); err != nil {
		t.Fatalf("decode error body: %v — %s", err, rr.Body.String())
	}
	return pe
}

// wantBlocked asserts a top-level blocked_target error with status and reason.
func wantBlocked(t *testing.T, rr *httptest.ResponseRecorder, status int, reason string) {
	t.Helper()
	if rr.Code != status {
		t.Fatalf("status %d, want %d — %s", rr.Code, status, rr.Body.String())
	}
	pe := decodeProxyError(t, rr)
	if pe.Error != "blocked_target" || pe.Status != status || pe.Reason != reason {
		t.Errorf("error body = %+v, want blocked_target/%d/%s", pe, status, reason)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("blocked_target error carries no CORS headers")
	}
}

func TestParseAllowLocal(t *testing.T) {
	valid := []struct {
		in   string
		want string // canonical String() of all entries, comma-joined
	}{
		{"wp.test", "wp.test"},
		{"WP.Test.", "wp.test"},
		{"nas.lan", "nas.lan"},
		{"wp.home.arpa", "wp.home.arpa"},
		{"*.test", "*.test"},
		{"*.localhost", "*.localhost"},
		{"localhost", "localhost"},
		{"*.ddev.site,localhost:8888", "*.ddev.site,localhost:8888"},
		{" *.ddev.site , , localhost:8888 ", "*.ddev.site,localhost:8888"},
		{"*.intranet.example", "*.intranet.example"},
		{"10.0.5.20", "10.0.5.20"},
		{"10.0.5.0/24", "10.0.5.0/24"},
		{"10.0.5.0/24:8080", "10.0.5.0/24:8080"},
		{"127.0.0.1:8888", "127.0.0.1:8888"},
		{"192.168.0.0/16", "192.168.0.0/16"},
		{"100.64.0.0/16", "100.64.0.0/16"},
		{"100.100.0.0/16", "100.100.0.0/16"}, // contains a metadata address, which stays blocked
		{"[fd00::5]", "[fd00::5]"},
		{"[fd00::5]:8443", "[fd00::5]:8443"},
		{"[fd00::/64]", "[fd00::/64]"},
		{"[fd00::/64]:8443", "[fd00::/64]:8443"},
		{"[fd00:ec2::/48]", "[fd00:ec2::/48]"},
		{"[::1]", "[::1]"},
		{"wp.test:65535", "wp.test:65535"},
	}
	for _, tc := range valid {
		t.Run("ok/"+tc.in, func(t *testing.T) {
			entries, err := parseAllowLocal([]string{tc.in}, 8765)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			var got []string
			for _, e := range entries {
				got = append(got, e.String())
			}
			if strings.Join(got, ",") != tc.want {
				t.Errorf("got %q, want %q", strings.Join(got, ","), tc.want)
			}
		})
	}

	invalid := []struct {
		in       string
		mentions string // the error must contain this
	}{
		{"", "empty"},
		{" , ,", "empty"},
		{"*", "every name"},
		{"a.*.example", "wildcard"},
		{"*.*.example", "wildcard"},
		{"*example.com", "wildcard"},
		{"*.lan", "every device"},
		{"*.local", "every device"},
		{"*.internal", "every device"},
		{"*.home.arpa", "home network"},
		{"*.fritz.box", "home network"},
		{"*.nas.home.arpa", "only exact names"},
		{"*.x.fritz.box", "only exact names"},
		{`"*.ddev.site`, "quotation marks"},
		{`localhost:8888"`, "quotation marks"},
		{"'wp.test'", "quotation marks"},
		{"\u201c*.ddev.site\u201d", "quotation marks"},
		{"\u2018wp.test\u2019", "quotation marks"},
		{"*.nip.io", "nip.io"},
		{"*.sslip.io", "sslip.io"},
		{"*.xip.io", "xip.io"},
		{"*.localtest.me", "localtest.me"},
		{"*.lvh.me", "lvh.me"},
		{"*.traefik.me", "traefik.me"},
		{"*.10.0.0.1.nip.io", "nip.io"},
		{"fd00::5", "brackets"},
		{"fd00::/64", "brackets"},
		{"[10.0.5.20]", "without brackets"},
		{"[wp.test]", "IPv6"},
		{"[fd00::5", `"]"`},
		{"[fd00::5]x", "after"},
		{"localhost:*", "single number"},
		{"localhost:8000-8100", "single number"},
		{"localhost:", "empty port"},
		{"localhost:0", "between 1 and 65535"},
		{"localhost:65536", "between 1 and 65535"},
		{"localhost:8765", "own --port"},
		{"10.0.5.20:6379", "Redis"},
		{"localhost:2375", "Docker"},
		{"localhost:2376", "Docker"},
		{"localhost:2379", "etcd"},
		{"localhost:3306", "MySQL"},
		{"localhost:5432", "PostgreSQL"},
		{"localhost:9200", "Elasticsearch"},
		{"localhost:10250", "kubelet"},
		{"localhost:11211", "memcached"},
		{"localhost:27017", "MongoDB"},
		{"0.0.0.0/0", "every address"},
		{"[::/0]", "every address"},
		{"10.0.0.0/8", "/16 or narrower"},
		{"[fd00::/32]", "/48 or narrower"},
		{"10.0.5.1/24", "host bits"},
		{"192.0.0.0/16", "mixes"},
		{"172.32.0.0/16", "public"},
		{"8.8.8.8", "public"},
		{"169.254.0.0/16", "always blocked"},
		{"169.254.169.254", "always blocked"},
		{"100.100.100.200", "metadata"},
		{"[fd00:ec2::254]", "metadata"},
		{"224.0.0.1", "always blocked"},
		{"[fe80::1]", "always blocked"},
		{"[2002::/48]", "always blocked"},
		{"-bad-.test", "not a valid host name"},
		{"under_score.test", "not a valid host name"},
		{"1.2.3", "not a valid host name"},
		{"wp.tëst", "Punycode"},
		{"https://wp.test", "scheme"},
		{"wp.test/path", "CIDR"},
	}
	for _, tc := range invalid {
		t.Run("bad/"+tc.in, func(t *testing.T) {
			_, err := parseAllowLocal([]string{tc.in}, 8765)
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), tc.mentions) {
				t.Errorf("error %q does not mention %q", err, tc.mentions)
			}
			if strings.TrimSpace(strings.Trim(tc.in, ", ")) != "" && !strings.Contains(err.Error(), fmt.Sprintf("%q", strings.TrimSpace(strings.Split(tc.in, ",")[0]))) {
				t.Errorf("error %q does not name the entry", err)
			}
		})
	}

	// The flag may be repeated; the values are merged.
	entries, err := parseAllowLocal([]string{"wp.test", "localhost:8888,10.0.5.0/24"}, 0)
	if err != nil || len(entries) != 3 {
		t.Fatalf("repeated flag: %v, %d entries", err, len(entries))
	}
	// --port 0 (random port) cannot be named in advance.
	if _, err := parseAllowLocal([]string{"localhost:8765"}, 0); err != nil {
		t.Errorf("with --port 0 any port is fine: %v", err)
	}
}

func TestValidateFlags_PositionalArgs(t *testing.T) {
	base := startFlags{timeoutSec: 30, maxMB: 50}

	// PowerShell splits an unquoted list into separate arguments.
	f := base
	f.rawOrigins = "https://www.jpkc.com"
	f.allowLocal, f.allowLocalSet = []string{"*.ddev.site"}, true
	f.args = []string{"localhost:8888", "--origin", "https://www.jpkc.com"}
	_, err := validateFlags(f)
	if err == nil {
		t.Fatal("expected leftover arguments with --allow-local to be fatal")
	}
	for _, want := range []string{"localhost:8888", `quote the list: --allow-local "a,b"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q", err, want)
		}
	}
	// The argument check comes before "requires --origin", whose message
	// would be misleading here.
	f.rawOrigins = ""
	if _, err := validateFlags(f); err == nil || strings.Contains(err.Error(), "requires --origin") {
		t.Errorf("got %v, want the positional-argument error", err)
	}

	// --allow-local itself among the leftovers: an unquoted --origin list
	// stopped the flag parser before it. The user meant to set the flag, so
	// this is fatal as well, with the same hint.
	for _, args := range [][]string{
		{"https://b.example", "--allow-local", "*.ddev.site"},
		{"https://b.example", "-allow-local", "*.ddev.site"},
		{"https://b.example", "--allow-local=*.ddev.site"},
		{"https://b.example", "-allow-local=*.ddev.site"},
	} {
		f = base
		f.rawOrigins = "https://a.example"
		f.args = args
		if _, err := validateFlags(f); err == nil || !strings.Contains(err.Error(), `quote the list: --allow-local "a,b"`) {
			t.Errorf("args %q: %v, want the positional-argument error", args, err)
		}
	}
	// Only the flag name counts, not a value that merely mentions it.
	f = base
	f.args = []string{"allow-local", "x--allow-local", "---allow-local"}
	if _, err := validateFlags(f); err != nil {
		t.Errorf("args %q: %v, want only a warning", f.args, err)
	}

	// Without the new flags: start as in v1.3.0, plus a warning.
	f = base
	f.args = []string{"stray"}
	start, err := validateFlags(f)
	if err != nil {
		t.Fatalf("v1.3.0 command line must still start: %v", err)
	}
	if len(start.warnings) != 1 || !strings.Contains(start.warnings[0], "stray") {
		t.Errorf("warnings = %q", start.warnings)
	}
	// No arguments, no warning.
	if start, err := validateFlags(base); err != nil || len(start.warnings) != 0 || start.allowLocal != nil {
		t.Errorf("plain start: %+v, %v", start, err)
	}
}

func TestValidateFlags_AllowLocal(t *testing.T) {
	ok := startFlags{timeoutSec: 30, maxMB: 50, rawOrigins: "https://www.jpkc.com",
		allowLocal: []string{"*.ddev.site"}, allowLocalSet: true}

	start, err := validateFlags(ok)
	if err != nil {
		t.Fatalf("valid flags: %v", err)
	}
	if len(start.allowLocal) != 1 || start.allowLocal[0].String() != "*.ddev.site" {
		t.Errorf("allowLocal = %v", start.allowLocal)
	}

	f := ok
	f.rawOrigins = ""
	if _, err := validateFlags(f); err == nil || err.Error() != "--allow-local requires --origin (otherwise any website could use the proxy to reach your local network)" {
		t.Errorf("without --origin: %v", err)
	}
	f = ok
	f.allowAnyHost = true
	if _, err := validateFlags(f); err == nil || err.Error() != "--allow-local cannot be combined with --allow-any-host" {
		t.Errorf("with --allow-any-host: %v", err)
	}
	f = ok
	f.allowLocal = []string{""}
	if _, err := validateFlags(f); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf(`--allow-local "": %v`, err)
	}
	f = ok
	f.allowLocal = []string{"*.lan"}
	if _, err := validateFlags(f); err == nil {
		t.Error("an invalid entry must be fatal")
	}

	for _, origin := range []string{
		"null", "*", "http://www.example.com", "https://www.example.com/tools/", "https://www.example.com/",
		"https://www.example.com?x", "https://www.example.com#x", "https://user@www.example.com", "https://",
		"https://www.example.com:", "https://www.example.com:99999", "ftp://www.example.com", "www.example.com",
		"http://localhost.example.com", "http://10.0.0.1",
		"https://www.jpkc.com,null", // every entry counts
	} {
		f = ok
		f.rawOrigins = origin
		_, err := validateFlags(f)
		if err == nil {
			t.Errorf("--origin %q must be fatal with --allow-local", origin)
			continue
		}
		if !strings.Contains(err.Error(), "must be an https origin without a path") {
			t.Errorf("--origin %q: %v", origin, err)
		}
	}
	for _, origin := range []string{
		"https://www.jpkc.com", "https://jpkcom-tools.ddev.site:8443", "http://localhost:8080", "http://localhost",
		"http://127.0.0.1:3000", "HTTPS://WWW.JPKC.COM", "https://www.jpkc.com, https://jpkcom-tools.ddev.site",
	} {
		f = ok
		f.rawOrigins = origin
		if _, err := validateFlags(f); err != nil {
			t.Errorf("--origin %q: %v", origin, err)
		}
	}

	// Without --allow-local, --origin stays unchecked (COMPAT-2).
	f = startFlags{timeoutSec: 30, maxMB: 50, rawOrigins: "null,https://x.example/path"}
	if start, err := validateFlags(f); err != nil || len(start.origins) != 2 {
		t.Errorf("v1.3.0 origins: %+v, %v", start, err)
	}
	// The v1.3.0 checks are unchanged.
	for _, bad := range []startFlags{
		{port: -1, timeoutSec: 30}, {port: 65536, timeoutSec: 30}, {timeoutSec: 0}, {timeoutSec: 30, maxMB: -1},
		{timeoutSec: 30, maxMB: 1024*1024 + 1},
	} {
		if _, err := validateFlags(bad); err == nil {
			t.Errorf("%+v must be fatal", bad)
		}
	}
}

func TestAllowLocal_Match(t *testing.T) {
	cases := []struct {
		entries    string
		host, port string
		want       bool
	}{
		{"*.ddev.site", "x.ddev.site", "443", true},
		{"*.ddev.site", "a.b.ddev.site", "80", true},
		{"*.ddev.site", "X.DDEV.SITE.", "443", true},
		{"*.ddev.site", "ddev.site", "443", false},
		{"*.ddev.site", "xddev.site", "443", false},
		{"*.ddev.site", "x.ddev.site.evil.example", "443", false},
		{"*.ddev.site", "x.ddev.site", "8443", false},
		{"10.0.5.0/24:8080", "10.0.5.7", "8080", true},
		{"10.0.5.0/24:8080", "10.0.5.7", "80", false},
		{"10.0.5.0/24:8080", "nas.example", "8080", false},
		{"10.0.5.20", "10.0.5.20", "443", true},
		{"10.0.5.20", "10.0.5.21", "443", false},
		{"localhost:8888", "localhost", "8888", true},
		{"localhost:8888", "127.0.0.1", "8888", false}, // a literal is not the name
		{"localhost", "localhost", "443", true},
		{"localhost", "a.localhost", "443", false},
		{"*.localhost", "a.localhost", "80", true},
		{"[fd00::/64]:8443", "fd00::5", "8443", true},
		{"[fd00::/64]:8443", "fd00:0:0:1::5", "8443", false},
		{"wp.test", "wp.test", "8080", false}, // no port: 80 and 443 only
		// Request names must pass the same syntax check as entries.
		{"*.ddev.site", "a..ddev.site", "443", false},
		{"*.ddev.site", "-a.ddev.site", "443", false},
		{"*.ddev.site", "a_b.ddev.site", "443", false},
		{"wp.test", "wp..test", "443", false},
	}
	for _, tc := range cases {
		cfg, _ := localCfg(t, tc.entries, nil, nil)
		if got := cfg.allowLocalMatch(tc.host, tc.port); got != tc.want {
			t.Errorf("%s: allowLocalMatch(%s, %s) = %v, want %v", tc.entries, tc.host, tc.port, got, tc.want)
		}
	}

	// localVerdict: the address decides together with the name.
	verdicts := []struct {
		entries    string
		host, port string
		ip         string
		want       verdict
	}{
		{"*.ddev.site", "x.ddev.site", "443", "127.0.0.1", verdictAllowed},
		{"*.ddev.site", "x.ddev.site", "443", "::1", verdictAllowed},
		{"*.ddev.site", "x.ddev.site", "443", "192.168.1.66", verdictNotAllowlisted},
		{"*.ddev.site", "x.ddev.site", "443", "93.184.215.14", verdictPublic},
		{"*.ddev.site", "evil.test", "443", "127.0.0.1", verdictNotAllowlisted},
		{"*.ddev.site", "a..ddev.site", "443", "127.0.0.1", verdictNotAllowlisted},
		{"*.ddev.site", "x.ddev.site", "443", "169.254.169.254", verdictAlwaysBlocked},
		{"10.0.5.0/24:8080", "10.0.5.7", "8080", "10.0.5.7", verdictAllowed},
		{"10.0.5.0/24:8080", "10.0.5.7", "80", "10.0.5.7", verdictNotAllowlisted},
		{"10.0.5.0/24:8080", "nas.example", "8080", "10.0.5.7", verdictNotAllowlisted},
		{"localhost:8888", "127.0.0.1", "8888", "127.0.0.1", verdictNotAllowlisted},
		{"localhost:8888", "localhost", "8888", "127.0.0.1", verdictAllowed},
	}
	for _, tc := range verdicts {
		cfg, _ := localCfg(t, tc.entries, nil, nil)
		if got := cfg.localVerdict(tc.host, tc.port, net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("%s: localVerdict(%s, %s, %s) = %v, want %v", tc.entries, tc.host, tc.port, tc.ip, got, tc.want)
		}
	}

	// Off: nothing matches.
	cfg, _ := localCfg(t, "", nil, nil)
	if cfg.allowLocalMatchURL(&url.URL{Scheme: "http", Host: "localhost"}) {
		t.Error("without --allow-local nothing is a local target")
	}
}

func TestAllowLocal_NameLoopbackOnly(t *testing.T) {
	// A spoofed DNS answer for a listed name points into the LAN.
	cfg, _ := localCfg(t, "*.ddev.site", map[string]string{"x.ddev.site": "192.168.1.66"}, nil)
	rr := doProxy(t, cfg, http.MethodGet, "http://x.ddev.site/", "", nil)
	// The pre-check leaves a listed name to the dialer, which refuses it.
	wantBlocked(t, rr, http.StatusBadGateway, reasonNotAllowlisted)

	// The same through a real server: the name resolves to loopback and a
	// LAN address; only loopback is ever dialled.
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	cfg, _ = localCfg(t, "wp.test:"+port, map[string]string{"wp.test": "192.168.1.66,127.0.0.1"}, nil)
	if rr := doProxy(t, cfg, http.MethodGet, "http://wp.test:"+port+"/", "", nil); rr.Code != http.StatusOK || hits.Load() != 1 {
		t.Errorf("status %d, hits %d — %s", rr.Code, hits.Load(), rr.Body.String())
	}

	// An IP/CIDR entry opens its range to the name entries, and only that.
	cfg, _ = localCfg(t, "wp.intranet.example,10.0.5.0/24", nil, nil)
	if v := cfg.localVerdict("wp.intranet.example", "443", net.ParseIP("10.0.5.7")); v != verdictAllowed {
		t.Errorf("name → 10.0.5.7: %v, want allowed", v)
	}
	if v := cfg.localVerdict("wp.intranet.example", "443", net.ParseIP("10.0.6.7")); v != verdictNotAllowlisted {
		t.Errorf("name → 10.0.6.7: %v, want not allowlisted", v)
	}
	// The CIDR entry's port plays no role for the name; the name's does.
	cfg, _ = localCfg(t, "wp.intranet.example,10.0.5.0/24:8080", nil, nil)
	if v := cfg.localVerdict("wp.intranet.example", "443", net.ParseIP("10.0.5.7")); v != verdictAllowed {
		t.Errorf("name:443 → 10.0.5.7 with a :8080 range: %v, want allowed", v)
	}

	// localhost maps to both loopback addresses without DNS.
	cfg, lookups := localCfg(t, "localhost", nil, nil)
	ips, err := cfg.resolveHost(context.Background(), "localhost")
	if err != nil || len(ips) != 2 || lookups.Load() != 0 {
		t.Fatalf("resolveHost(localhost) = %v, %v, %d lookups", ips, err, lookups.Load())
	}
	for _, ip := range ips {
		if v := cfg.localVerdict("localhost", "443", ip); v != verdictAllowed {
			t.Errorf("localhost → %s: %v, want allowed", ip, v)
		}
	}
}

func TestAllowLocal_NameReachesLoopback(t *testing.T) {
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	hosts := map[string]string{"wp.test": "127.0.0.1"}
	target := "http://wp.test:" + port + "/"

	cfg, _ := localCfg(t, "wp.test:"+port, hosts, nil)
	rr := doProxy(t, cfg, http.MethodGet, target, "", nil)
	if rr.Code != http.StatusOK || rr.Body.String() != "local ok" {
		t.Fatalf("status %d — %s", rr.Code, rr.Body.String())
	}
	if ip := rr.Header().Get("X-Upstream-IP"); ip != "127.0.0.1" {
		t.Errorf("X-Upstream-IP = %q", ip)
	}

	// Flag off: the v1.3.0 block, now with a reason.
	cfg, _ = localCfg(t, "", hosts, nil)
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, target, "", nil), http.StatusForbidden, reasonPrivate)

	// Flag on with another entry.
	cfg, _ = localCfg(t, "other.test:"+port, hosts, nil)
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, target, "", nil), http.StatusForbidden, reasonNotAllowlisted)

	// Right name, wrong port.
	cfg, _ = localCfg(t, "wp.test", hosts, nil)
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, target, "", nil), http.StatusForbidden, reasonNotAllowlisted)

	if hits.Load() != 1 {
		t.Errorf("server saw %d requests, want 1", hits.Load())
	}
}

func TestAllowLocal_ForeignNameToLoopbackBlocked(t *testing.T) {
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	cfg, _ := localCfg(t, "*.ddev.site", map[string]string{"evil.test": "127.0.0.1"}, nil)
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, "http://evil.test:"+port+"/", "", nil),
		http.StatusForbidden, reasonNotAllowlisted)

	// Past a pre-check that waved it through, the dialer says the same.
	cfg.ssrfCheck = func(string) bool { return false }
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, "http://evil.test:"+port+"/", "", nil),
		http.StatusBadGateway, reasonNotAllowlisted)
	if hits.Load() != 0 {
		t.Errorf("server saw %d requests, want 0", hits.Load())
	}
}

func TestAllowLocal_RebindingBlocked(t *testing.T) {
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	cfg, _ := localCfg(t, "*.ddev.site", nil, nil)
	var calls atomic.Int32
	cfg.lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		// First answer public (the pre-check), every later one loopback.
		if calls.Add(1) == 1 {
			return []net.IPAddr{{IP: net.ParseIP("100.63.255.1")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	rr := doProxy(t, cfg, http.MethodGet, "http://rebind.test:"+port+"/", "", nil)
	wantBlocked(t, rr, http.StatusBadGateway, reasonNotAllowlisted)
	if hits.Load() != 0 {
		t.Errorf("server saw %d requests, want 0", hits.Load())
	}
	if calls.Load() != 2 {
		t.Errorf("lookups = %d, want 2 (pre-check and dialer)", calls.Load())
	}

	// A listed name is never pre-resolved: the dialer's own answer is the
	// only one that counts, and it may only be loopback.
	calls.Store(0)
	cfg.lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		if calls.Add(1) == 1 {
			return []net.IPAddr{{IP: net.ParseIP("192.168.1.66")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, "http://x.ddev.site/", "", nil), http.StatusBadGateway, reasonNotAllowlisted)
	if calls.Load() != 1 {
		t.Errorf("lookups = %d, want 1 (dialer only)", calls.Load())
	}
}

func TestAllowLocal_TimingPreserved(t *testing.T) {
	srv, _ := countingServer(t, nil)
	port := serverPort(t, srv)
	cfg, _ := localCfg(t, "wp.test:"+port, map[string]string{"wp.test": "127.0.0.1"}, nil)
	slow := cfg.lookupIP
	cfg.lookupIP = func(ctx context.Context, host string) ([]net.IPAddr, error) {
		time.Sleep(5 * time.Millisecond) // a DNS phase the header can show
		return slow(ctx, host)
	}

	rr := doProxy(t, cfg, http.MethodGet, "http://wp.test:"+port+"/", "", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d — %s", rr.Code, rr.Body.String())
	}
	if ip := rr.Header().Get("X-Upstream-IP"); ip != "127.0.0.1" {
		t.Errorf("X-Upstream-IP = %q", ip)
	}
	timing := rr.Header().Get("X-Upstream-Timing")
	m := regexp.MustCompile(`^dns=(\d+);tcp=(\d+);ssl=0;ttfb=\d+;total=\d+$`).FindStringSubmatch(timing)
	if m == nil {
		t.Fatalf("X-Upstream-Timing = %q", timing)
	}
	if dns, _ := strconv.Atoi(m[1]); dns < 4 {
		t.Errorf("dns phase %dms, want the lookup's ≥ 5ms — %q", dns, timing)
	}

	// Both phases reach the trace through the guard.
	var dnsStart, dnsDone, connectStart, connectDone atomic.Int32
	trace := &httptrace.ClientTrace{
		DNSStart:     func(httptrace.DNSStartInfo) { dnsStart.Add(1) },
		DNSDone:      func(httptrace.DNSDoneInfo) { dnsDone.Add(1) },
		ConnectStart: func(string, string) { connectStart.Add(1) },
		ConnectDone:  func(string, string, error) { connectDone.Add(1) },
	}
	ctx := httptrace.WithClientTrace(withLocalStart(context.Background(), true), trace)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://wp.test:"+port+"/", nil)
	resp, err := newUpstreamClient(cfg).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if dnsStart.Load() != 1 || dnsDone.Load() != 1 || connectStart.Load() != 1 || connectDone.Load() != 1 {
		t.Errorf("trace: dns %d/%d, connect %d/%d", dnsStart.Load(), dnsDone.Load(), connectStart.Load(), connectDone.Load())
	}
}

func TestAllowLocal_AlwaysBlocked(t *testing.T) {
	cases := []struct {
		name, entries, target string
		ownPort               int
		status                int
	}{
		{"metadata v4", "10.0.5.0/24", "http://169.254.169.254/", 0, http.StatusForbidden},
		{"own port", "localhost", "http://localhost:%d/ping", 1, http.StatusForbidden},
		{"alibaba metadata", "100.100.0.0/16", "http://100.100.100.200/", 0, http.StatusForbidden},
		{"aws metadata v6", "[fd00:ec2::/48]", "http://[fd00:ec2::254]/", 0, http.StatusForbidden},
		{"flag off, metadata", "", "http://169.254.169.254/latest/meta-data/", 0, http.StatusForbidden},
		{"flag off, own port", "", "http://127.0.0.1:%d/ping", 1, http.StatusForbidden},
		{"multicast", "10.0.5.0/24", "http://224.0.0.1/", 0, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := localCfg(t, tc.entries, nil, nil)
			target := tc.target
			if tc.ownPort != 0 {
				cfg.port = 18765
				target = fmt.Sprintf(tc.target, cfg.port)
			}
			wantBlocked(t, doProxy(t, cfg, http.MethodGet, target, "", nil), tc.status, reasonAlwaysBlocked)
		})
	}

	// An entry naming the own port: only possible with --port 0 at parse
	// time. The listed name skips the pre-check; the dialer refuses.
	cfg, _ := localCfg(t, "localhost:18765", nil, nil)
	cfg.port = 18765
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, "http://localhost:18765/ping", "", nil),
		http.StatusBadGateway, reasonAlwaysBlocked)
	// An address entry naming the own port: pre-check on the literal.
	cfg, _ = localCfg(t, "127.0.0.1:18765", nil, nil)
	cfg.port = 18765
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, "http://127.0.0.1:18765/ping", "", nil),
		http.StatusForbidden, reasonAlwaysBlocked)

	// "Flag off, 10.0.0.1" stays the v1.3.0 case.
	cfg, _ = localCfg(t, "", nil, nil)
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, "http://10.0.0.1/", "", nil), http.StatusForbidden, reasonPrivate)
}

func TestAllowLocal_PrecheckSkipsDNSForListedName(t *testing.T) {
	cfg, lookups := localCfg(t, "*.ddev.site", map[string]string{"x.ddev.site": "127.0.0.1", "pub.example": "93.184.215.14"}, nil)
	u, _ := url.Parse("https://x.ddev.site/wp-json/")
	if blocked, reason := cfg.precheck(context.Background(), u, true); blocked || lookups.Load() != 0 {
		t.Errorf("listed name, local start: blocked=%v reason=%q lookups=%d", blocked, reason, lookups.Load())
	}
	// Not a local start (a hop of a public request): resolved and judged.
	if blocked, reason := cfg.precheck(context.Background(), u, false); !blocked || reason != reasonNotAllowlisted || lookups.Load() != 1 {
		t.Errorf("listed name, public start: blocked=%v reason=%q lookups=%d", blocked, reason, lookups.Load())
	}
	// A name off the list is resolved even on a local start.
	p, _ := url.Parse("https://pub.example/")
	if blocked, _ := cfg.precheck(context.Background(), p, true); blocked || lookups.Load() != 2 {
		t.Errorf("public name: blocked=%v lookups=%d", blocked, lookups.Load())
	}
	// A lookup failure fails open, as in v1.3.0.
	n, _ := url.Parse("https://nx.example/")
	if blocked, _ := cfg.precheck(context.Background(), n, false); blocked {
		t.Error("an unresolvable name must fail open in the pre-check")
	}
}

func TestPrecheck_ReasonMatchesDialer(t *testing.T) {
	cases := []struct {
		name, entries string
		hosts         map[string]string
		target        string
		ownPort       int
		want          string
	}{
		{"private literal, flag off", "", nil, "http://10.0.0.1/", 0, reasonPrivate},
		{"private name, flag off", "", map[string]string{"nas.example": "10.0.0.1"}, "http://nas.example/", 0, reasonPrivate},
		{"loopback name, flag off", "", map[string]string{"wp.test": "127.0.0.1"}, "http://wp.test:8080/", 0, reasonPrivate},
		{"metadata, flag off", "", nil, "http://169.254.169.254/", 0, reasonAlwaysBlocked},
		{"own port, flag off", "", nil, "http://127.0.0.1:18765/", 18765, reasonAlwaysBlocked},
		{"unlisted name", "*.ddev.site", map[string]string{"evil.test": "127.0.0.1"}, "http://evil.test/", 0, reasonNotAllowlisted},
		{"unlisted literal", "10.0.5.0/24", nil, "http://10.0.6.1/", 0, reasonNotAllowlisted},
		{"listed range, wrong port", "10.0.5.0/24", nil, "http://10.0.5.1:8080/", 0, reasonNotAllowlisted},
		{"metadata in a listed range", "100.100.0.0/16", nil, "http://100.100.100.200/", 0, reasonAlwaysBlocked},
		{"metadata, flag on", "10.0.5.0/24", nil, "http://169.254.169.254/", 0, reasonAlwaysBlocked},
		{"own port, flag on", "*.ddev.site", nil, "http://localhost:18765/", 18765, reasonAlwaysBlocked},
		{"mixed answers", "*.ddev.site", map[string]string{"mix.test": "127.0.0.1,169.254.169.254"}, "http://mix.test/", 0, reasonAlwaysBlocked},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, _ := localCfg(t, tc.entries, tc.hosts, nil)
			if tc.ownPort != 0 {
				cfg.port = tc.ownPort
			}
			u, _ := url.Parse(tc.target)
			localStart := cfg.allowLocalMatchURL(u)
			blocked, reason := cfg.precheck(context.Background(), u, localStart)
			if !blocked || reason != tc.want {
				t.Errorf("pre-check: blocked=%v reason=%q, want %q", blocked, reason, tc.want)
			}

			// The dialer, reached directly (as after a fail-open pre-check).
			ctx, cancel := context.WithTimeout(withLocalStart(context.Background(), localStart), 5*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tc.target, nil)
			resp, err := newUpstreamClient(cfg).Do(req)
			if err == nil {
				resp.Body.Close()
				t.Fatal("the dialer let the request through")
			}
			pe := upstreamFailure(ctx, err)
			if pe.Error != "blocked_target" || pe.Reason != tc.want {
				t.Errorf("dialer: %+v (err %v), want reason %q", pe, err, tc.want)
			}
		})
	}
}

func TestAllowLocal_TLSProbeUsesAllowance(t *testing.T) {
	pki := newTestPKI(t)
	der, key := pki.leaf(t, certOpts{cn: "wp.test", dns: []string{"wp.test"}})
	srv := tlsServerWith(t, [][]byte{der, pki.interDER}, key, nil, nil)
	port := serverPort(t, srv)
	target := "https://wp.test:" + port + "/"

	// The test CA is not trusted: tls_error. The probe must reach the
	// local target through the same allowance as the request.
	cfg, _ := localCfg(t, "wp.test:"+port, map[string]string{"wp.test": "127.0.0.1"}, x509.NewCertPool())
	resp := decodeInspect(t, doInspect(t, cfg, target, "&diag=1"))
	if resp.Error == nil || resp.Error.Error != "tls_error" {
		t.Fatalf("error = %+v", resp.Error)
	}
	if resp.SSL == nil || resp.SSL.CertSource != "probe" || resp.SSL.ProbeError != "" {
		t.Fatalf("ssl = %+v, want certSource probe", resp.SSL)
	}
	if len(resp.SSL.Chain) != 2 {
		t.Errorf("chain has %d certificates, want 2 (as served)", len(resp.SSL.Chain))
	}

	page := decodePage(t, doPage(t, cfg, target, "&diag=1"))
	if page.Error == nil || page.Error.Error != "tls_error" || page.SSL == nil || page.SSL.CertSource != "probe" {
		t.Errorf("/page: error=%+v ssl=%+v", page.Error, page.SSL)
	}

	// Without the allowance on the request (missing context value), the
	// probe is refused like the request and falls back to the chain from
	// the verification error.
	ip := "127.0.0.1"
	state, err := probeTLS(context.Background(), cfg, "wp.test", port, ip)
	if err == nil || !errors.Is(err, errBlockedTarget) || state != nil {
		t.Errorf("probe without local start: state=%v err=%v", state, err)
	}
	state, err = probeTLS(withLocalStart(context.Background(), true), cfg, "wp.test", port, ip)
	if err != nil || state == nil || len(state.PeerCertificates) != 2 {
		t.Errorf("probe with local start: err=%v", err)
	}
	// A name off the list gets no allowance even on a local start.
	if _, err := probeTLS(withLocalStart(context.Background(), true), cfg, "evil.test", port, ip); !errors.Is(err, errBlockedTarget) {
		t.Errorf("probe for an unlisted name: %v", err)
	}
}

// redirectTo answers every request with a 302 to loc.
func redirectTo(loc string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusFound)
	}
}

func TestAllowLocal_RedirectIntoLocal(t *testing.T) {
	local, localHits := countingServer(t, nil)
	lport := serverPort(t, local)
	pub, _ := countingServer(t, redirectTo("http://wp.test:"+lport+"/wp-json/"))
	pport := serverPort(t, pub)

	cfg, _ := localCfg(t, "wp.test:"+lport, map[string]string{"pub.test": "127.0.0.1", "wp.test": "127.0.0.1"}, nil)
	// pub.test plays a public site: the only test that opens the base
	// dialer (and the pre-check) to loopback. The exact-address dialer for
	// listed targets is unaffected.
	cfg.ssrfCheck = func(string) bool { return false }
	cfg.dialControl = allowAllDial
	start := "http://pub.test:" + pport + "/"

	rr := doProxy(t, cfg, http.MethodGet, start, "&follow=1", nil)
	wantBlocked(t, rr, http.StatusForbidden, reasonRedirectIntoLocal)
	if pe := decodeProxyError(t, rr); pe.Type != "Blocked target" {
		t.Errorf("type = %q", pe.Type)
	}

	page := decodePage(t, doPage(t, cfg, start, ""))
	if page.Error == nil || page.Error.Error != "blocked_target" || page.Error.Reason != reasonRedirectIntoLocal {
		t.Fatalf("/page error = %+v", page.Error)
	}
	last := page.RedirectChain[len(page.RedirectChain)-1]
	if last.ErrorCategory != "blocked_target" || last.ErrorReason != reasonRedirectIntoLocal {
		t.Errorf("/page last hop = %+v", last)
	}

	// Also a listed IP literal.
	cfg.allowLocal, _ = parseAllowLocal([]string{"127.0.0.1:" + lport}, 0)
	pub2, _ := countingServer(t, redirectTo("http://127.0.0.1:"+lport+"/"))
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, "http://pub.test:"+serverPort(t, pub2)+"/", "&follow=1", nil),
		http.StatusForbidden, reasonRedirectIntoLocal)

	if localHits.Load() != 0 {
		t.Errorf("local target saw %d requests, want 0", localHits.Load())
	}
}

func TestAllowLocal_LocalToPublicAllowed(t *testing.T) {
	pub, pubHits := countingServer(t, nil)
	pport := serverPort(t, pub)
	local, _ := countingServer(t, redirectTo("http://pub.test:"+pport+"/final"))
	lport := serverPort(t, local)

	cfg, _ := localCfg(t, "wp.test:"+lport, map[string]string{"pub.test": "127.0.0.1", "wp.test": "127.0.0.1"}, nil)
	// pub.test plays a public site (see TestAllowLocal_RedirectIntoLocal).
	cfg.ssrfCheck = func(string) bool { return false }
	cfg.dialControl = allowAllDial
	start := "http://wp.test:" + lport + "/"

	rr := doProxy(t, cfg, http.MethodGet, start, "&follow=1", nil)
	if rr.Code != http.StatusOK || rr.Header().Get("X-Upstream-Final-URL") != "http://pub.test:"+pport+"/final" {
		t.Fatalf("status %d final %q — %s", rr.Code, rr.Header().Get("X-Upstream-Final-URL"), rr.Body.String())
	}
	page := decodePage(t, doPage(t, cfg, start, ""))
	if page.Error != nil || page.FinalURL != "http://pub.test:"+pport+"/final" {
		t.Errorf("/page: error=%+v final=%q", page.Error, page.FinalURL)
	}
	if pubHits.Load() < 2 {
		t.Errorf("public target saw %d requests", pubHits.Load())
	}
}

func TestAllowLocal_LocalToLocalAllowed(t *testing.T) {
	second, hits := countingServer(t, nil)
	sport := serverPort(t, second)
	first, _ := countingServer(t, redirectTo("http://api.wp.test:"+sport+"/wp-json/"))
	fport := serverPort(t, first)

	// The real guard: no ssrfCheck, no dialControl.
	cfg, _ := localCfg(t, "wp.test:"+fport+",*.wp.test:"+sport,
		map[string]string{"wp.test": "127.0.0.1", "api.wp.test": "127.0.0.1"}, nil)
	start := "http://wp.test:" + fport + "/"

	rr := doProxy(t, cfg, http.MethodGet, start, "&follow=1", nil)
	if rr.Code != http.StatusOK || rr.Body.String() != "local ok" || rr.Header().Get("X-Upstream-Redirects") != "1" {
		t.Fatalf("status %d — %s", rr.Code, rr.Body.String())
	}
	page := decodePage(t, doPage(t, cfg, start, ""))
	if page.Error != nil || page.FinalURL != "http://api.wp.test:"+sport+"/wp-json/" || page.HTML != "local ok" {
		t.Errorf("/page: error=%+v final=%q", page.Error, page.FinalURL)
	}

	// A local start redirecting to a local target that is not listed.
	before := hits.Load()
	first2, _ := countingServer(t, redirectTo("http://127.0.0.1:"+sport+"/"))
	cfg.allowLocal, _ = parseAllowLocal([]string{"wp.test:" + serverPort(t, first2)}, 0)
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, "http://wp.test:"+serverPort(t, first2)+"/", "&follow=1", nil),
		http.StatusForbidden, reasonNotAllowlisted)
	if before < 2 || hits.Load() != before {
		t.Errorf("second target saw %d requests, then %d; the unlisted hop must add none", before, hits.Load())
	}
}

func TestAllowLocal_AllEndpoints(t *testing.T) {
	pki := newTestPKI(t)
	der, key := pki.leaf(t, certOpts{cn: "wp.test", dns: []string{"wp.test"}})
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html>local</html>"))
	})
	mux.HandleFunc("/old", redirectTo("/"))
	srv := tlsServerWith(t, [][]byte{der, pki.interDER}, key, nil, mux)
	port := serverPort(t, srv)
	base := "https://wp.test:" + port

	cfg, _ := localCfg(t, "wp.test:"+port, map[string]string{"wp.test": "127.0.0.1"}, pki.pool)

	for _, extra := range []string{"", "&follow=1"} {
		rr := doProxy(t, cfg, http.MethodGet, base+"/old", extra, nil)
		want := http.StatusFound
		if extra != "" {
			want = http.StatusOK
		}
		if rr.Code != want {
			t.Errorf("/proxy%s: status %d — %s", extra, rr.Code, rr.Body.String())
		}
	}
	if rr := doProxy(t, cfg, http.MethodHead, base+"/", "", nil); rr.Code != http.StatusOK {
		t.Errorf("/proxy HEAD: %d", rr.Code)
	}
	for _, extra := range []string{"", "&get=1", "&body=1", "&diag=1"} {
		rr := doInspect(t, cfg, base+"/", extra)
		if rr.Code != http.StatusOK {
			t.Errorf("/inspect%s: %d — %s", extra, rr.Code, rr.Body.String())
			continue
		}
		resp := decodeInspect(t, rr)
		if resp.Status != http.StatusOK || resp.Error != nil || resp.SSL == nil || !resp.SSL.Verified || resp.IP != "127.0.0.1" {
			t.Errorf("/inspect%s: status=%d error=%+v ip=%q", extra, resp.Status, resp.Error, resp.IP)
		}
		if extra == "&body=1" && resp.Body != "<html>local</html>" {
			t.Errorf("/inspect body = %q", resp.Body)
		}
	}
	for _, extra := range []string{"", "&diag=1"} {
		page := decodePage(t, doPage(t, cfg, base+"/old", extra))
		if page.Error != nil || page.HTML != "<html>local</html>" || len(page.RedirectChain) != 2 || page.SSL == nil {
			t.Errorf("/page%s: error=%+v chain=%d body=%q", extra, page.Error, len(page.RedirectChain), page.HTML)
		}
	}
}

func TestAllowLocal_MissingContextValueFailsClosed(t *testing.T) {
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	cfg, _ := localCfg(t, "wp.test:"+port, map[string]string{"wp.test": "127.0.0.1"}, nil)
	client := newUpstreamClient(cfg)
	target := "http://wp.test:" + port + "/"

	// A code path that forgot withLocalStart.
	resp, err := client.Get(target)
	if err == nil {
		resp.Body.Close()
		t.Fatal("a request without the local-start value reached the local target")
	}
	if pe := upstreamFailure(context.Background(), err); pe.Error != "blocked_target" || pe.Reason != reasonNotAllowlisted {
		t.Errorf("error = %+v", pe)
	}
	// An explicit false is the same.
	req, _ := http.NewRequestWithContext(withLocalStart(context.Background(), false), http.MethodGet, target, nil)
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("localStart=false reached the local target")
	}
	if hits.Load() != 0 {
		t.Fatalf("server saw %d requests", hits.Load())
	}
	// With the value: through.
	req, _ = http.NewRequestWithContext(withLocalStart(context.Background(), true), http.MethodGet, target, nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if localStartFrom(context.Background()) {
		t.Error("a missing value must read as false")
	}
}

func TestAllowLocal_NoConnectionReuse(t *testing.T) {
	cfg, _ := localCfg(t, "wp.test", nil, nil)
	// With --allow-local the two request classes have separate transports
	// (HTTP/2 shares connections between concurrent requests regardless of
	// DisableKeepAlives; see TestAttack_H2ConnectionSharing), and each keeps
	// HTTP/1.1 connections single-use.
	if _, ok := newUpstreamClient(cfg).Transport.(*localSplitTransport); !ok {
		t.Fatal("with --allow-local the upstream client must split its transport by localStart")
	}
	for _, transport := range upstreamTransports(t, newUpstreamClient(cfg)) {
		if !transport.DisableKeepAlives {
			t.Fatal("DisableKeepAlives must stay true")
		}
	}
	// Without the list: the single v1.3.0 transport.
	if _, ok := newUpstreamClient(&config{}).Transport.(*http.Transport); !ok {
		t.Error("without --allow-local the upstream client must keep the single v1.3.0 transport")
	}

	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.Start()
	t.Cleanup(srv.Close)
	port := serverPort(t, srv)
	cfg, _ = localCfg(t, "wp.test:"+port, map[string]string{"wp.test": "127.0.0.1"}, nil)
	client := newUpstreamClient(cfg)
	target := "http://wp.test:" + port + "/"

	req, _ := http.NewRequestWithContext(withLocalStart(context.Background(), true), http.MethodGet, target, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	req, _ = http.NewRequestWithContext(withLocalStart(context.Background(), false), http.MethodGet, target, nil)
	if resp, err := client.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("the second request reused the first one's permission")
	} else if !errors.Is(err, errBlockedTarget) {
		t.Errorf("second request: %v", err)
	}
	if conns.Load() != 1 {
		t.Errorf("server saw %d connections, want 1 (the second dial is refused)", conns.Load())
	}
}

func TestBlockedTarget_Reason(t *testing.T) {
	// /proxy, /inspect, /page: pre-check 403 with top-level reason.
	cfg, _ := localCfg(t, "*.ddev.site", map[string]string{"evil.test": "127.0.0.1", "x.ddev.site": "192.168.1.66"}, nil)
	for name, do := range map[string]func(string, string) *httptest.ResponseRecorder{
		"proxy":   func(u, e string) *httptest.ResponseRecorder { return doProxy(t, cfg, http.MethodGet, u, e, nil) },
		"inspect": func(u, e string) *httptest.ResponseRecorder { return doInspect(t, cfg, u, e) },
		"page":    func(u, e string) *httptest.ResponseRecorder { return doPage(t, cfg, u, e) },
	} {
		t.Run(name, func(t *testing.T) {
			wantBlocked(t, do("http://evil.test/", ""), http.StatusForbidden, reasonNotAllowlisted)
			wantBlocked(t, do("http://169.254.169.254/", ""), http.StatusForbidden, reasonAlwaysBlocked)
		})
	}

	// Dialer: /proxy 502 top-level, /inspect?diag=1 and /page inline.
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, "http://x.ddev.site/", "", nil), http.StatusBadGateway, reasonNotAllowlisted)
	wantBlocked(t, doInspect(t, cfg, "http://x.ddev.site/", ""), http.StatusBadGateway, reasonNotAllowlisted)
	resp := decodeInspect(t, doInspect(t, cfg, "http://x.ddev.site/", "&diag=1"))
	if resp.Error == nil || resp.Error.Error != "blocked_target" || resp.Error.Reason != reasonNotAllowlisted || resp.Error.Status != 502 {
		t.Errorf("/inspect?diag=1 error = %+v", resp.Error)
	}
	page := decodePage(t, doPage(t, cfg, "http://x.ddev.site/", ""))
	if page.Error == nil || page.Error.Reason != reasonNotAllowlisted || len(page.RedirectChain) != 1 ||
		page.RedirectChain[0].ErrorReason != reasonNotAllowlisted || page.RedirectChain[0].ErrorCategory != "blocked_target" {
		t.Errorf("/page error = %+v chain = %+v", page.Error, page.RedirectChain)
	}

	// /page: a redirect hop the pre-check refuses (reason in error and hop),
	// and a non-http scheme.
	hop, _ := countingServer(t, redirectTo("http://169.254.169.254/"))
	js, _ := countingServer(t, redirectTo("javascript:alert(1)"))
	hcfg, _ := localCfg(t, "", map[string]string{"hop.test": "127.0.0.1"}, nil)
	hcfg.dialControl = allowAllDial
	// hop.test plays a public start; every literal still goes through the
	// real pre-check.
	hcfg.ssrfCheck = nil
	hcfg.lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	hopStart := "http://hop.test:" + serverPort(t, hop) + "/"
	// The start resolves to loopback and would be refused itself; skip the
	// start's pre-check by asking the tracer directly.
	ctx := withLocalStart(context.Background(), false)
	req := httptest.NewRequest(http.MethodGet, "/page", nil)
	hops, _, fail := traceRedirectChain(ctx, newUpstreamClient(hcfg), hopStart, req, 20, hcfg)
	if fail == nil || fail.pe.Error != "blocked_target" || fail.pe.Reason != reasonAlwaysBlocked {
		t.Fatalf("/page blocked hop: %+v", fail)
	}
	if last := hops[len(hops)-1]; last.ErrorReason != reasonAlwaysBlocked || last.ErrorCategory != "blocked_target" {
		t.Errorf("/page blocked hop: %+v", last)
	}

	scfg := testCfg(t, nil)
	page = decodePage(t, doPage(t, scfg, js.URL+"/", ""))
	last := page.RedirectChain[len(page.RedirectChain)-1]
	if page.Error == nil || page.Error.Reason != reasonUnsupportedScheme || last.ErrorReason != reasonUnsupportedScheme {
		t.Errorf("/page javascript: error=%+v hop=%+v", page.Error, last)
	}

	// /proxy?follow=1 hop refused by the pre-check: 403 with type and reason.
	fcfg, _ := localCfg(t, "", nil, nil)
	fcfg.dialControl = allowAllDial
	fcfg.lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	fcfg.ssrfCheck = func(h string) bool { return h != "hop.test" }
	rr := doProxy(t, fcfg, http.MethodGet, "http://hop.test:"+serverPort(t, hop)+"/", "&follow=1", nil)
	wantBlocked(t, rr, http.StatusForbidden, reasonPrivate)

	// Flag off: always_blocked and private, no not_allowlisted.
	off, _ := localCfg(t, "", nil, nil)
	wantBlocked(t, doProxy(t, off, http.MethodGet, "http://169.254.169.254/", "", nil), http.StatusForbidden, reasonAlwaysBlocked)
	wantBlocked(t, doProxy(t, off, http.MethodGet, "http://10.0.0.1/", "", nil), http.StatusForbidden, reasonPrivate)
}

func TestSafeDialControl_ReasonAndText(t *testing.T) {
	err := safeDialControl("tcp", "127.0.0.1:8080", nil)
	var be *blockedError
	if !errors.As(err, &be) || be.reason != reasonPrivate || err.Error() != "target address is blocked: 127.0.0.1" {
		t.Errorf("loopback: %v (%+v)", err, be)
	}
	err = safeDialControl("tcp", "169.254.169.254:80", nil)
	if !errors.As(err, &be) || be.reason != reasonAlwaysBlocked {
		t.Errorf("metadata: %v", err)
	}
	err = safeDialControl("tcp", "[fd00:ec2::254]:80", nil)
	if !errors.As(err, &be) || be.reason != reasonAlwaysBlocked {
		t.Errorf("AWS IPv6 metadata: %v", err)
	}
	// IPv4-mapped forms are normalised.
	err = safeDialControl("tcp", "[::ffff:169.254.169.254]:80", nil)
	if !errors.As(err, &be) || be.reason != reasonAlwaysBlocked {
		t.Errorf("mapped metadata: %v", err)
	}
	// The exact-address hook opens one ip:port and nothing else.
	ctl := exactAddressControl(net.ParseIP("127.0.0.1"), "8080", safeDialControl)
	if err := ctl("tcp", "127.0.0.1:8080", nil); err != nil {
		t.Errorf("exact address refused: %v", err)
	}
	for _, addr := range []string{"127.0.0.1:8081", "127.0.0.2:8080", "[::1]:8080"} {
		if err := ctl("tcp", addr, nil); !errors.Is(err, errBlockedTarget) {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestBanner_LocalLines(t *testing.T) {
	info := bannerInfo{version: "dev", port: 8765, token: strings.Repeat("a", 48), dnsLabel: "1.1.1.1:53",
		origins: []string{"https://www.jpkc.com"}}

	plain := bannerLines(info)
	for _, l := range plain {
		if strings.Contains(l, "Local") || strings.Contains(l, "WARNING") {
			t.Errorf("banner without new flags has %q", l)
		}
	}
	if len(plain) != 19 {
		t.Errorf("v1.3.0 banner has 19 lines, got %d", len(plain))
	}

	entries, err := parseAllowLocal([]string{"*.ddev.site,localhost:8888,[fd00::/64]:8443"}, 8765)
	if err != nil {
		t.Fatal(err)
	}
	info.allowLocal = entries
	lines := bannerLines(info)
	if len(lines) != len(plain)+2 {
		t.Fatalf("got %d lines, want %d", len(lines), len(plain)+2)
	}
	text := strings.Join(lines, "\n")
	for _, want := range []string{
		"║    Local    :  *.ddev.site, localhost:8888, [fd00::/64]:8443",
		"║    WARNING  :  local network access enabled for the allowed origins",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("banner lacks %q:\n%s", want, text)
		}
	}
	// Right after the Host line.
	for i, l := range lines {
		if strings.Contains(l, "Host     :") && !strings.Contains(lines[i+1], "Local    :") {
			t.Errorf("Local line not after Host: %q", lines[i+1])
		}
	}
	// Every box line has the same width — the new lines are in the width list.
	width := -1
	for _, l := range lines {
		if !strings.HasPrefix(l, "║") && !strings.HasPrefix(l, "╔") && !strings.HasPrefix(l, "╟") && !strings.HasPrefix(l, "╠") && !strings.HasPrefix(l, "╚") {
			continue
		}
		w := utf8.RuneCountInString(l)
		if width == -1 {
			width = w
		} else if w != width {
			t.Errorf("line width %d ≠ %d: %q", w, width, l)
		}
	}

	// A warning for leftover arguments.
	info.allowLocal = nil
	info.warnings = []string{`ignored arguments ["x"]`}
	if text := strings.Join(bannerLines(info), "\n"); !strings.Contains(text, `WARNING  :  ignored arguments ["x"]`) {
		t.Errorf("warning missing:\n%s", text)
	}
}
