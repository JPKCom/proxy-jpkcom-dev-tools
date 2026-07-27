package main

import (
	"bytes"
	"compress/flate"
	"compress/zlib"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

	cfg := newTestConfig()
	mux := http.NewServeMux()
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		writeCORSHeaders(w, r, cfg)
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("localproxy ok\n"))
	})
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
	cfg := newTestConfig()
	mux := http.NewServeMux()
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeCORSHeaders(w, r, cfg)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"version": Version,
			"license": License,
			"author":  Author,
			"url":     AuthorURL,
			"repo":    RepoURL,
		})
	})

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
	var resp map[string]string
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
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeCORSHeaders(w, r, cfg)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"version": Version})
	})

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
	if info := extractSSLInfo(nil); info != nil {
		t.Error("expected nil for nil TLS state")
	}
}

func TestExtractSSLInfo_NoCerts(t *testing.T) {
	state := &tls.ConnectionState{}
	if info := extractSSLInfo(state); info != nil {
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
	// Headers the tools rely on and that must survive.
	src.Header.Set("Accept", "text/markdown")
	src.Header.Set("User-Agent", "Mozilla/5.0")
	src.Header.Set("Accept-Language", "de-DE")
	src.Header.Set("X-Requested-With", "XMLHttpRequest")

	dst := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	dst.Header = http.Header{}
	copyRequestHeaders(src, dst)

	for _, h := range []string{"Cookie", "Authorization", "Origin", "Referer", "Sec-Fetch-Mode", "X-Proxy-Token"} {
		if v := dst.Header.Get(h); v != "" {
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

	info := extractSSLInfo(state)
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
