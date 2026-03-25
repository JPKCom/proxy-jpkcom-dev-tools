package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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
	if !isPrivateHost("127.0.0.1", nil) {
		t.Error("127.0.0.1 should be detected as private")
	}
}

func TestIsPrivateHost_PrivateRange(t *testing.T) {
	if !isPrivateHost("192.168.1.1", nil) {
		t.Error("192.168.1.1 should be detected as private")
	}
}

func TestIsPrivateHost_Public(t *testing.T) {
	// Use a known public IP (Google DNS).
	if isPrivateHost("8.8.8.8", nil) {
		t.Error("8.8.8.8 should not be detected as private")
	}
}

func TestIsPrivateHost_Unresolvable(t *testing.T) {
	// Unresolvable hosts should NOT be treated as private (let the
	// upstream request fail naturally).
	if isPrivateHost("this-host-does-not-exist.invalid", nil) {
		t.Error("unresolvable host should not be treated as private")
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
// Version variable
// -----------------------------------------------------------------------

func TestVersionDefault(t *testing.T) {
	if Version != "dev" {
		t.Errorf("expected default Version to be 'dev', got %q", Version)
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
	if resp.Headers["Server"] != "TestServer" {
		t.Errorf("expected Server header in response, got %q", resp.Headers["Server"])
	}
	if resp.Headers["X-Custom"] != "inspect-test" {
		t.Errorf("expected X-Custom header in response, got %q", resp.Headers["X-Custom"])
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
	if resp.Headers["Server"] != "TestServer" {
		t.Errorf("expected Server=TestServer in headers, got %q", resp.Headers["Server"])
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
