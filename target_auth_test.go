package main

// Tests of the target credentials of v1.4.0: X-Target-Authorization with
// X-Target-Origin on /proxy, and userinfo in the url as implicit credentials
// (AUTH-1 … AUTH-14, LOG-1, LOG-2 of the v1.4.0 requirements, section 7.1).
//
// Everything runs against httptest targets on loopback; names other than
// 127.0.0.1 resolve through cfg.lookupIP, so no test touches the network.

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

const (
	// taBasic is the Basic value of "test" (AUTH-2 acceptance example).
	taBasic = "Basic dGVzdA=="
	// taPlaceholder is "testuser:PLACEHOLDER" as Basic credentials (LOG-1).
	taPlaceholder = "Basic dGVzdHVzZXI6UExBQ0VIT0xERVI="
)

// seenRequest is what a recording target saw of one request.
type seenRequest struct {
	method string
	host   string
	path   string
	query  string
	auth   string
	header http.Header
	body   string
}

// requestLog collects the requests a target saw. Handlers run on the
// server's goroutines, so every access is locked.
type requestLog struct {
	mu   sync.Mutex
	reqs []seenRequest
}

func (l *requestLog) add(r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reqs = append(l.reqs, seenRequest{
		method: r.Method, host: r.Host, path: r.URL.Path, query: r.URL.RawQuery,
		auth: r.Header.Get("Authorization"), header: r.Header.Clone(), body: string(body),
	})
}

func (l *requestLog) all() []seenRequest {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.reqs)
}

func (l *requestLog) count(match func(seenRequest) bool) int {
	n := 0
	for _, s := range l.all() {
		if match == nil || match(s) {
			n++
		}
	}
	return n
}

// recordingTarget starts a test target that records every request and then
// runs h (nil: 200 "ok"). With tlsOn it is an HTTPS server; roots then trusts
// its certificate (127.0.0.1, ::1, example.com, *.example.com).
func recordingTarget(t *testing.T, tlsOn bool, h http.HandlerFunc) (*httptest.Server, *requestLog, *x509.CertPool) {
	t.Helper()
	rl := &requestLog{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rl.add(r)
		if h != nil {
			h(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok")
	})
	var srv *httptest.Server
	if tlsOn {
		srv = httptest.NewTLSServer(handler)
	} else {
		srv = httptest.NewServer(handler)
	}
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	t.Cleanup(srv.Close)
	var roots *x509.CertPool
	if tlsOn {
		roots = x509.NewCertPool()
		roots.AddCert(srv.Certificate())
	}
	return srv, rl, roots
}

// credHeader builds the two credential headers.
func credHeader(value, origin string) http.Header {
	return http.Header{"X-Target-Authorization": {value}, "X-Target-Origin": {origin}}
}

// doEndpointH runs one request through the real handler of endpoint with
// extra headers. hdr keys are used as they are — not canonicalised — so a
// test can send "X_Target_Authorization" or a lower-case map key.
func doEndpointH(t *testing.T, cfg *config, endpoint, method, target, extra string, hdr http.Header, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, endpoint+"?url="+url.QueryEscape(target)+extra, body)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	for k, vs := range hdr {
		req.Header[k] = append(req.Header[k], vs...)
	}
	rr := httptest.NewRecorder()
	client := newUpstreamClient(cfg)
	switch endpoint {
	case "/proxy":
		proxyHandler(cfg, client).ServeHTTP(rr, req)
	case "/inspect":
		inspectHandler(cfg, client).ServeHTTP(rr, req)
	case "/page":
		pageHandler(cfg, client).ServeHTTP(rr, req)
	default:
		t.Fatalf("unknown endpoint %s", endpoint)
	}
	return rr
}

// doProxyH is doProxy with extra request headers (section 7.1).
func doProxyH(t *testing.T, cfg *config, method, target, extra string, hdr http.Header, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	return doEndpointH(t, cfg, "/proxy", method, target, extra, hdr, body)
}

// doInspectH and doPageH are the same for /inspect and /page.
func doInspectH(t *testing.T, cfg *config, target, extra string, hdr http.Header) *httptest.ResponseRecorder {
	t.Helper()
	return doEndpointH(t, cfg, "/inspect", http.MethodGet, target, extra, hdr, nil)
}

func doPageH(t *testing.T, cfg *config, target, extra string, hdr http.Header) *httptest.ResponseRecorder {
	t.Helper()
	return doEndpointH(t, cfg, "/page", http.MethodGet, target, extra, hdr, nil)
}

// wantAuthRefused asserts a 400 auth_refused with reason: no type, no
// upstream metadata, readable by the caller (CORS).
func wantAuthRefused(t *testing.T, rr *httptest.ResponseRecorder, reason string) {
	t.Helper()
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status %d, want 400 auth_refused/%s — %s", rr.Code, reason, rr.Body.String())
	}
	pe := decodeProxyError(t, rr)
	if pe.Error != "auth_refused" || pe.Status != http.StatusBadRequest || pe.Reason != reason || pe.Type != "" || pe.Message == "" {
		t.Errorf("error body = %+v, want auth_refused/400/%s without type", pe, reason)
	}
	if keys := jsonKeys(t, rr.Body.Bytes()); !slices.Equal(keys, []string{"error", "message", "reason", "status"}) {
		t.Errorf("error keys %q", keys)
	}
	for k := range rr.Header() {
		if strings.HasPrefix(strings.ToLower(k), "x-upstream-") {
			t.Errorf("auth_refused carries %s", k)
		}
	}
	if rr.Header().Get("Access-Control-Allow-Origin") == "" {
		t.Error("auth_refused carries no CORS headers")
	}
}

// basicOf is the Basic value for user:pass.
func basicOf(user, pass string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
}

// withUserinfo puts user:pass into a server URL.
func withUserinfo(rawURL, userinfo string) string {
	scheme, rest, _ := strings.Cut(rawURL, "://")
	return scheme + "://" + userinfo + "@" + rest
}

// lockedBuffer is a log sink that server goroutines may write to while the
// test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLog sends the standard logger into a buffer for the rest of the test.
func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	return buf
}

// dump renders a response (status, every header, body) as one string.
func dump(rr *httptest.ResponseRecorder) string {
	var b strings.Builder
	b.WriteString(strconv.Itoa(rr.Code) + "\n")
	for k, vs := range rr.Header() {
		b.WriteString(k + ": " + strings.Join(vs, ", ") + "\n")
	}
	b.WriteString(rr.Body.String())
	return b.String()
}

// -----------------------------------------------------------------------
// AUTH-1 Preflight
// -----------------------------------------------------------------------

func TestCORS_AllowHeadersIncludesTargetAuthorization(t *testing.T) {
	cfg := newTestConfig()
	const want = "Content-Type, X-Proxy-Token, X-Target-Authorization, X-Target-Origin"
	for _, endpoint := range []string{"/proxy", "/inspect", "/page"} {
		req := httptest.NewRequest(http.MethodOptions, endpoint, nil)
		req.Header.Set("Origin", "https://test.example.com")
		req.Header.Set("Access-Control-Request-Method", "GET")
		req.Header.Set("Access-Control-Request-Headers", "x-proxy-token,x-target-authorization,x-target-origin")
		rr := httptest.NewRecorder()
		map[string]http.Handler{
			"/proxy": proxyHandler(cfg, http.DefaultClient), "/inspect": inspectHandler(cfg, http.DefaultClient),
			"/page": pageHandler(cfg, http.DefaultClient),
		}[endpoint].ServeHTTP(rr, req)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("%s OPTIONS: %d", endpoint, rr.Code)
		}
		got := rr.Header().Get("Access-Control-Allow-Headers")
		if got != want {
			t.Errorf("%s Allow-Headers = %q, want %q", endpoint, got, want)
		}
		listed := map[string]bool{}
		for _, h := range strings.Split(got, ",") {
			listed[strings.ToLower(strings.TrimSpace(h))] = true
		}
		for _, h := range []string{"x-proxy-token", "x-target-authorization", "x-target-origin"} {
			if !listed[h] {
				t.Errorf("%s: %s not allowed", endpoint, h)
			}
		}
		for _, h := range []string{"x-http-method-override", "authorization", "x-wp-nonce", "cookie"} {
			if listed[h] {
				t.Errorf("%s: %s must not be allowed", endpoint, h)
			}
		}
		if m := rr.Header().Get("Access-Control-Allow-Methods"); m != "GET, HEAD, POST, OPTIONS" {
			t.Errorf("%s Allow-Methods = %q", endpoint, m)
		}
	}
}

// -----------------------------------------------------------------------
// AUTH-2 / AUTH-12 Form of the headers
// -----------------------------------------------------------------------

func TestTargetAuth_InvalidValue(t *testing.T) {
	srv, rl, roots := recordingTarget(t, true, nil)
	cfg := testCfg(t, roots)
	origin := srv.URL

	refused := []struct {
		name string
		hdr  http.Header
	}{
		{"no scheme", credHeader("dGVzdA==", origin)},
		{"digest", credHeader("Digest abc", origin)},
		{"negotiate", credHeader("Negotiate abc", origin)},
		{"basic without value", credHeader("Basic", origin)},
		{"basic with trailing space", credHeader("Basic ", origin)},
		{"two spaces", credHeader("Basic  dGVzdA==", origin)},
		{"space in value", credHeader("Basic a b", origin)},
		{"control character", credHeader("Basic dGVz\x01dA==", origin)},
		{"NUL", credHeader("Basic dGVzdA==\x00", origin)},
		{"CRLF smuggling", credHeader("Basic dGVzdA==\r\nX-HTTP-Method-Override: DELETE", origin)},
		{"LF smuggling", credHeader("Basic dGVzdA==\nCookie: a=b", origin)},
		{"comma list", credHeader("Basic dGVzdA==, Bearer abc", origin)},
		{"padding only", credHeader("Basic ==", origin)},
		{"padding in the middle", credHeader("Basic ab=cd", origin)},
		{"non-ASCII", credHeader("Bearer abcé", origin)},
		{"8193 bytes", credHeader("Bearer "+strings.Repeat("a", 8193-len("Bearer ")), origin)},
		{"empty value", credHeader("", origin)},
		{"two occurrences", http.Header{
			"X-Target-Authorization": {taBasic, taBasic}, "X-Target-Origin": {origin}}},
		{"underscore variant added", http.Header{
			"X-Target-Authorization": {taBasic}, "X-Target-Origin": {origin}, "X_Target_Authorization": {taBasic}}},
		{"underscore variant alone", http.Header{
			"X_Target_Authorization": {taBasic}, "X-Target-Origin": {origin}}},
		{"underscore origin", http.Header{
			"X-Target-Authorization": {taBasic}, "X_Target_Origin": {origin}}},
		{"lower-case map key", http.Header{
			"x-target-authorization": {taBasic}, "X-Target-Origin": {origin}}},
		{"upper-case map key", http.Header{
			"X-TARGET-AUTHORIZATION": {taBasic}, "X-Target-Origin": {origin}}},
		{"missing X-Target-Origin", http.Header{"X-Target-Authorization": {taBasic}}},
		{"X-Target-Origin alone", http.Header{"X-Target-Origin": {origin}}},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			wantAuthRefused(t, doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", tc.hdr, nil), reasonInvalidValue)
		})
	}
	if n := rl.count(nil); n != 0 {
		t.Fatalf("target saw %d requests for refused values, want 0", n)
	}

	accepted := []struct{ in, sent string }{
		{taBasic, taBasic},
		{"bearer eyJ.eyJ.sig", "Bearer eyJ.eyJ.sig"},
		{"BASIC dGVzdA==", taBasic},
		{"Bearer abc-._~+/def==", "Bearer abc-._~+/def=="},
		{"Bearer " + strings.Repeat("a", 8192-len("Bearer ")), "Bearer " + strings.Repeat("a", 8192-len("Bearer "))},
	}
	for _, tc := range accepted {
		before := rl.count(nil)
		rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", credHeader(tc.in, origin), nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("%.40q: status %d — %s", tc.in, rr.Code, rr.Body.String())
		}
		reqs := rl.all()
		if len(reqs) != before+1 || reqs[len(reqs)-1].auth != tc.sent {
			t.Errorf("%.40q: target saw Authorization %.60q, want %.60q", tc.in, reqs[len(reqs)-1].auth, tc.sent)
		}
	}
}

func TestTargetAuth_TargetOriginRequired(t *testing.T) {
	srv, rl, roots := recordingTarget(t, true, nil)
	cfg := testCfg(t, roots)
	u, _ := url.Parse(srv.URL)
	port := u.Port()

	for _, origin := range []string{
		srv.URL + "/",
		srv.URL + "/wp-json/",
		srv.URL + "?x=1",
		srv.URL + "?",
		srv.URL + "#frag",
		"ftp://127.0.0.1:" + port,
		"https://user@127.0.0.1:" + port,
		"https://user:pw@127.0.0.1:" + port,
		"127.0.0.1:" + port,
		"//127.0.0.1:" + port,
		"https://",
		"https://:" + port,
		"https://127.0.0.1:0",
		"https://127.0.0.1:65536",
		"https://127.0.0.1:x",
		"null",
		"*",
		"",
		"https://" + strings.Repeat("a", 512) + ".example",
		srv.URL + ", " + srv.URL,
		"https://127.0.0.1 :" + port,
	} {
		rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", credHeader(taBasic, origin), nil)
		if rr.Code != http.StatusBadRequest || decodeProxyError(t, rr).Reason != reasonInvalidValue {
			t.Errorf("X-Target-Origin %.60q: %d %s", origin, rr.Code, rr.Body.String())
		}
	}
	// Two occurrences.
	hdr := http.Header{"X-Target-Authorization": {taBasic}, "X-Target-Origin": {srv.URL, srv.URL}}
	wantAuthRefused(t, doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", hdr, nil), reasonInvalidValue)

	if n := rl.count(nil); n != 0 {
		t.Errorf("target saw %d requests, want 0", n)
	}
}

func TestTargetAuth_OriginMismatch(t *testing.T) {
	srv, rl, roots := recordingTarget(t, true, nil)
	cfg := testCfg(t, roots)
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())

	for _, origin := range []string{
		"https://127.0.0.1:" + strconv.Itoa(port+1), // other port only
		"http://127.0.0.1:" + u.Port(),              // other scheme
		"https://localhost:" + u.Port(),             // other host, same machine
		"https://127.0.0.1",                         // default port 443
		"https://example.com:" + u.Port(),
	} {
		rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", credHeader(taBasic, origin), nil)
		wantAuthRefused(t, rr, reasonOriginMismatch)
	}
	if n := rl.count(nil); n != 0 {
		t.Errorf("target saw %d requests, want 0", n)
	}

	// Case, a trailing dot and an explicit default port do not matter.
	same := []struct{ a, b string }{
		{"https://Example.COM./x?y", "https://example.com:443"},
		{"HTTPS://example.com:443/", "https://EXAMPLE.com"},
		{"http://example.com/", "http://example.com:80"},
		{"http://example.com:0080/", "http://example.com"},
		{"https://[::1]:8443/", "https://[::1]:8443"},
	}
	for _, tc := range same {
		ua, _ := url.Parse(tc.a)
		got, ok := parseTargetOrigin(tc.b)
		if !ok || originOf(ua) != got {
			t.Errorf("originOf(%q) = %q, parseTargetOrigin(%q) = %q %v — want equal", tc.a, originOf(ua), tc.b, got, ok)
		}
	}
	differ := []struct{ a, b string }{
		{"https://example.com/", "http://example.com"},
		{"https://example.com/", "https://www.example.com"},
		{"https://example.com/", "https://example.com:8443"},
		{"https://xn--bcher-kva.example/", "https://bücher.example"},
	}
	for _, tc := range differ {
		ua, _ := url.Parse(tc.a)
		if got, ok := parseTargetOrigin(tc.b); ok && originOf(ua) == got {
			t.Errorf("originOf(%q) == origin %q, want different", tc.a, tc.b)
		}
	}
	if o := originOf(&url.URL{Scheme: "ftp", Host: "example.com"}); o != "" {
		t.Errorf("originOf(ftp) = %q, want empty", o)
	}
}

// -----------------------------------------------------------------------
// AUTH-3 Never forwarded as such; allowlist of request headers
// -----------------------------------------------------------------------

func TestTargetAuth_SetsAuthorizationOnTarget(t *testing.T) {
	for _, value := range []string{taBasic, "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"} {
		srv, rl, roots := recordingTarget(t, true, nil)
		cfg := testCfg(t, roots)
		cfg.allowedOrigins = []string{"https://test.example.com"}
		hdr := credHeader(value, srv.URL)
		hdr["Origin"] = []string{"https://test.example.com"}
		rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/wp-json/", "", hdr, nil)
		if rr.Code != http.StatusOK || rr.Body.String() != "ok" {
			t.Fatalf("status %d — %s", rr.Code, rr.Body.String())
		}
		reqs := rl.all()
		if len(reqs) != 1 {
			t.Fatalf("target saw %d requests, want 1", len(reqs))
		}
		if reqs[0].auth != value {
			t.Errorf("Authorization = %q, want %q", reqs[0].auth, value)
		}
		for _, h := range []string{"X-Target-Authorization", "X-Target-Origin", "X-Proxy-Token", "Origin"} {
			if v := reqs[0].header.Get(h); v != "" {
				t.Errorf("%s reached the target: %q", h, v)
			}
		}
		if got := rr.Header().Get("X-Upstream-Auth"); got != authSent {
			t.Errorf("X-Upstream-Auth = %q, want sent", got)
		}
		if !exposed(rr, "X-Upstream-Auth") {
			t.Errorf("X-Upstream-Auth not exposed: %q", rr.Header().Get("Access-Control-Expose-Headers"))
		}
		if rr.Header().Get("Authorization") != "" {
			t.Error("Authorization echoed to the caller")
		}
	}
}

func TestTargetAuth_HeaderAllowlist(t *testing.T) {
	srv, rl, roots := recordingTarget(t, true, nil)
	cfg := testCfg(t, roots)
	browser := http.Header{
		"Accept":           {"application/json"},
		"Accept-Language":  {"de-DE"},
		"User-Agent":       {"Mozilla/5.0"},
		"Cache-Control":    {"no-cache"},
		"Pragma":           {"no-cache"},
		"X-Custom":         {"1"},
		"X-Wp-Nonce":       {"abc"},
		"Cookie":           {"wordpress_logged_in=x"},
		"Authorization":    {"Basic b3RoZXI6b3RoZXI="},
		"Content-Type":     {"application/json"},
		"X-Requested-With": {"XMLHttpRequest"},
		"Accept_Language":  {"smuggled"},
		"X_Wp_Nonce":       {"smuggled"},
	}
	hdr := credHeader(taBasic, srv.URL)
	for k, v := range browser {
		hdr[k] = v
	}
	// A GET body is never forwarded; with credentials not even a _method in it.
	rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", hdr, strings.NewReader("_method=DELETE"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d — %s", rr.Code, rr.Body.String())
	}
	seen := rl.all()[0]
	for _, h := range []string{"Accept", "Accept-Language", "User-Agent", "Cache-Control", "Pragma"} {
		if seen.header.Get(h) != browser.Get(h) {
			t.Errorf("%s = %q, want %q", h, seen.header.Get(h), browser.Get(h))
		}
	}
	for k := range seen.header {
		switch strings.ToLower(k) {
		case "accept", "accept-language", "user-agent", "cache-control", "pragma",
			"authorization", "accept-encoding", "content-length",
			"connection": // "close", set by the transport (DisableKeepAlives)
		default:
			t.Errorf("header %s reached an authenticated target", k)
		}
	}
	if seen.auth != taBasic {
		t.Errorf("Authorization = %q, want the X-Target-Authorization value", seen.auth)
	}
	if seen.body != "" {
		t.Errorf("body %q reached the target", seen.body)
	}

	// Without credentials the v1.3.0 deny list still applies: X-Custom goes.
	rr = doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", http.Header{"X-Custom": {"1"}}, nil)
	if rr.Code != http.StatusOK || rl.all()[1].header.Get("X-Custom") != "1" {
		t.Errorf("anonymous request lost X-Custom: %d", rr.Code)
	}
}

// -----------------------------------------------------------------------
// AUTH-4 /proxy only
// -----------------------------------------------------------------------

func TestTargetAuth_RefusedOnInspectAndPage(t *testing.T) {
	srv, rl, roots := recordingTarget(t, true, nil)
	cfg := testCfg(t, roots)
	hdr := credHeader(taBasic, srv.URL)
	for _, tc := range []struct{ endpoint, extra string }{
		{"/inspect", ""},
		{"/inspect", "&get=1&diag=1"},
		{"/inspect", "&body=1"},
		{"/page", ""},
		{"/page", "&diag=1"},
	} {
		rr := doEndpointH(t, cfg, tc.endpoint, http.MethodGet, srv.URL+"/", tc.extra, hdr, nil)
		wantAuthRefused(t, rr, reasonEndpoint)
	}
	if n := rl.count(nil); n != 0 {
		t.Errorf("target saw %d requests, want 0", n)
	}
}

// -----------------------------------------------------------------------
// AUTH-5 GET and HEAD only
// -----------------------------------------------------------------------

func TestTargetAuth_PostRefused(t *testing.T) {
	srv, rl, roots := recordingTarget(t, true, nil)
	cfg := testCfg(t, roots)
	for _, extra := range []string{"", "&follow=1"} {
		rr := doProxyH(t, cfg, http.MethodPost, srv.URL+"/wp-json/wp/v2/posts", extra,
			credHeader(taBasic, srv.URL), strings.NewReader(`{"title":"x"}`))
		wantAuthRefused(t, rr, reasonMethod)
	}
	t.Run("userinfo without header", func(t *testing.T) {
		rr := doProxyH(t, cfg, http.MethodPost, withUserinfo(srv.URL, "user:apppass")+"/wp-json/wp/v2/posts", "",
			nil, strings.NewReader(`{"title":"x"}`))
		wantAuthRefused(t, rr, reasonMethod)
	})
	// HEAD is fine.
	rr := doProxyH(t, cfg, http.MethodHead, srv.URL+"/", "", credHeader(taBasic, srv.URL), nil)
	if rr.Code != http.StatusOK || rr.Header().Get("X-Upstream-Auth") != authSent {
		t.Errorf("HEAD with credentials: %d, X-Upstream-Auth %q", rr.Code, rr.Header().Get("X-Upstream-Auth"))
	}
	if n := rl.count(func(s seenRequest) bool { return s.method != http.MethodHead }); n != 0 {
		t.Errorf("target saw %d non-HEAD requests, want 0", n)
	}
}

func TestProxy_PostWithoutAuthUnchanged(t *testing.T) {
	srv, rl, _ := recordingTarget(t, false, nil)
	cfg := testCfg(t, nil)
	rr := doProxy(t, cfg, http.MethodPost, srv.URL+"/form?_method=DELETE", "", strings.NewReader("a=1&_method=DELETE"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d — %s", rr.Code, rr.Body.String())
	}
	seen := rl.all()
	if len(seen) != 1 || seen[0].method != http.MethodPost || seen[0].body != "a=1&_method=DELETE" ||
		seen[0].query != "_method=DELETE" || seen[0].auth != "" {
		t.Errorf("target saw %+v", seen)
	}
	for _, h := range []string{"X-Upstream-Auth", "X-Upstream-Cache-Control"} {
		if rr.Header().Get(h) != "" || exposed(rr, h) {
			t.Errorf("%s on an anonymous POST", h)
		}
	}
}

// -----------------------------------------------------------------------
// AUTH-6 Method overrides
// -----------------------------------------------------------------------

func TestTargetAuth_MethodOverrideGuard(t *testing.T) {
	refused := []string{
		"_method=DELETE",
		"_METHOD=delete",
		".method=PUT",
		"%20_method=PATCH",
		"+_method=PATCH",
		"%5Fmethod=POST",
		"%5fmethod=POST",
		"_method=OPTIONS&_method=DELETE",
		"_method=GET&_method=DELETE",
		"_method[]=DELETE",
		"_method%5B%5D=DELETE",
		"_method[x]=GET",
		"_method[=DELETE",
		"rest_route=/wp/v2/posts/1&_method=DELETE",
		"_method%00x=DELETE",
		"_method%00=PUT",
		"_method=DELETE%00",
		"a=1;_method=DELETE",
		"a=1;_method=PUT",
		"_method",
		"_method=",
		"_method=%20",
		"_m%65thod=DELETE",
		"_method=DEL%45TE",
		"a=%01",
		"a%0A=1",
		"a=%7F",
		// Review I1: only ASCII case folding and ASCII spaces, like PHP 8.
		"_method=OPT%C4%B1ONS", // dotless i
		"_method=OPTION%C5%BF", // long s
		"_method=%C4%B1get",
		"_method=%C2%A0GET", // no-break space
		"_method=GET%C2%A0",
		"_method=%E2%80%83HEAD", // em space
	}
	allowed := []string{
		"",
		"_method=OPTIONS",
		"_method=get",
		"_method=HEAD",
		"_method=%20get%20",
		"x_method=DELETE",
		"_methods=DELETE",
		"method=DELETE",
		"_method.=DELETE",
		"%5Fmethod%3DDELETE",
		"search=a%2Bb&_fields=id,title",
		"a=%zz&b=%",
		"context=help&_method=OPTIONS",
	}
	for _, q := range refused {
		if !writesViaOverride(&url.URL{RawQuery: q}) {
			t.Errorf("writesViaOverride(%q) = false, want true", q)
		}
	}
	for _, q := range allowed {
		if writesViaOverride(&url.URL{RawQuery: q}) {
			t.Errorf("writesViaOverride(%q) = true, want false", q)
		}
	}

	// Through the handler: a refused query never reaches the target.
	srv, rl, roots := recordingTarget(t, true, nil)
	cfg := testCfg(t, roots)
	for _, q := range refused {
		rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/wp-json/wp/v2/posts/1?"+q, "", credHeader(taBasic, srv.URL), nil)
		if rr.Code != http.StatusBadRequest || decodeProxyError(t, rr).Reason != reasonMethodOverride {
			t.Errorf("?%s: %d %s", q, rr.Code, rr.Body.String())
		}
	}
	if n := rl.count(nil); n != 0 {
		t.Fatalf("target saw %d requests for refused queries", n)
	}
	for _, q := range allowed {
		rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/wp-json/?"+q, "", credHeader(taBasic, srv.URL), nil)
		if rr.Code != http.StatusOK {
			t.Errorf("?%s: %d %s", q, rr.Code, rr.Body.String())
		}
	}
}

func TestTargetAuth_MethodOverrideHeadersRefused(t *testing.T) {
	srv, rl, roots := recordingTarget(t, true, nil)
	cfg := testCfg(t, roots)
	for _, h := range []http.Header{
		{"X-Http-Method-Override": {"DELETE"}},
		{"X-Http-Method-Override": {"GET"}}, // any value
		{"X-Http-Method": {"PUT"}},
		{"X-Method-Override": {"PATCH"}},
		{"X_HTTP_METHOD_OVERRIDE": {"DELETE"}},
		{"x-http-method-override": {"DELETE"}},
		{"X_Method_Override": {"DELETE"}},
	} {
		hdr := credHeader(taBasic, srv.URL)
		for k, v := range h {
			hdr[k] = v
		}
		wantAuthRefused(t, doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", hdr, nil), reasonMethodOverride)
		// The same with userinfo instead of the header.
		wantAuthRefused(t, doProxyH(t, cfg, http.MethodGet, withUserinfo(srv.URL, "u:p")+"/", "", h, nil), reasonMethodOverride)
		wantAuthRefused(t, doInspectH(t, cfg, withUserinfo(srv.URL, "u:p")+"/", "", h), reasonMethodOverride)
	}
	if n := rl.count(nil); n != 0 {
		t.Errorf("target saw %d requests, want 0", n)
	}
}

func TestProxy_MethodOverrideWithoutAuthUnchanged(t *testing.T) {
	srv, rl, _ := recordingTarget(t, false, nil)
	cfg := testCfg(t, nil)
	for _, q := range []string{"_method=DELETE", "_method[]=PUT", "a=1;_method=PATCH", "a=%01"} {
		rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/wp-json/?"+q, "",
			http.Header{"X-Http-Method-Override": {"DELETE"}}, nil)
		if rr.Code != http.StatusOK {
			t.Errorf("?%s: %d %s", q, rr.Code, rr.Body.String())
		}
		if rr.Header().Get("X-Upstream-Auth") != "" {
			t.Errorf("?%s: X-Upstream-Auth on an anonymous request", q)
		}
	}
	for _, s := range rl.all() {
		if s.header.Get("X-Http-Method-Override") != "DELETE" || s.auth != "" {
			t.Errorf("anonymous request changed: %+v", s)
		}
	}
	// /inspect and /page as well.
	if rr := doInspectH(t, cfg, srv.URL+"/?_method=DELETE", "", nil); rr.Code != http.StatusOK {
		t.Errorf("/inspect: %d", rr.Code)
	}
	if p := decodePage(t, doPageH(t, cfg, srv.URL+"/?_method=DELETE", "", nil)); p.Error != nil || p.Status != 200 {
		t.Errorf("/page: %+v", p.Error)
	}
}

func TestTargetAuth_MethodOverrideOnHop(t *testing.T) {
	for _, loc := range []string{
		"/wp-json/wp/v2/posts/1?_method=DELETE",
		"/wp-json/wp/v2/posts/1?a=1;_method=PUT",
		"/wp-json/wp/v2/posts/1?%5Fmethod=DELETE",
	} {
		t.Run(loc, func(t *testing.T) {
			srv, rl, roots := recordingTarget(t, true, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/start" {
					w.Header().Set("Location", loc)
					w.WriteHeader(http.StatusFound)
					return
				}
				io.WriteString(w, "deleted")
			})
			cfg := testCfg(t, roots)
			isTarget := func(s seenRequest) bool { return strings.HasPrefix(s.path, "/wp-json/") }

			// Header credentials: the chain ends before the hop.
			rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/start", "&follow=1", credHeader(taBasic, srv.URL), nil)
			if rr.Code != http.StatusFound {
				t.Fatalf("status %d, want 302 — %s", rr.Code, rr.Body.String())
			}
			if got := rr.Header().Get("X-Upstream-Auth"); got != authWithheldMethodOverride {
				t.Errorf("X-Upstream-Auth = %q", got)
			}
			if got := rr.Header().Get("X-Upstream-Location"); !strings.HasPrefix(got, srv.URL+"/wp-json/") {
				t.Errorf("X-Upstream-Location = %q", got)
			}
			if n := rl.count(isTarget); n != 0 {
				t.Fatalf("override hop saw %d requests", n)
			}

			// Userinfo: the hop goes on, but without Authorization.
			rr = doProxyH(t, cfg, http.MethodGet, withUserinfo(srv.URL, "user:pw")+"/start", "&follow=1", nil, nil)
			if rr.Code != http.StatusOK {
				t.Fatalf("userinfo: status %d — %s", rr.Code, rr.Body.String())
			}
			if got := rr.Header().Get("X-Upstream-Auth"); got != authWithheld {
				t.Errorf("userinfo: X-Upstream-Auth = %q, want withheld", got)
			}
			// /page with userinfo: HEAD hop and final GET, both anonymous.
			if p := decodePage(t, doPageH(t, cfg, withUserinfo(srv.URL, "user:pw")+"/start", "", nil)); p.Error != nil {
				t.Errorf("/page: %+v", p.Error)
			}
			if n := rl.count(func(s seenRequest) bool { return isTarget(s) && s.auth != "" }); n != 0 {
				t.Errorf("override hop saw %d requests with Authorization", n)
			}
			if n := rl.count(func(s seenRequest) bool {
				return s.path == "/start" && s.auth != basicOf("user", "pw") && s.auth != taBasic
			}); n != 0 {
				t.Errorf("start URL saw %d requests without credentials", n)
			}
		})
	}
}

// -----------------------------------------------------------------------
// AUTH-7 Origin binding and redirects
// -----------------------------------------------------------------------

func TestTargetAuth_FollowSameOrigin(t *testing.T) {
	srv, rl, roots := recordingTarget(t, true, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/a":
			w.Header().Set("Location", "/b")
			w.WriteHeader(http.StatusMovedPermanently)
		case strings.HasPrefix(r.URL.Path, "/hop/"):
			n, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/hop/"))
			w.Header().Set("Location", "/hop/"+strconv.Itoa(n+1))
			w.WriteHeader(http.StatusFound)
		default:
			io.WriteString(w, "b")
		}
	})
	cfg := testCfg(t, roots)
	rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/a", "&follow=1", credHeader(taBasic, srv.URL), nil)
	if rr.Code != http.StatusOK || rr.Body.String() != "b" {
		t.Fatalf("status %d — %s", rr.Code, rr.Body.String())
	}
	if n := rl.count(func(s seenRequest) bool { return s.auth == taBasic }); n != 2 {
		t.Errorf("%d requests carried Authorization, want 2", n)
	}
	if rr.Header().Get("X-Upstream-Redirects") != "1" || rr.Header().Get("X-Upstream-Auth") != authSent {
		t.Errorf("redirects %q, auth %q", rr.Header().Get("X-Upstream-Redirects"), rr.Header().Get("X-Upstream-Auth"))
	}

	// Hop limit reached on the same origin: still "sent".
	rr = doProxyH(t, cfg, http.MethodGet, srv.URL+"/hop/0", "&follow=1", credHeader(taBasic, srv.URL), nil)
	if rr.Code != http.StatusFound || rr.Header().Get("X-Upstream-Auth") != authSent ||
		rr.Header().Get("X-Upstream-Redirects") != strconv.Itoa(maxProxyRedirects) {
		t.Errorf("hop limit: %d, auth %q, redirects %q", rr.Code, rr.Header().Get("X-Upstream-Auth"), rr.Header().Get("X-Upstream-Redirects"))
	}
	if n := rl.count(func(s seenRequest) bool { return s.auth != taBasic }); n != 0 {
		t.Errorf("%d same-origin requests without Authorization", n)
	}
}

func TestTargetAuth_StopsAtCrossOriginRedirect(t *testing.T) {
	check := func(t *testing.T, rr *httptest.ResponseRecorder, wantLoc string) {
		t.Helper()
		if rr.Code != http.StatusFound {
			t.Fatalf("status %d, want 302 — %s", rr.Code, rr.Body.String())
		}
		if got := rr.Header().Get("X-Upstream-Auth"); got != authWithheldCrossOrigin {
			t.Errorf("X-Upstream-Auth = %q", got)
		}
		if got := rr.Header().Get("X-Upstream-Location"); got != wantLoc {
			t.Errorf("X-Upstream-Location = %q, want %q", got, wantLoc)
		}
		if rr.Header().Get("X-Upstream-Redirects") != "0" {
			t.Errorf("X-Upstream-Redirects = %q, want 0", rr.Header().Get("X-Upstream-Redirects"))
		}
	}

	t.Run("other port", func(t *testing.T) {
		b, bLog, _ := recordingTarget(t, true, nil)
		a, aLog, roots := recordingTarget(t, true, redirectTo(b.URL+"/steal"))
		roots.AddCert(b.Certificate())
		cfg := testCfg(t, roots)
		check(t, doProxyH(t, cfg, http.MethodGet, a.URL+"/", "&follow=1", credHeader(taBasic, a.URL), nil), b.URL+"/steal")
		if bLog.count(nil) != 0 {
			t.Errorf("B saw %d requests", bLog.count(nil))
		}
		if aLog.count(func(s seenRequest) bool { return s.auth == taBasic }) != 1 {
			t.Error("A did not get the credentials once")
		}
	})

	t.Run("other host", func(t *testing.T) {
		var srv *httptest.Server
		srv, rl, roots := recordingTarget(t, true, func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.Host, "a.example.com") {
				w.Header().Set("Location", "https://b.example.com:"+serverPort(t, srv)+"/steal")
				w.WriteHeader(http.StatusFound)
				return
			}
			io.WriteString(w, "b")
		})
		cfg := testCfg(t, roots)
		cfg.lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
			if host == "a.example.com" || host == "b.example.com" || host == "127.0.0.1" {
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
			}
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		port := serverPort(t, srv)
		start := "https://a.example.com:" + port + "/"
		check(t, doProxyH(t, cfg, http.MethodGet, start, "&follow=1", credHeader(taBasic, "https://a.example.com:"+port), nil),
			"https://b.example.com:"+port+"/steal")
		if n := rl.count(func(s seenRequest) bool { return strings.HasPrefix(s.host, "b.example.com") }); n != 0 {
			t.Errorf("b.example.com saw %d requests", n)
		}
		// A protocol-relative Location is another origin as well.
		srv2, rl2, roots2 := recordingTarget(t, true, redirectTo("//b.example.com:"+port+"/x"))
		cfg.rootCAs = roots2
		port2 := serverPort(t, srv2)
		check(t, doProxyH(t, cfg, http.MethodGet, "https://a.example.com:"+port2+"/", "&follow=1",
			credHeader(taBasic, "https://a.example.com:"+port2), nil), "https://b.example.com:"+port+"/x")
		if rl2.count(nil) != 1 {
			t.Errorf("A2 saw %d requests, want 1", rl2.count(nil))
		}
	})

	t.Run("https to http", func(t *testing.T) {
		plain, plainLog, _ := recordingTarget(t, false, nil)
		a, _, roots := recordingTarget(t, true, redirectTo(plain.URL+"/"))
		cfg := testCfg(t, roots)
		check(t, doProxyH(t, cfg, http.MethodGet, a.URL+"/", "&follow=1", credHeader(taBasic, a.URL), nil), plain.URL+"/")
		if plainLog.count(nil) != 0 {
			t.Errorf("http target saw %d requests", plainLog.count(nil))
		}
	})

	t.Run("same host other scheme and port", func(t *testing.T) {
		a, _, roots := recordingTarget(t, true, redirectTo("http://127.0.0.1:"+"1"+"/"))
		cfg := testCfg(t, roots)
		check(t, doProxyH(t, cfg, http.MethodGet, a.URL+"/", "&follow=1", credHeader(taBasic, a.URL), nil), "http://127.0.0.1:1/")
	})

	t.Run("userinfo in Location to the same origin is followed", func(t *testing.T) {
		var srv *httptest.Server
		srv, rl, roots := recordingTarget(t, true, func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/" {
				w.Header().Set("Location", "https://attacker:x@127.0.0.1:"+serverPort(t, srv)+"/b")
				w.WriteHeader(http.StatusFound)
				return
			}
			io.WriteString(w, "b")
		})
		cfg := testCfg(t, roots)
		rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "&follow=1", credHeader(taBasic, srv.URL), nil)
		if rr.Code != http.StatusOK || rr.Header().Get("X-Upstream-Auth") != authSent {
			t.Fatalf("%d %q", rr.Code, rr.Header().Get("X-Upstream-Auth"))
		}
		if n := rl.count(func(s seenRequest) bool { return s.auth != taBasic }); n != 0 {
			t.Errorf("%d requests did not carry exactly the X-Target-Authorization value", n)
		}
		if strings.Contains(rr.Header().Get("X-Upstream-Final-URL"), "attacker") {
			t.Errorf("userinfo of the Location in X-Upstream-Final-URL: %q", rr.Header().Get("X-Upstream-Final-URL"))
		}
	})
}

func TestTargetAuth_NoFollowReturns3xx(t *testing.T) {
	b, bLog, _ := recordingTarget(t, true, nil)
	a, aLog, roots := recordingTarget(t, true, redirectTo(b.URL+"/x"))
	cfg := testCfg(t, roots)
	rr := doProxyH(t, cfg, http.MethodGet, a.URL+"/", "", credHeader(taBasic, a.URL), nil)
	if rr.Code != http.StatusFound || rr.Header().Get("X-Upstream-Auth") != authSent ||
		rr.Header().Get("X-Upstream-Location") != b.URL+"/x" || rr.Header().Get("Location") != "" {
		t.Errorf("%d auth %q location %q", rr.Code, rr.Header().Get("X-Upstream-Auth"), rr.Header().Get("X-Upstream-Location"))
	}
	if aLog.count(nil) != 1 || bLog.count(nil) != 0 {
		t.Errorf("A saw %d, B saw %d requests; want 1 and 0", aLog.count(nil), bLog.count(nil))
	}
}

// -----------------------------------------------------------------------
// AUTH-8 https only, except loopback --allow-local targets
// -----------------------------------------------------------------------

func TestTargetAuth_InsecureSchemeRefused(t *testing.T) {
	srv, rl, _ := recordingTarget(t, false, nil)
	cfg := testCfg(t, nil)
	wantAuthRefused(t, doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", credHeader(taBasic, srv.URL), nil), reasonInsecureScheme)
	if rl.count(nil) != 0 {
		t.Errorf("target saw %d requests", rl.count(nil))
	}
	// Userinfo keeps the v1.3.0 behaviour over http (AUTH-13).
	rr := doProxyH(t, cfg, http.MethodGet, withUserinfo(srv.URL, "u:p")+"/", "", nil, nil)
	if rr.Code != http.StatusOK || rl.all()[0].auth != basicOf("u", "p") {
		t.Errorf("userinfo over http: %d", rr.Code)
	}
}

func TestTargetAuth_InsecureSchemeAllowedForLocalTarget(t *testing.T) {
	srv, rl, _ := recordingTarget(t, false, nil)
	port := serverPort(t, srv)
	cfg, _ := localCfg(t, "wp.test:"+port, map[string]string{"wp.test": "127.0.0.1"}, nil)
	rr := doProxyH(t, cfg, http.MethodGet, "http://wp.test:"+port+"/wp-json/", "", credHeader(taBasic, "http://wp.test:"+port), nil)
	if rr.Code != http.StatusOK || rr.Header().Get("X-Upstream-Auth") != authSent {
		t.Fatalf("status %d auth %q — %s", rr.Code, rr.Header().Get("X-Upstream-Auth"), rr.Body.String())
	}
	if rl.all()[0].auth != taBasic {
		t.Errorf("Authorization = %q", rl.all()[0].auth)
	}
	// Same entry, but the name answers with a public address first and then
	// loopback: the public one is never dialled, loopback is.
	cfg, _ = localCfg(t, "wp.test:"+port, map[string]string{"wp.test": "93.184.215.14,127.0.0.1"}, nil)
	rr = doProxyH(t, cfg, http.MethodGet, "http://wp.test:"+port+"/", "", credHeader(taBasic, "http://wp.test:"+port), nil)
	if rr.Code != http.StatusOK || rr.Header().Get("X-Upstream-IP") != "127.0.0.1" {
		t.Errorf("mixed answer: %d ip %q — %s", rr.Code, rr.Header().Get("X-Upstream-IP"), rr.Body.String())
	}
}

func TestTargetAuth_HTTPToListedNameResolvingPublicRefused(t *testing.T) {
	cfg, lookups := localCfg(t, "wp.test:8080", map[string]string{"wp.test": "93.184.215.14"}, nil)
	rr := doProxyH(t, cfg, http.MethodGet, "http://wp.test:8080/", "", credHeader(taBasic, "http://wp.test:8080"), nil)
	wantAuthRefused(t, rr, reasonInsecureScheme)
	if lookups.Load() == 0 {
		t.Error("the dialer never resolved the name — the refusal did not come from the dial stage")
	}
}

func TestTargetAuth_HTTPToLANRefused(t *testing.T) {
	hosts := map[string]string{"wp.intranet.example": "10.0.5.7"}
	cfg, _ := localCfg(t, "wp.intranet.example,10.0.5.0/24", hosts, nil)
	rr := doProxyH(t, cfg, http.MethodGet, "http://wp.intranet.example/", "", credHeader(taBasic, "http://wp.intranet.example"), nil)
	wantAuthRefused(t, rr, reasonInsecureScheme)

	// Over https the same target is admissible. The request context is
	// cancelled up front, so nothing is dialled — only the verdict counts.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/proxy?url="+url.QueryEscape("https://wp.intranet.example/"), nil).WithContext(ctx)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	req.Header.Set("X-Target-Authorization", taBasic)
	req.Header.Set("X-Target-Origin", "https://wp.intranet.example")
	rec := httptest.NewRecorder()
	proxyHandler(cfg, newUpstreamClient(cfg)).ServeHTTP(rec, req)
	if pe := decodeProxyError(t, rec); pe.Error == "auth_refused" || pe.Error == "blocked_target" {
		t.Errorf("https to an allowed LAN address refused: %+v", pe)
	}

	// The dial stage itself: loopback-only with the mark, the plain verdict without.
	// The unmarked call gets a cancelled context: the allowed address would
	// otherwise really be dialled.
	failing := &net.Dialer{Control: func(string, string, syscall.RawConn) error { return errors.New("no dial in tests") }}
	guard := localGuard(cfg, failing)
	marked := withAuthOverHTTP(withLocalStart(context.Background(), true))
	if _, err := guard(marked, "tcp", "wp.intranet.example:80"); !errors.Is(err, errInsecureAuth) {
		t.Errorf("auth over http to 10.0.5.7: err %v, want errInsecureAuth", err)
	}
	if _, err := guard(withLocalStart(ctx, true), "tcp", "wp.intranet.example:80"); errors.Is(err, errInsecureAuth) || err == nil {
		t.Errorf("without credentials over http: err %v, want the dialer's own error", err)
	}
}

// -----------------------------------------------------------------------
// AUTH-9 / AUTH-13 Userinfo
// -----------------------------------------------------------------------

func TestTargetAuth_UserinfoRefused(t *testing.T) {
	srv, rl, roots := recordingTarget(t, true, nil)
	cfg := testCfg(t, roots)
	for _, ui := range []string{"user:pass", "user", ":pass", "", "us%65r:p%40ss"} {
		rr := doProxyH(t, cfg, http.MethodGet, withUserinfo(srv.URL, ui)+"/", "", credHeader(taBasic, srv.URL), nil)
		wantAuthRefused(t, rr, reasonUserinfo)
	}
	if rl.count(nil) != 0 {
		t.Errorf("target saw %d requests", rl.count(nil))
	}
}

func TestUserinfo_PostRefused(t *testing.T) {
	srv, rl, _ := recordingTarget(t, false, nil)
	cfg := testCfg(t, nil)
	for _, ui := range []string{"user:apppass", "user", "", "us%65r:p%40ss"} {
		rr := doProxyH(t, cfg, http.MethodPost, withUserinfo(srv.URL, ui)+"/wp-json/wp/v2/posts", "", nil, strings.NewReader("{}"))
		wantAuthRefused(t, rr, reasonMethod)
	}
	if rl.count(nil) != 0 {
		t.Errorf("target saw %d requests", rl.count(nil))
	}
}

func TestUserinfo_MethodOverrideRefused(t *testing.T) {
	srv, rl, _ := recordingTarget(t, false, nil)
	cfg := testCfg(t, nil)
	target := withUserinfo(srv.URL, "user:apppass") + "/wp-json/wp/v2/posts/1?_method=DELETE"
	for _, tc := range []struct{ endpoint, extra string }{
		{"/proxy", ""}, {"/proxy", "&follow=1"}, {"/inspect", ""}, {"/inspect", "&get=1"}, {"/inspect", "&body=1"},
		{"/page", ""}, {"/page", "&diag=1"},
	} {
		wantAuthRefused(t, doEndpointH(t, cfg, tc.endpoint, http.MethodGet, target, tc.extra, nil, nil), reasonMethodOverride)
	}
	if rl.count(nil) != 0 {
		t.Errorf("target saw %d requests", rl.count(nil))
	}
}

func TestUserinfo_StillAuthenticatesGET(t *testing.T) {
	srv, rl, _ := recordingTarget(t, false, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/r" {
			w.Header().Set("Location", "/ok")
			w.WriteHeader(http.StatusFound)
			return
		}
		io.WriteString(w, "ok")
	})
	cfg := testCfg(t, nil)
	want := basicOf("user", "p@ss")
	target := withUserinfo(srv.URL, "us%65r:p%40ss")
	for _, tc := range []struct{ endpoint, method, path, extra string }{
		{"/proxy", http.MethodGet, "/ok", ""},
		{"/proxy", http.MethodHead, "/ok", ""},
		{"/proxy", http.MethodGet, "/r", "&follow=1"},
		{"/inspect", http.MethodGet, "/ok", ""},
		{"/inspect", http.MethodGet, "/ok", "&get=1"},
		{"/inspect", http.MethodGet, "/ok", "&body=1"},
		{"/page", http.MethodGet, "/r", ""},
		{"/page", http.MethodGet, "/r", "&diag=1"},
	} {
		before := rl.count(nil)
		rr := doEndpointH(t, cfg, tc.endpoint, tc.method, target+tc.path, tc.extra, nil, nil)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s%s: %d — %s", tc.endpoint, tc.extra, rr.Code, rr.Body.String())
		}
		reqs := rl.all()[before:]
		if len(reqs) == 0 {
			t.Fatalf("%s%s: no upstream request", tc.endpoint, tc.extra)
		}
		for _, s := range reqs {
			if s.auth != want {
				t.Errorf("%s%s: %s %s carried %q, want %q", tc.endpoint, tc.extra, s.method, s.path, s.auth, want)
			}
		}
		if tc.endpoint == "/proxy" {
			if rr.Header().Get("X-Upstream-Auth") != authSent || rr.Header().Get("Cache-Control") != "no-store" {
				t.Errorf("/proxy%s: auth %q cache %q", tc.extra, rr.Header().Get("X-Upstream-Auth"), rr.Header().Get("Cache-Control"))
			}
		}
	}
	// Empty userinfo is what net/http sent as well: Basic of ":".
	before := rl.count(nil)
	if rr := doProxyH(t, cfg, http.MethodGet, withUserinfo(srv.URL, "")+"/ok", "", nil, nil); rr.Code != http.StatusOK {
		t.Fatalf("empty userinfo: %d", rr.Code)
	}
	if got := rl.all()[before].auth; got != basicOf("", "") {
		t.Errorf("empty userinfo sent %q", got)
	}
}

func TestUserinfo_CrossOriginContinuesAnonymously(t *testing.T) {
	b, bLog, _ := recordingTarget(t, false, nil)
	a, aLog, _ := recordingTarget(t, false, redirectTo(b.URL+"/elsewhere"))
	cfg := testCfg(t, nil)
	rr := doProxyH(t, cfg, http.MethodGet, withUserinfo(a.URL, "user:pw")+"/", "&follow=1", nil, nil)
	if rr.Code != http.StatusOK || rr.Body.String() != "ok" {
		t.Fatalf("status %d — %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("X-Upstream-Auth"); got != authWithheld {
		t.Errorf("X-Upstream-Auth = %q, want withheld", got)
	}
	if bLog.count(nil) != 1 || bLog.all()[0].auth != "" {
		t.Errorf("B: %+v, want one anonymous request", bLog.all())
	}
	if aLog.count(nil) != 1 || aLog.all()[0].auth != basicOf("user", "pw") {
		t.Errorf("A: %+v, want one request with the credentials", aLog.all())
	}
	// /page: the hop on B is anonymous as well.
	before := bLog.count(nil)
	if p := decodePage(t, doPageH(t, cfg, withUserinfo(a.URL, "user:pw")+"/", "", nil)); p.Error != nil {
		t.Fatalf("/page: %+v", p.Error)
	}
	for _, s := range bLog.all()[before:] {
		if s.auth != "" {
			t.Errorf("/page sent credentials to B: %s %s", s.method, s.path)
		}
	}
}

func TestUserinfo_NeverEchoed(t *testing.T) {
	logs := captureLog(t)
	srv, _, _ := recordingTarget(t, false, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/r" {
			w.Header().Set("Location", "/ok")
			w.WriteHeader(http.StatusFound)
			return
		}
		io.WriteString(w, "ok")
	})
	cfg := testCfg(t, nil)
	target := withUserinfo(srv.URL, "secretuser:secretpass")
	var out []string
	for _, tc := range []struct{ endpoint, target, extra string }{
		{"/proxy", target + "/r", "&follow=1"},
		{"/proxy", target + "/ok", "&follow=1"},
		{"/proxy", target + "/r", ""},
		{"/inspect", target + "/r", ""},
		{"/inspect", target + "/ok", "&body=1&diag=1"},
		{"/page", target + "/r", "&diag=1"},
		{"/page", target + "/ok", ""},
		// Failures that log the target URL.
		{"/proxy", withUserinfo(strings.TrimSuffix(closedPortURL(t), "/"), "secretuser:secretpass") + "/", ""},
		{"/inspect", withUserinfo(strings.TrimSuffix(closedPortURL(t), "/"), "secretuser:secretpass") + "/", "&diag=1"},
		{"/page", withUserinfo(strings.TrimSuffix(closedPortURL(t), "/"), "secretuser:secretpass") + "/", "&diag=1"},
	} {
		rr := doEndpointH(t, cfg, tc.endpoint, http.MethodGet, tc.target, tc.extra, nil, nil)
		out = append(out, dump(rr))
		if tc.endpoint == "/page" && rr.Code == http.StatusOK {
			p := decodePage(t, rr)
			if p.URL != strings.Replace(tc.target, "secretuser:secretpass@", "", 1) {
				t.Errorf("/page url = %q", p.URL)
			}
		}
	}
	out = append(out, logs.String())
	for _, s := range out {
		for _, secret := range []string{"secretuser", "secretpass", base64.StdEncoding.EncodeToString([]byte("secretuser:secretpass"))} {
			if strings.Contains(s, secret) {
				t.Errorf("%q leaked:\n%s", secret, s)
			}
		}
	}
}

// -----------------------------------------------------------------------
// AUTH-10 Cache
// -----------------------------------------------------------------------

func TestProxy_VaryIncludesTargetAuthorization(t *testing.T) {
	srv, _, roots := recordingTarget(t, true, nil)
	cfg := testCfg(t, roots)
	want := []string{"Origin", "X-Target-Authorization"}
	for name, rr := range map[string]*httptest.ResponseRecorder{
		"anonymous":   doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", nil, nil),
		"credentials": doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", credHeader(taBasic, srv.URL), nil),
		"refused":     doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", credHeader("Digest x", srv.URL), nil),
		"bad request": doProxyH(t, cfg, http.MethodGet, "not-a-url", "", nil, nil),
	} {
		if got := rr.Header().Values("Vary"); !slices.Equal(got, want) {
			t.Errorf("%s: Vary %q, want %q", name, got, want)
		}
	}
	// Only /proxy.
	if got := doInspectH(t, cfg, srv.URL+"/", "", nil).Header().Values("Vary"); !slices.Equal(got, []string{"Origin"}) {
		t.Errorf("/inspect Vary %q", got)
	}
	if got := doPageH(t, cfg, srv.URL+"/", "", nil).Header().Values("Vary"); !slices.Equal(got, []string{"Origin"}) {
		t.Errorf("/page Vary %q", got)
	}
}

func TestTargetAuth_NoStoreAndUpstreamCacheControl(t *testing.T) {
	srv, _, roots := recordingTarget(t, true, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cached" {
			w.Header().Set("Cache-Control", "public, max-age=3600")
			w.Header().Set("ETag", `"v1"`)
			w.Header().Set("Expires", "Wed, 01 Jan 2031 00:00:00 GMT")
		}
		io.WriteString(w, "data")
	})
	cfg := testCfg(t, roots)

	rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/cached", "", credHeader(taBasic, srv.URL), nil)
	if got := rr.Header().Values("Cache-Control"); !slices.Equal(got, []string{"no-store"}) {
		t.Errorf("Cache-Control %q, want [no-store]", got)
	}
	if got := rr.Header().Get("X-Upstream-Cache-Control"); got != "public, max-age=3600" {
		t.Errorf("X-Upstream-Cache-Control %q", got)
	}
	if !exposed(rr, "X-Upstream-Cache-Control") || !exposed(rr, "Cache-Control") {
		t.Errorf("expose list %q", rr.Header().Get("Access-Control-Expose-Headers"))
	}
	for _, h := range []string{"ETag", "Expires"} {
		if rr.Header().Get(h) != "" || exposed(rr, h) {
			t.Errorf("%s survived on an authenticated response", h)
		}
	}

	// No upstream Cache-Control: no-store all the same, no X-Upstream-Cache-Control.
	rr = doProxyH(t, cfg, http.MethodGet, srv.URL+"/plain", "", credHeader(taBasic, srv.URL), nil)
	if rr.Header().Get("Cache-Control") != "no-store" || rr.Header().Get("X-Upstream-Cache-Control") != "" ||
		exposed(rr, "X-Upstream-Cache-Control") {
		t.Errorf("without upstream policy: cc %q, upstream %q", rr.Header().Get("Cache-Control"), rr.Header().Get("X-Upstream-Cache-Control"))
	}

	// Anonymous: the target's policy unchanged, as in v1.3.0.
	rr = doProxyH(t, cfg, http.MethodGet, srv.URL+"/cached", "", nil, nil)
	if rr.Header().Get("Cache-Control") != "public, max-age=3600" || rr.Header().Get("ETag") != `"v1"` ||
		rr.Header().Get("X-Upstream-Cache-Control") != "" {
		t.Errorf("anonymous: cc %q etag %q", rr.Header().Get("Cache-Control"), rr.Header().Get("ETag"))
	}
}

func TestTargetAuth_ExposeHeadersOnlyWithAuth(t *testing.T) {
	srv, _, roots := recordingTarget(t, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "max-age=60")
		io.WriteString(w, "x")
	})
	cfg := testCfg(t, roots)
	anon := doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", nil, nil)
	authd := doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", credHeader(taBasic, srv.URL), nil)
	for _, h := range []string{"X-Upstream-Auth", "X-Upstream-Cache-Control"} {
		if exposed(anon, h) || anon.Header().Get(h) != "" {
			t.Errorf("anonymous response lists %s", h)
		}
		if !exposed(authd, h) {
			t.Errorf("authenticated response does not list %s", h)
		}
	}
}

// -----------------------------------------------------------------------
// AUTH-11 Refusals: no upstream contact, fixed order
// -----------------------------------------------------------------------

func TestAuthRefused_NoUpstreamProtocolHeader(t *testing.T) {
	srv, rl, roots := recordingTarget(t, true, nil)
	cfg := testCfg(t, roots)
	plain, plainLog, _ := recordingTarget(t, false, nil)
	cases := []struct {
		reason string
		rr     *httptest.ResponseRecorder
	}{
		{reasonInvalidValue, doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", credHeader("x", srv.URL), nil)},
		{reasonEndpoint, doInspectH(t, cfg, srv.URL+"/", "&diag=1", credHeader(taBasic, srv.URL))},
		{reasonMethod, doProxyH(t, cfg, http.MethodPost, srv.URL+"/", "", credHeader(taBasic, srv.URL), strings.NewReader("x"))},
		{reasonMethodOverride, doProxyH(t, cfg, http.MethodGet, srv.URL+"/?_method=DELETE", "", credHeader(taBasic, srv.URL), nil)},
		{reasonUserinfo, doProxyH(t, cfg, http.MethodGet, withUserinfo(srv.URL, "u:p")+"/", "", credHeader(taBasic, srv.URL), nil)},
		{reasonOriginMismatch, doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", credHeader(taBasic, "https://example.com"), nil)},
		{reasonInsecureScheme, doProxyH(t, cfg, http.MethodGet, plain.URL+"/", "", credHeader(taBasic, plain.URL), nil)},
	}
	// Dial stage of insecure_scheme.
	lcfg, _ := localCfg(t, "wp.test:8080", map[string]string{"wp.test": "93.184.215.14"}, nil)
	cases = append(cases, struct {
		reason string
		rr     *httptest.ResponseRecorder
	}{reasonInsecureScheme, doProxyH(t, lcfg, http.MethodGet, "http://wp.test:8080/", "", credHeader(taBasic, "http://wp.test:8080"), nil)})

	for _, tc := range cases {
		wantAuthRefused(t, tc.rr, tc.reason)
	}
	if rl.count(nil)+plainLog.count(nil) != 0 {
		t.Errorf("targets saw %d requests", rl.count(nil)+plainLog.count(nil))
	}
}

func TestAuthRefused_Order(t *testing.T) {
	srv, rl, roots := recordingTarget(t, true, nil)
	cfg := testCfg(t, roots)
	ui := withUserinfo(srv.URL, "u:p")
	cred := credHeader(taBasic, srv.URL)

	// Each case violates several rules; the earliest one in AUTH-11 wins.
	wantAuthRefused(t, doInspectH(t, cfg, ui+"/?_method=DELETE", "", credHeader("Digest x", srv.URL)), reasonInvalidValue)
	wantAuthRefused(t, doInspectH(t, cfg, ui+"/?_method=DELETE", "", cred), reasonEndpoint)
	wantAuthRefused(t, doProxyH(t, cfg, http.MethodPost, ui+"/?_method=DELETE", "", credHeader(taBasic, "https://example.com"), nil), reasonMethod)
	wantAuthRefused(t, doProxyH(t, cfg, http.MethodGet, ui+"/?_method=DELETE", "", credHeader(taBasic, "https://example.com"), nil), reasonMethodOverride)
	wantAuthRefused(t, doProxyH(t, cfg, http.MethodGet, ui+"/", "", credHeader(taBasic, "https://example.com"), nil), reasonUserinfo)

	// origin_mismatch comes before the SSRF pre-check.
	blocking := testCfg(t, roots)
	blocking.ssrfCheck = func(string) bool { return true }
	wantAuthRefused(t, doProxyH(t, blocking, http.MethodGet, srv.URL+"/", "", credHeader(taBasic, "https://example.com"), nil), reasonOriginMismatch)
	wantBlocked(t, doProxyH(t, blocking, http.MethodGet, srv.URL+"/", "", cred, nil), http.StatusForbidden, reasonPrivate)

	// blocked_target comes before insecure_scheme: the missing allowance is
	// the real problem of http://foo.ddev.site.
	lcfg, _ := localCfg(t, "wp.test", map[string]string{"foo.ddev.site": "127.0.0.1", "wp.test": "127.0.0.1"}, nil)
	wantBlocked(t, doProxyH(t, lcfg, http.MethodGet, "http://foo.ddev.site/", "", credHeader(taBasic, "http://foo.ddev.site"), nil),
		http.StatusForbidden, reasonNotAllowlisted)

	// Origin, method, token and url checks come before any credential rule,
	// so a caller without the token learns nothing about them.
	noToken := httptest.NewRequest(http.MethodGet, "/proxy?url="+url.QueryEscape(srv.URL+"/"), nil)
	noToken.Header.Set("X-Target-Authorization", "Digest x")
	rec := httptest.NewRecorder()
	proxyHandler(cfg, newUpstreamClient(cfg)).ServeHTTP(rec, noToken)
	if pe := decodeProxyError(t, rec); rec.Code != http.StatusForbidden || pe.Error != "forbidden" {
		t.Errorf("without token: %d %+v", rec.Code, pe)
	}
	if rr := doProxyH(t, cfg, http.MethodPut, srv.URL+"/", "", credHeader("Digest x", srv.URL), nil); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %d", rr.Code)
	}
	if rr := doProxyH(t, cfg, http.MethodGet, "ftp://example.com/", "", credHeader("Digest x", srv.URL), nil); decodeProxyError(t, rr).Error != "bad_request" {
		t.Errorf("ftp url: %s", rr.Body.String())
	}
	restricted := testCfg(t, roots)
	restricted.allowedOrigins = []string{"https://test.example.com"}
	hdr := credHeader("Digest x", srv.URL)
	hdr["Origin"] = []string{"https://evil.example"}
	if rr := doProxyH(t, restricted, http.MethodGet, srv.URL+"/", "", hdr, nil); rr.Code != http.StatusForbidden ||
		rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Errorf("foreign origin: %d", rr.Code)
	}

	if rl.count(nil) != 0 {
		t.Errorf("target saw %d requests", rl.count(nil))
	}
}

// -----------------------------------------------------------------------
// AUTH-14 X-Upstream-* only from the proxy
// -----------------------------------------------------------------------

func TestForwardsResponseHeader_DropsUpstreamPrefix(t *testing.T) {
	for _, h := range []string{"x-upstream-auth", "x-upstream-location", "x-upstream-final-url", "x-upstream-cache-control", "x-upstream-",
		// Review I2: the underscore spellings as well.
		"x_upstream_auth", "x_upstream-location", "x-upstream_cache_control"} {
		if forwardsResponseHeader(h, nil) {
			t.Errorf("forwardsResponseHeader(%q) = true", h)
		}
	}
	for _, h := range []string{"x-upstreamish", "x-custom", "content-type", "cache-control"} {
		if !forwardsResponseHeader(h, nil) {
			t.Errorf("forwardsResponseHeader(%q) = false", h)
		}
	}

	srv, _, roots := recordingTarget(t, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Upstream-Auth", "sent")
		w.Header().Set("X-Upstream-Location", "https://evil.example/")
		w.Header().Set("X-Upstream-Cache-Control", "public")
		w.Header().Set("X-Upstream-Redirects", "9")
		// Set directly: Header.Set would canonicalise the names.
		w.Header()["X_Upstream_Auth"] = []string{"sent"}
		w.Header()["x_upstream_location"] = []string{"https://evil.example/"}
		io.WriteString(w, "x")
	})
	cfg := testCfg(t, roots)
	rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", nil, nil)
	for _, h := range []string{"X-Upstream-Auth", "X-Upstream-Location", "X-Upstream-Cache-Control", "X-Upstream-Redirects"} {
		if rr.Header().Get(h) != "" {
			t.Errorf("%s from the target reached the caller: %q", h, rr.Header().Get(h))
		}
	}
	for key := range rr.Header() {
		if strings.HasPrefix(normHeader(key), "x-upstream-auth") || strings.Contains(strings.ToLower(key), "x_upstream") {
			t.Errorf("underscore spelling %q from the target reached the caller", key)
		}
	}
	if ex := rr.Header().Get("Access-Control-Expose-Headers"); strings.Contains(strings.ToLower(ex), "x_upstream") {
		t.Errorf("underscore spelling exposed: %s", ex)
	}
	for _, h := range []string{"X-Upstream-Auth", "X-Upstream-Cache-Control"} {
		if exposed(rr, h) {
			t.Errorf("%s exposed on an anonymous response", h)
		}
	}
	// With credentials the proxy's own values win.
	rr = doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "&follow=1", credHeader(taBasic, srv.URL), nil)
	if rr.Header().Get("X-Upstream-Redirects") != "0" || rr.Header().Get("X-Upstream-Location") != "" ||
		rr.Header().Get("X-Upstream-Cache-Control") != "" || rr.Header().Get("X-Upstream-Auth") != authSent {
		t.Errorf("forged metadata with credentials: %v", rr.Header())
	}
}

// TestForwardsResponseHeader_DropsProxyNamespace pins review I3 as intended
// behaviour: the proxy's own request headers (X-Proxy-Token since v1.3.0,
// X-Target-Authorization and X-Target-Origin since v1.4.0) are hop-by-hop, so
// a target that sends them back does not get them to the caller either —
// with and without credentials. Documented with difference 6 (README
// changelog); it only changes what a hostile or odd target can send.
func TestForwardsResponseHeader_DropsProxyNamespace(t *testing.T) {
	srv, _, roots := recordingTarget(t, true, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Proxy-Token", "t")
		w.Header().Set("X-Target-Authorization", "Basic eDp5")
		w.Header().Set("X-Target-Origin", "https://evil.example")
		w.Header().Set("X-Custom", "kept")
		io.WriteString(w, "x")
	})
	cfg := testCfg(t, roots)
	for _, hdr := range []http.Header{nil, credHeader(taBasic, srv.URL)} {
		rr := doProxyH(t, cfg, http.MethodGet, srv.URL+"/", "", hdr, nil)
		for _, h := range []string{"X-Proxy-Token", "X-Target-Authorization", "X-Target-Origin"} {
			if rr.Header().Get(h) != "" || exposed(rr, h) {
				t.Errorf("credentials %t: %s from the target reached the caller", hdr != nil, h)
			}
		}
		if hdr == nil && rr.Header().Get("X-Custom") != "kept" {
			t.Errorf("anonymous: X-Custom dropped: %v", rr.Header())
		}
	}
}

// -----------------------------------------------------------------------
// LOG-1 / LOG-2 Never logged or echoed
// -----------------------------------------------------------------------

func TestTargetAuth_NeverLoggedOrEchoed(t *testing.T) {
	logs := captureLog(t)
	secrets := []string{"PLACEHOLDER", "dGVzdHVzZXI6UExBQ0VIT0xERVI=", "dGVzdHVzZXI", "testuser"}

	ok, _, roots := recordingTarget(t, true, nil)
	other, _, _ := recordingTarget(t, true, nil)
	roots.AddCert(other.Certificate())
	cross, _, _ := recordingTarget(t, true, redirectTo(other.URL+"/"))
	roots.AddCert(cross.Certificate())
	slow, _, _ := recordingTarget(t, true, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	})
	roots.AddCert(slow.Certificate())
	untrusted := selfSignedServer(t)
	plainOK, _, _ := recordingTarget(t, false, nil)
	plainCross, _, _ := recordingTarget(t, false, redirectTo(other.URL+"/"))
	plainSlow, _, _ := recordingTarget(t, false, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
	})

	cfg := testCfg(t, roots)
	cfg.requestTimeout = 300 * time.Millisecond
	blockedCfg := testCfg(t, roots)
	blockedCfg.ssrfCheck = func(string) bool { return true }
	dialerCfg := testCfg(t, roots)
	dialerCfg.dialControl = nil // safeDialControl: loopback is blocked in the dialer
	localCfgHTTP, _ := localCfg(t, "wp.test:8080", map[string]string{"wp.test": "93.184.215.14"}, nil)

	h := func(u string) http.Header { return credHeader(taPlaceholder, u) }
	ui := func(u string) string { return withUserinfo(u, "testuser:PLACEHOLDER") }
	var out []*httptest.ResponseRecorder
	add := func(rr *httptest.ResponseRecorder) { out = append(out, rr) }

	// Header credentials, every path.
	add(doProxyH(t, cfg, http.MethodGet, ok.URL+"/", "", credHeader(taPlaceholder+" PLACEHOLDER", ok.URL), nil))
	add(doProxyH(t, cfg, http.MethodGet, ok.URL+"/", "", credHeader("Basic dGVzdHVzZXI6UExBQ0VIT0xERVI=\x00", ok.URL), nil))
	add(doProxyH(t, cfg, http.MethodPost, ok.URL+"/", "", h(ok.URL), strings.NewReader("x")))
	add(doInspectH(t, cfg, ok.URL+"/", "&diag=1", h(ok.URL)))
	add(doPageH(t, cfg, ok.URL+"/", "&diag=1", h(ok.URL)))
	add(doProxyH(t, cfg, http.MethodGet, cross.URL+"/", "&follow=1", h(cross.URL), nil))
	add(doProxyH(t, cfg, http.MethodGet, ok.URL+"/?_method=DELETE", "", h(ok.URL), nil))
	add(doProxyH(t, cfg, http.MethodGet, slow.URL+"/", "", h(slow.URL), nil))
	add(doProxyH(t, testCfg(t, x509.NewCertPool()), http.MethodGet, untrusted.URL+"/", "", h(untrusted.URL), nil))
	add(doProxyH(t, blockedCfg, http.MethodGet, ok.URL+"/", "", h(ok.URL), nil))
	add(doProxyH(t, dialerCfg, http.MethodGet, ok.URL+"/", "", h(ok.URL), nil))
	add(doProxyH(t, cfg, http.MethodGet, plainOK.URL+"/", "", h(plainOK.URL), nil))
	add(doProxyH(t, localCfgHTTP, http.MethodGet, "http://wp.test:8080/", "", h("http://wp.test:8080"), nil))
	add(doProxyH(t, cfg, http.MethodGet, ok.URL+"/", "&follow=1", h(ok.URL), nil))
	add(doProxyH(t, cfg, http.MethodGet, ok.URL+"/", "", h("https://example.com"), nil))
	add(doProxyH(t, cfg, http.MethodGet, ui(ok.URL)+"/", "", h(ok.URL), nil))

	// Userinfo instead of the header, the same paths.
	add(doProxyH(t, cfg, http.MethodPost, ui(plainOK.URL)+"/", "", nil, strings.NewReader("x")))
	add(doInspectH(t, cfg, ui(plainOK.URL)+"/", "&diag=1&body=1", nil))
	add(doPageH(t, cfg, ui(plainOK.URL)+"/", "&diag=1", nil))
	add(doProxyH(t, cfg, http.MethodGet, ui(plainCross.URL)+"/", "&follow=1", nil, nil))
	add(doPageH(t, cfg, ui(plainCross.URL)+"/", "&diag=1", nil))
	add(doProxyH(t, cfg, http.MethodGet, ui(plainOK.URL)+"/?_method=DELETE", "", nil, nil))
	add(doProxyH(t, cfg, http.MethodGet, ui(plainSlow.URL)+"/", "", nil, nil))
	add(doInspectH(t, cfg, ui(plainSlow.URL)+"/", "&diag=1", nil))
	add(doPageH(t, cfg, ui(plainSlow.URL)+"/", "&diag=1", nil))
	add(doProxyH(t, testCfg(t, x509.NewCertPool()), http.MethodGet, ui(untrusted.URL)+"/", "", nil, nil))
	add(doInspectH(t, testCfg(t, x509.NewCertPool()), ui(untrusted.URL)+"/", "&diag=1", nil))
	add(doPageH(t, testCfg(t, x509.NewCertPool()), ui(untrusted.URL)+"/", "&diag=1", nil))
	add(doProxyH(t, blockedCfg, http.MethodGet, ui(ok.URL)+"/", "", nil, nil))
	add(doProxyH(t, dialerCfg, http.MethodGet, ui(plainOK.URL)+"/", "", nil, nil))
	add(doPageH(t, dialerCfg, ui(plainOK.URL)+"/", "&diag=1", nil))
	add(doProxyH(t, cfg, http.MethodGet, ui(plainOK.URL)+"/", "&follow=1", nil, nil))
	add(doProxyH(t, cfg, http.MethodGet, ui(strings.TrimSuffix(closedPortURL(t), "/"))+"/", "", nil, nil))

	// Make sure the paths really ran: a few spot checks.
	codes := map[string]bool{}
	for _, rr := range out {
		if rr.Code >= 400 {
			if pe := decodeProxyError(t, rr); pe.Error != "" {
				codes[pe.Error] = true
			}
		}
	}
	for _, want := range []string{"auth_refused", "timeout", "tls_error", "blocked_target", "connection_error"} {
		if !codes[want] {
			t.Errorf("no %s among the triggered paths: %v", want, codes)
		}
	}

	all := []string{logs.String()}
	for _, rr := range out {
		all = append(all, dump(rr))
	}
	for _, s := range all {
		for _, secret := range secrets {
			if strings.Contains(s, secret) {
				t.Errorf("%q leaked:\n%s", secret, s)
			}
		}
	}
	if !strings.Contains(logs.String(), "upstream error") {
		t.Error("no upstream error was logged — the log capture did not work")
	}
}

// -----------------------------------------------------------------------
// Small units
// -----------------------------------------------------------------------

func TestNormHeader(t *testing.T) {
	for in, want := range map[string]string{
		"X_Proxy_Token":          "x-proxy-token",
		"X-TARGET-AUTHORIZATION": "x-target-authorization",
		"x_http_method_override": "x-http-method-override",
		"Accept":                 "accept",
	} {
		if got := normHeader(in); got != want {
			t.Errorf("normHeader(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCopyRequestHeaders_UnderscoreAndCredentialHeaders(t *testing.T) {
	src := httptest.NewRequest(http.MethodGet, "/proxy?url=https://example.com", nil)
	for k, v := range map[string]string{
		"X-Target-Authorization": taBasic,
		"X-Target-Origin":        "https://example.com",
		"X_Proxy_Token":          "token",
		"X_Target_Authorization": taBasic,
		"X_TARGET_ORIGIN":        "https://example.com",
		"Sec_Fetch_Site":         "cross-site",
		"Cookie_":                "kept: not a known name",
		"Connection":             "X_Hop",
		"X-Hop":                  "connection-listed",
	} {
		src.Header[k] = []string{v}
	}
	dst := httptest.NewRequest(http.MethodGet, "https://example.com", nil)
	dst.Header = http.Header{}
	copyRequestHeaders(src, dst)
	for k := range dst.Header {
		switch normHeader(k) {
		case "x-target-authorization", "x-target-origin", "x-proxy-token", "sec-fetch-site", "x-hop", "connection":
			t.Errorf("%s reached the upstream request", k)
		}
	}
	if dst.Header.Get("Authorization") != "" {
		t.Error("Authorization set without credentials on the context")
	}
}

func TestVaryTargetAuthWriter_ImplicitWriteHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	w := &varyTargetAuthWriter{ResponseWriter: rr}
	w.Header().Add("Vary", "Origin")
	w.Write([]byte("x"))
	w.WriteHeader(http.StatusTeapot) // superfluous, must not add a second Vary
	if got := rr.Header().Values("Vary"); !slices.Equal(got, []string{"Origin", "X-Target-Authorization"}) {
		t.Errorf("Vary %q", got)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("status %d", rr.Code)
	}
}
