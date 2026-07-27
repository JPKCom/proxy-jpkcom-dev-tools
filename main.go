// localproxy - A secure local HTTPS proxy for browser-based online tools.
//
// This proxy runs on localhost only, validates request origins against an
// allowlist, and forwards HTTP/HTTPS requests to external URLs — bypassing
// browser CORS restrictions safely.
//
// Usage:
//
//	./localproxy [--port 8765] [--origin https://yourtool.example.com]
package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

// Version is set at build time via -ldflags "-X main.Version=...".
// Local builds show "dev"; release builds get the git tag (e.g. "v1.0.5").
var Version = "dev"

const (
	Author    = "Jean Pierre Kolb"
	AuthorURL = "https://www.jpkc.com/"
	RepoURL   = "https://github.com/JPKCom/proxy-jpkcom-dev-tools"
	License   = "GPL-2.0-or-later"
)

// -----------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------

// config holds all runtime configuration for the proxy.
type config struct {
	// port is the TCP port the proxy listens on (localhost only).
	port int

	// allowedOrigins is the list of Origins (scheme+host) permitted to use
	// the proxy. An empty list disables the origin check (dev mode only).
	allowedOrigins []string

	// sessionToken is a random hex string generated at startup that every
	// request must supply via the X-Proxy-Token header.
	sessionToken string

	// requestTimeout is the maximum time allowed for a proxied request.
	requestTimeout time.Duration

	// maxResponseBytes caps how many bytes are read from the upstream response.
	// 0 means unlimited (not recommended for production).
	maxResponseBytes int64

	// ssrfCheck is the function used to determine whether a hostname resolves
	// to a blocked address. Defaults to isPrivateHost in production; tests may
	// override it with a no-op to allow localhost targets.
	//
	// This is only a fast pre-flight rejection — it is NOT the security
	// boundary. Because the resolution it performs is separate from the one
	// the HTTP transport performs, it is inherently vulnerable to DNS
	// rebinding. The authoritative check runs in the dialer (safeDialControl),
	// which sees the actual IP being connected to.
	ssrfCheck func(string) bool

	// resolver is the DNS resolver used for upstream lookups and SSRF checks.
	// nil means net.DefaultResolver (system DNS).
	resolver *net.Resolver

	// allowAnyHost disables the Host-header check that normally restricts the
	// proxy to being addressed as localhost. Escape hatch for exotic setups.
	allowAnyHost bool
}

// blocksHost reports whether the target hostname should be rejected before any
// connection is attempted. It is a convenience wrapper around the configured
// ssrfCheck, defaulting to a DNS-based private-range lookup.
func (c *config) blocksHost(ctx context.Context, hostname string) bool {
	if c.ssrfCheck != nil {
		return c.ssrfCheck(hostname)
	}
	return isPrivateHost(ctx, hostname, c.resolver)
}

// tokenValid compares the request's X-Proxy-Token against the session token in
// constant time, so a caller cannot recover the token byte-by-byte by timing
// the comparison.
func (c *config) tokenValid(r *http.Request) bool {
	got := []byte(r.Header.Get("X-Proxy-Token"))
	want := []byte(c.sessionToken)
	return subtle.ConstantTimeCompare(got, want) == 1
}

// pageBudget is the overall wall-clock cap for a single /page request. That
// endpoint performs several upstream requests (one HEAD per redirect hop, a
// HEAD encoding probe and the final GET), so it needs more headroom than a
// single request — but it must still be bounded, or a target serving slow
// redirects could pin a goroutine and a connection for many minutes.
func (c *config) pageBudget() time.Duration {
	return 3 * c.requestTimeout
}

// -----------------------------------------------------------------------
// Token generation
// -----------------------------------------------------------------------

// generateToken creates a cryptographically random hex token of the given
// byte length (returned as a hex string of length byteLen*2).
func generateToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("token generation failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// -----------------------------------------------------------------------
// JSON error responses
// -----------------------------------------------------------------------

// proxyError is the JSON structure returned to the client on upstream failures.
type proxyError struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Status  int    `json:"status"`
}

// writeJSONError writes a categorized JSON error response with CORS headers.
//
// CORS matters here: without the headers the browser rejects the response
// before JavaScript can look at it, so the caller cannot tell "wrong token"
// apart from "proxy not running" — both surface as an opaque TypeError.
func writeJSONError(w http.ResponseWriter, r *http.Request, cfg *config, code string, message string, status int) {
	writeCORSHeaders(w, r, cfg)
	writeJSON(w, status, proxyError{Error: code, Message: message, Status: status})
}

// writeJSON serialises v as the response body. Encoding errors can only surface
// after the status line is committed, so they are logged rather than returned.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("warn: could not encode JSON response: %v", err)
	}
}

// -----------------------------------------------------------------------
// Shared handler preamble
// -----------------------------------------------------------------------

// authorizeRequest runs the checks every authenticated endpoint shares: method,
// CORS preflight, origin, token, target URL and the SSRF pre-check.
//
// It returns the parsed target and true when the caller should proceed. When it
// returns false it has already written the complete response — including the
// 204 for a preflight — and the caller must return immediately.
func authorizeRequest(w http.ResponseWriter, r *http.Request, cfg *config, allowedMethods ...string) (*url.URL, bool) {
	if r.Method == http.MethodOptions {
		writeCORSHeaders(w, r, cfg)
		w.WriteHeader(http.StatusNoContent)
		return nil, false
	}

	// The origin check comes before the method check so that a disallowed
	// origin learns nothing about which methods an endpoint accepts.
	if !isOriginAllowed(r.Header.Get("Origin"), cfg.allowedOrigins) {
		// Deliberately plain text and without CORS headers: this response is
		// not meant to be readable by the origin that was just rejected.
		http.Error(w, "forbidden: origin not allowed", http.StatusForbidden)
		return nil, false
	}

	if !slices.Contains(allowedMethods, r.Method) {
		w.Header().Set("Allow", strings.Join(allowedMethods, ", "))
		writeJSONError(w, r, cfg, "method_not_allowed", "method not allowed on this endpoint", http.StatusMethodNotAllowed)
		return nil, false
	}

	if !cfg.tokenValid(r) {
		writeJSONError(w, r, cfg, "forbidden", "invalid or missing proxy token", http.StatusForbidden)
		return nil, false
	}

	rawTarget := r.URL.Query().Get("url")
	if rawTarget == "" {
		writeJSONError(w, r, cfg, "bad_request", "missing 'url' query parameter", http.StatusBadRequest)
		return nil, false
	}

	target, err := url.ParseRequestURI(rawTarget)
	if err != nil || (target.Scheme != "https" && target.Scheme != "http") {
		writeJSONError(w, r, cfg, "bad_request", "'url' must be a valid http/https URL", http.StatusBadRequest)
		return nil, false
	}

	if cfg.blocksHost(r.Context(), target.Hostname()) {
		writeJSONError(w, r, cfg, "blocked_target", "target resolves to a private or reserved address", http.StatusForbidden)
		return nil, false
	}

	return target, true
}

// classifyUpstreamError inspects the error chain from an upstream request and
// returns an error code and a safe, human-readable message.
func classifyUpstreamError(err error) (code string, message string) {
	// Blocked by the dialer's SSRF guard. Checked first: this arrives wrapped
	// in a *net.OpError, which would otherwise be reported as a mere
	// connection failure and hide the real reason from the caller.
	if errors.Is(err, errBlockedTarget) {
		return "blocked_target", "target resolves to a private or reserved address"
	}

	// DNS resolution failure.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns_error", "could not resolve hostname"
	}

	// TLS certificate verification errors.
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "tls_error", "TLS certificate verification failed"
	}
	var unknownAuthErr x509.UnknownAuthorityError
	if errors.As(err, &unknownAuthErr) {
		return "tls_error", "TLS certificate signed by unknown authority"
	}
	var certInvalidErr x509.CertificateInvalidError
	if errors.As(err, &certInvalidErr) {
		return "tls_error", "TLS certificate invalid"
	}
	var hostnameErr x509.HostnameError
	if errors.As(err, &hostnameErr) {
		return "tls_error", "TLS certificate hostname mismatch"
	}

	// Connection refused / unreachable.
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "connection_error", "could not connect to upstream host"
	}

	return "upstream_error", "upstream request failed"
}

// -----------------------------------------------------------------------
// Connection tracing
// -----------------------------------------------------------------------

// connTrace captures connection-level metadata via httptrace hooks.
type connTrace struct {
	mu           sync.Mutex
	dnsStart     time.Time
	dnsDone      time.Time
	connectStart time.Time
	connectDone  time.Time
	tlsStart     time.Time
	tlsDone      time.Time
	gotFirstByte time.Time
	remoteAddr   string // "ip:port" from ConnectDone
}

// attach returns a context instrumented with httptrace hooks that populate ct.
func (ct *connTrace) attach(ctx context.Context) context.Context {
	return httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) {
			ct.mu.Lock()
			ct.dnsStart = time.Now()
			ct.mu.Unlock()
		},
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			ct.mu.Lock()
			ct.dnsDone = time.Now()
			ct.mu.Unlock()
		},
		ConnectStart: func(_, _ string) {
			ct.mu.Lock()
			ct.connectStart = time.Now()
			ct.mu.Unlock()
		},
		ConnectDone: func(_, addr string, _ error) {
			ct.mu.Lock()
			ct.connectDone = time.Now()
			ct.remoteAddr = addr
			ct.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			ct.mu.Lock()
			ct.tlsStart = time.Now()
			ct.mu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			ct.mu.Lock()
			ct.tlsDone = time.Now()
			ct.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			ct.mu.Lock()
			ct.gotFirstByte = time.Now()
			ct.mu.Unlock()
		},
	})
}

// timingHeader returns a semicolon-delimited timing string, e.g.
// "dns=12;tcp=45;ssl=23;ttfb=156;total=234" (values in ms).
func (ct *connTrace) timingHeader(requestStart time.Time) string {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	ms := func(d time.Duration) int64 {
		return int64(math.Round(float64(d.Microseconds()) / 1000.0))
	}

	var dns, tcp, ssl, ttfb int64
	if !ct.dnsStart.IsZero() && !ct.dnsDone.IsZero() {
		dns = ms(ct.dnsDone.Sub(ct.dnsStart))
	}
	if !ct.connectStart.IsZero() && !ct.connectDone.IsZero() {
		tcp = ms(ct.connectDone.Sub(ct.connectStart))
	}
	if !ct.tlsStart.IsZero() && !ct.tlsDone.IsZero() {
		ssl = ms(ct.tlsDone.Sub(ct.tlsStart))
	}
	total := ms(time.Since(requestStart))
	if !ct.gotFirstByte.IsZero() {
		ttfb = ms(ct.gotFirstByte.Sub(requestStart))
	}

	return fmt.Sprintf("dns=%d;tcp=%d;ssl=%d;ttfb=%d;total=%d", dns, tcp, ssl, ttfb, total)
}

// timingMap returns a map of timing values in milliseconds (1 decimal precision).
func (ct *connTrace) timingMap(requestStart time.Time) map[string]float64 {
	ct.mu.Lock()
	defer ct.mu.Unlock()

	msf := func(d time.Duration) float64 {
		return math.Round(float64(d.Microseconds())/100.0) / 10.0
	}

	m := make(map[string]float64)
	if !ct.dnsStart.IsZero() && !ct.dnsDone.IsZero() {
		m["dnsLookup"] = msf(ct.dnsDone.Sub(ct.dnsStart))
	} else {
		m["dnsLookup"] = 0
	}
	if !ct.connectStart.IsZero() && !ct.connectDone.IsZero() {
		m["tcpConnect"] = msf(ct.connectDone.Sub(ct.connectStart))
	} else {
		m["tcpConnect"] = 0
	}
	if !ct.tlsStart.IsZero() && !ct.tlsDone.IsZero() {
		m["sslHandshake"] = msf(ct.tlsDone.Sub(ct.tlsStart))
	} else {
		m["sslHandshake"] = 0
	}
	if !ct.gotFirstByte.IsZero() {
		m["ttfb"] = msf(ct.gotFirstByte.Sub(requestStart))
	} else {
		m["ttfb"] = 0
	}
	m["total"] = msf(time.Since(requestStart))
	return m
}

// remoteIP extracts just the IP from the captured "ip:port" address.
func (ct *connTrace) remoteIP() string {
	ct.mu.Lock()
	defer ct.mu.Unlock()
	if ct.remoteAddr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(ct.remoteAddr)
	if err != nil {
		return ct.remoteAddr
	}
	return host
}

// -----------------------------------------------------------------------
// HTTP handler
// -----------------------------------------------------------------------

// proxyHandler returns an http.Handler that validates requests and forwards
// them to the upstream URL supplied in the "url" query parameter.
func proxyHandler(cfg *config, client *http.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// ------------------------------------------------------------------
		// 1.-4. Method, CORS preflight, origin, token, target URL, SSRF.
		// ------------------------------------------------------------------
		target, ok := authorizeRequest(w, r, cfg,
			http.MethodGet, http.MethodHead, http.MethodPost)
		if !ok {
			return
		}

		// ------------------------------------------------------------------
		// 5. Build the upstream request with connection tracing.
		// ------------------------------------------------------------------
		ctx, cancel := context.WithTimeout(r.Context(), cfg.requestTimeout)
		defer cancel()

		ct := &connTrace{}
		requestStart := time.Now()
		ctx = ct.attach(ctx)

		var bodyReader io.Reader
		if r.Method == http.MethodPost {
			bodyReader = r.Body
		}

		upstreamReq, err := http.NewRequestWithContext(ctx, r.Method, target.String(), bodyReader)
		if err != nil {
			writeJSONError(w, r, cfg, "upstream_error", "could not build upstream request", http.StatusInternalServerError)
			return
		}

		// Forward safe request headers, strip hop-by-hop and proxy-specific ones.
		copyRequestHeaders(r, upstreamReq)

		// ------------------------------------------------------------------
		// 6. Execute the upstream request.
		// ------------------------------------------------------------------
		resp, err := client.Do(upstreamReq)
		if err != nil {
			log.Printf("upstream error: %v", err)
			if ctx.Err() == context.DeadlineExceeded {
				writeJSONError(w, r, cfg, "timeout", "upstream request timed out", http.StatusGatewayTimeout)
				return
			}
			code, message := classifyUpstreamError(err)
			writeJSONError(w, r, cfg, code, message, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// ------------------------------------------------------------------
		// 7. Write CORS headers + upstream response headers to the client.
		// ------------------------------------------------------------------
		writeCORSHeaders(w, r, cfg)
		copyResponseHeaders(resp, w)

		// Upstream metadata headers (timing, IP, protocol, content info).
		w.Header().Set("X-Upstream-Protocol", resp.Proto)
		if ip := ct.remoteIP(); ip != "" {
			w.Header().Set("X-Upstream-IP", ip)
		}
		w.Header().Set("X-Upstream-Timing", ct.timingHeader(requestStart))
		if ce := resp.Header.Get("Content-Encoding"); ce != "" {
			w.Header().Set("X-Upstream-Content-Encoding", ce)
		}
		// Build explicit Access-Control-Expose-Headers from all response
		// headers (wildcard "*" doesn't work with specific origins per spec).
		exposeSet := make(map[string]struct{})
		for key := range resp.Header {
			if _, skip := hopByHopHeaders[strings.ToLower(key)]; !skip {
				exposeSet[key] = struct{}{}
			}
		}
		// Include our custom metadata headers.
		for _, h := range []string{
			"X-Upstream-Protocol", "X-Upstream-IP", "X-Upstream-Timing",
			"X-Upstream-Content-Encoding", "X-Upstream-Content-Length",
			"X-Upstream-Truncated",
		} {
			exposeSet[h] = struct{}{}
		}
		exposeKeys := make([]string, 0, len(exposeSet))
		for k := range exposeSet {
			exposeKeys = append(exposeKeys, k)
		}
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(exposeKeys, ", "))
		w.Header().Set("X-Content-Type-Options", "nosniff")

		cl := resp.Header.Get("Content-Length")
		ce := resp.Header.Get("Content-Encoding")

		// ------------------------------------------------------------------
		// 8. Stream the response body (capped at maxResponseBytes if set).
		//    When Content-Length is missing but the response is compressed
		//    (chunked + Content-Encoding), buffer to count the transfer size.
		//    This is safe because the body is already capped at maxResponseBytes.
		// ------------------------------------------------------------------
		var bodySource io.Reader = resp.Body
		if cfg.maxResponseBytes > 0 {
			bodySource = io.LimitReader(resp.Body, cfg.maxResponseBytes)
		}

		if cl != "" {
			// Known size — report it as upstream metadata either way.
			w.Header().Set("X-Upstream-Content-Length", cl)

			// If the upstream body is larger than the cap we are about to
			// truncate it. Forwarding the original Content-Length would then
			// promise more bytes than we deliver: net/http detects the short
			// write and kills the connection, so the caller sees a generic
			// network error instead of a truncated body. Drop the header (the
			// response becomes chunked) and say so explicitly.
			if n, convErr := strconv.ParseInt(cl, 10, 64); convErr == nil &&
				cfg.maxResponseBytes > 0 && n > cfg.maxResponseBytes {
				w.Header().Del("Content-Length")
				w.Header().Set("X-Upstream-Truncated", "1")
				log.Printf("warn: upstream body of %d bytes truncated to %d", n, cfg.maxResponseBytes)
			}

			w.WriteHeader(resp.StatusCode)
			if _, err := io.Copy(w, bodySource); err != nil {
				log.Printf("warn: error streaming response body: %v", err)
			}
		} else if ce != "" {
			// Compressed but chunked — buffer to count transfer size.
			bodyBytes, err := io.ReadAll(bodySource)
			if err != nil {
				log.Printf("warn: error buffering response body: %v", err)
			}
			w.Header().Set("X-Upstream-Content-Length", strconv.Itoa(len(bodyBytes)))
			w.WriteHeader(resp.StatusCode)
			if _, err := w.Write(bodyBytes); err != nil {
				log.Printf("warn: error writing response body: %v", err)
			}
		} else {
			// No compression, no Content-Length — just stream.
			w.WriteHeader(resp.StatusCode)
			if _, err := io.Copy(w, bodySource); err != nil {
				log.Printf("warn: error streaming response body: %v", err)
			}
		}
	})
}

// -----------------------------------------------------------------------
// /inspect endpoint — returns connection metadata as JSON
// -----------------------------------------------------------------------

// inspectResponse is the JSON envelope returned by the /inspect endpoint.
//
// Headers preserves multi-valued response headers as JSON arrays — required
// for RFC 6265 §3 compliant Set-Cookie handling, where joining multiple
// values with ", " produces an unparseable string (cookie expiry dates
// contain literal commas, indistinguishable from the join separator).
type inspectResponse struct {
	Status   int                 `json:"status"`
	Headers  map[string][]string `json:"headers"`
	SSL      *sslInfo            `json:"ssl"`
	Timing   map[string]float64  `json:"timing"`
	IP       string              `json:"ip"`
	Protocol string              `json:"protocol"`
	// HTTP3 reports whether the target advertises HTTP/3 via Alt-Svc. It says
	// nothing about the protocol this request used — that is Protocol.
	HTTP3 bool   `json:"http3"`
	Body  string `json:"body,omitempty"`
}

// sslInfo holds TLS certificate details extracted from the connection.
type sslInfo struct {
	Version            string      `json:"version"`
	Subject            string      `json:"subject"`
	Issuer             string      `json:"issuer"`
	IssuerOrg          string      `json:"issuerOrg"`
	Organization       string      `json:"organization"`
	ValidFrom          string      `json:"validFrom"`
	ValidTo            string      `json:"validTo"`
	DaysLeft           int         `json:"daysLeft"`
	SANs               []string    `json:"sans"`
	Chain              []chainLink `json:"chain"`
	SignatureAlgorithm string      `json:"signatureAlgorithm"`
	PublicKeyAlgorithm string      `json:"publicKeyAlgorithm"`
}

// chainLink represents one certificate in the chain.
type chainLink struct {
	Subject string `json:"subject"`
	Issuer  string `json:"issuer"`
}

// tlsVersionName maps tls.Version* constants to human-readable names.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("TLS 0x%04x", v)
	}
}

// extractSSLInfo builds an sslInfo struct from the TLS connection state.
func extractSSLInfo(state *tls.ConnectionState) *sslInfo {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}

	leaf := state.PeerCertificates[0]

	org := ""
	if len(leaf.Subject.Organization) > 0 {
		org = leaf.Subject.Organization[0]
	}
	issuerOrg := ""
	if len(leaf.Issuer.Organization) > 0 {
		issuerOrg = leaf.Issuer.Organization[0]
	}

	daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)

	// SANs cover DNS names and IP addresses; a certificate issued only for an
	// IP would otherwise report an empty SAN list.
	sans := make([]string, 0, len(leaf.DNSNames)+len(leaf.IPAddresses))
	sans = append(sans, leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		sans = append(sans, ip.String())
	}

	chain := make([]chainLink, 0, len(state.PeerCertificates))
	for _, cert := range state.PeerCertificates {
		chain = append(chain, chainLink{
			Subject: cert.Subject.CommonName,
			Issuer:  cert.Issuer.CommonName,
		})
	}

	return &sslInfo{
		Version:            tlsVersionName(state.Version),
		Subject:            leaf.Subject.CommonName,
		Issuer:             leaf.Issuer.CommonName,
		IssuerOrg:          issuerOrg,
		Organization:       org,
		ValidFrom:          leaf.NotBefore.UTC().Format(time.RFC3339),
		ValidTo:            leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft:           daysLeft,
		SANs:               sans,
		Chain:              chain,
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: leaf.PublicKeyAlgorithm.String(),
	}
}

// inspectHandler returns an http.Handler that performs a request to the
// target URL and returns connection metadata (SSL, timing, headers, IP,
// protocol) as a JSON response. The response body is included when the
// "body" query parameter is set to "1".
func inspectHandler(cfg *config, client *http.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		target, ok := authorizeRequest(w, r, cfg, http.MethodGet, http.MethodHead)
		if !ok {
			return
		}

		// Build traced request.
		ctx, cancel := context.WithTimeout(r.Context(), cfg.requestTimeout)
		defer cancel()

		ct := &connTrace{}
		requestStart := time.Now()
		ctx = ct.attach(ctx)

		// Use GET if body requested, HEAD otherwise — to get full connection info.
		method := http.MethodHead
		includeBody := r.URL.Query().Get("body") == "1"
		if includeBody {
			method = http.MethodGet
		}

		// When body=1, we need two pieces of information:
		// 1. The server's true preferred Content-Encoding (may be zstd, br, etc.)
		// 2. A decompressed body (only gzip/deflate possible with stdlib)
		//
		// Strategy: send a HEAD request first with the browser's full
		// Accept-Encoding to discover the server's preferred encoding,
		// then send the GET with Accept-Encoding limited to gzip/deflate
		// so we can decompress the body. The HEAD-detected encoding is
		// restored in the final header map.
		var serverContentEncoding string
		if includeBody {
			headReq, err := http.NewRequestWithContext(ctx, http.MethodHead, target.String(), nil)
			if err != nil {
				writeJSONError(w, r, cfg, "upstream_error", "could not build upstream request", http.StatusInternalServerError)
				return
			}
			copyRequestHeaders(r, headReq)
			headResp, err := client.Do(headReq)
			if err == nil {
				serverContentEncoding = headResp.Header.Get("Content-Encoding")
				headResp.Body.Close()
			}
			// On HEAD failure, we continue — the GET below will report the error.
		}

		upstreamReq, err := http.NewRequestWithContext(ctx, method, target.String(), nil)
		if err != nil {
			writeJSONError(w, r, cfg, "upstream_error", "could not build upstream request", http.StatusInternalServerError)
			return
		}
		copyRequestHeaders(r, upstreamReq)

		// For body requests, limit Accept-Encoding to what stdlib can
		// decompress (gzip, deflate). This prevents garbled bytes in the
		// JSON response while still allowing the body to be read as text.
		if includeBody {
			upstreamReq.Header.Set("Accept-Encoding", "gzip, deflate")
		}

		resp, err := client.Do(upstreamReq)
		if err != nil {
			log.Printf("inspect upstream error: %v", err)
			if ctx.Err() == context.DeadlineExceeded {
				writeJSONError(w, r, cfg, "timeout", "upstream request timed out", http.StatusGatewayTimeout)
				return
			}
			code, message := classifyUpstreamError(err)
			writeJSONError(w, r, cfg, code, message, http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// Build timing map (milliseconds as floats, 1 decimal).
		timingMap := ct.timingMap(requestStart)

		// Collect response headers, preserving multi-valued headers as slices.
		// Set-Cookie in particular MUST NOT be joined: cookie expiry dates
		// contain literal commas, indistinguishable from a "," separator (RFC 6265 §3).
		hdrs := make(map[string][]string, len(resp.Header))
		for k, v := range resp.Header {
			hdrs[k] = v
		}

		// Restore the server's true Content-Encoding from the HEAD probe.
		// The GET response may show "gzip" because we limited Accept-Encoding,
		// but the HEAD reveals the server's actual preferred encoding (e.g. zstd, br).
		if serverContentEncoding != "" {
			hdrs["Content-Encoding"] = []string{serverContentEncoding}
		}

		// Read body if requested, decompressing based on Content-Encoding.
		var body string
		if includeBody {
			var bodySource io.Reader = resp.Body
			if cfg.maxResponseBytes > 0 {
				bodySource = io.LimitReader(resp.Body, cfg.maxResponseBytes)
			}

			// Decompress based on actual GET response encoding (gzip/deflate via stdlib).
			if dec, err := newDecompressor(bodySource, resp.Header.Get("Content-Encoding")); err != nil {
				log.Printf("warn: could not decompress inspect body: %v", err)
			} else if dec != nil {
				defer dec.Close()
				bodySource = dec
			}

			// Cap the decompressed stream too — guards against zip-bomb-style
			// payloads where a small compressed body expands to gigabytes.
			if cfg.maxResponseBytes > 0 {
				bodySource = io.LimitReader(bodySource, cfg.maxResponseBytes)
			}

			bodyBytes, err := io.ReadAll(bodySource)
			if err != nil {
				log.Printf("warn: error reading inspect body: %v", err)
			}
			body = string(bodyBytes)
		}

		result := inspectResponse{
			Status:   resp.StatusCode,
			Headers:  hdrs,
			SSL:      extractSSLInfo(resp.TLS),
			Timing:   timingMap,
			IP:       ct.remoteIP(),
			Protocol: resp.Proto,
			HTTP3:    altSvcAdvertisesHTTP3(resp.Header),
			Body:     body,
		}

		writeCORSHeaders(w, r, cfg)
		writeJSON(w, http.StatusOK, result)
	})
}

// -----------------------------------------------------------------------
// HTTP/3 detection
// -----------------------------------------------------------------------

// altSvcAdvertisesHTTP3 reports whether the response advertises HTTP/3.
//
// No QUIC stack is needed for this: HTTP/3 is discovered over TCP by design.
// A server announces it with an Alt-Svc field on its HTTP/1.1 or HTTP/2
// response (RFC 7838), which is exactly what this proxy already receives —
// so the signal an SEO tool wants is available without the transport.
//
// Draft tokens such as "h3-29" or "h3-Q050" are deliberately NOT accepted.
// They identify pre-RFC-9114 drafts that current browsers no longer negotiate;
// counting them would overstate what an actual visitor gets.
func altSvcAdvertisesHTTP3(header http.Header) bool {
	for _, field := range header.Values("Alt-Svc") {
		for _, alt := range splitAltSvcValues(field) {
			// Each alt-value is: protocol-id "=" alt-authority *( ";" param )
			// A bare "clear" has no "=" and simply yields no match.
			id, _, found := strings.Cut(alt, "=")
			if !found {
				continue
			}
			if strings.EqualFold(strings.TrimSpace(id), "h3") {
				return true
			}
		}
	}
	return false
}

// splitAltSvcValues splits an Alt-Svc field into its comma-separated
// alt-values, ignoring commas inside the quoted alt-authority.
func splitAltSvcValues(field string) []string {
	var (
		values  []string
		current strings.Builder
		inQuote bool
	)
	for _, r := range field {
		switch {
		case r == '"':
			inQuote = !inQuote
			current.WriteRune(r)
		case r == ',' && !inQuote:
			values = append(values, current.String())
			current.Reset()
		default:
			current.WriteRune(r)
		}
	}
	values = append(values, current.String())
	return values
}

// -----------------------------------------------------------------------
// Body decompression
// -----------------------------------------------------------------------

// newDecompressor returns a reader that decodes the given Content-Encoding, or
// (nil, nil) when the encoding needs no handling (identity, empty, or one the
// stdlib cannot decode such as br/zstd — those are passed through verbatim).
//
// "deflate" is deliberately not just flate.NewReader: RFC 7230 defines the
// token as zlib (RFC 1950), yet a large share of servers emit raw DEFLATE
// (RFC 1951) instead. Feeding zlib-wrapped data to a raw reader yields an
// empty or corrupt body, so sniff the two-byte zlib header and pick the
// matching decoder.
func newDecompressor(r io.Reader, encoding string) (io.ReadCloser, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(r)
		if err != nil {
			return nil, err
		}
		return gz, nil

	case "deflate":
		br := bufio.NewReader(r)
		if isZlibHeader(br) {
			zr, err := zlib.NewReader(br)
			if err != nil {
				return nil, err
			}
			return zr, nil
		}
		return flate.NewReader(br), nil

	default:
		return nil, nil
	}
}

// isZlibHeader peeks at the first two bytes and reports whether they form a
// valid RFC 1950 zlib header: the low nibble of CMF must be 8 (deflate) and
// the 16-bit big-endian value must be a multiple of 31.
func isZlibHeader(br *bufio.Reader) bool {
	head, err := br.Peek(2)
	if err != nil || len(head) < 2 {
		return false
	}
	cmf, flg := head[0], head[1]
	return cmf&0x0f == 8 && (uint16(cmf)<<8|uint16(flg))%31 == 0
}

// -----------------------------------------------------------------------
// /page endpoint — full page analysis (redirect chain + body + SSL + timing)
// -----------------------------------------------------------------------

// pageHop represents a single hop in the redirect chain.
type pageHop struct {
	Hop        int     `json:"hop"`
	URL        string  `json:"url"`
	Status     int     `json:"status"`
	Timing     float64 `json:"timing"`
	SSL        bool    `json:"ssl"`
	IP         string  `json:"ip"`
	Server     string  `json:"server,omitempty"`
	RawHeaders string  `json:"rawHeaders,omitempty"`
	Error      string  `json:"error,omitempty"`
}

// pageResponse is the JSON envelope returned by the /page endpoint.
//
// Headers preserves multi-valued response headers as JSON arrays — required
// for RFC 6265 §3 compliant Set-Cookie handling, where joining multiple
// values with ", " produces an unparseable string (cookie expiry dates
// contain literal commas, indistinguishable from the join separator).
type pageResponse struct {
	URL         string `json:"url"`
	FinalURL    string `json:"finalUrl"`
	Status      int    `json:"status"`
	HTTPVersion string `json:"httpVersion"`
	// HTTP3 reports whether the final page advertises HTTP/3 via Alt-Svc. It is
	// independent of HTTPVersion, which is the protocol this request used.
	HTTP3           bool                `json:"http3"`
	Headers         map[string][]string `json:"headers"`
	RawHeaders      string              `json:"rawHeaders"`
	HTML            string              `json:"html"`
	RedirectChain   []pageHop           `json:"redirectChain"`
	SSL             *sslInfo            `json:"ssl"`
	Timing          map[string]float64  `json:"timing"`
	IP              string              `json:"ip"`
	Size            int                 `json:"size"`
	TransferSize    int                 `json:"transferSize"`
	ContentEncoding string              `json:"contentEncoding"`
	Error           *proxyError         `json:"error"`
}

// formatRawHeaders renders response headers as a raw string (one per line).
func formatRawHeaders(h http.Header) string {
	var sb strings.Builder
	for key, vals := range h {
		for _, v := range vals {
			sb.WriteString(key)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// traceRedirectChain follows redirect hops via HEAD requests, recording
// timing, IP, headers, and status for each hop. Returns the chain and the
// final URL (which may be the original URL if no redirects occurred).
//
// The parent context carries the overall budget for the /page request. Each hop
// additionally gets its own per-request timeout, but the parent deadline always
// wins — otherwise maxHops slow redirects could keep the handler alive for
// maxHops × requestTimeout, and a client disconnect would not stop any of it.
func traceRedirectChain(parent context.Context, client *http.Client, startURL string, browserReq *http.Request, maxHops int, cfg *config) ([]pageHop, string) {
	var hops []pageHop
	currentURL := startURL
	visited := make(map[string]bool)

	for i := 0; i < maxHops; i++ {
		if parent.Err() != nil {
			hops = append(hops, pageHop{Hop: i + 1, URL: currentURL, Error: "timeout: redirect chain exceeded the time budget"})
			break
		}
		if visited[currentURL] {
			hops = append(hops, pageHop{Hop: i + 1, URL: currentURL, Error: "redirect loop detected"})
			break
		}
		visited[currentURL] = true

		ctx, cancel := context.WithTimeout(parent, cfg.requestTimeout)
		ct := &connTrace{}
		requestStart := time.Now()
		ctx = ct.attach(ctx)

		req, err := http.NewRequestWithContext(ctx, http.MethodHead, currentURL, nil)
		if err != nil {
			cancel()
			hops = append(hops, pageHop{Hop: i + 1, URL: currentURL, Error: "invalid URL"})
			break
		}
		copyRequestHeaders(browserReq, req)

		resp, err := client.Do(req)
		cancel()

		hop := pageHop{
			Hop:    i + 1,
			URL:    currentURL,
			SSL:    strings.HasPrefix(currentURL, "https://"),
			IP:     ct.remoteIP(),
			Timing: math.Round(ct.timingMap(requestStart)["total"]*10) / 10,
		}

		if err != nil {
			hop.Error = classifyUpstreamErrorMessage(err)
			hops = append(hops, hop)
			break
		}

		resp.Body.Close()
		hop.Status = resp.StatusCode
		hop.Server = resp.Header.Get("Server")
		hop.RawHeaders = formatRawHeaders(resp.Header)

		// Only record redirect hops (3xx). The final non-redirect hop is
		// handled by the caller (pageHandler) which does a GET with body.
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			hops = append(hops, hop)
			loc := resp.Header.Get("Location")
			if loc == "" {
				break
			}
			resolved, err := url.Parse(loc)
			if err != nil {
				break
			}
			base, _ := url.Parse(currentURL)
			nextURL := base.ResolveReference(resolved).String()

			// SSRF pre-check on each redirect target. The dialer enforces this
			// again for the actual connection; this only fails faster and
			// records a clearer reason in the chain.
			parsedNext, err := url.Parse(nextURL)
			if err != nil {
				break
			}
			if cfg.blocksHost(parent, parsedNext.Hostname()) {
				hops = append(hops, pageHop{
					Hop:   i + 2,
					URL:   nextURL,
					Error: "blocked_target: redirect target resolves to a private or reserved address",
				})
				break
			}

			currentURL = nextURL
			continue
		}
		break // not a redirect
	}

	return hops, currentURL
}

// classifyUpstreamErrorMessage returns a safe message for an upstream error.
func classifyUpstreamErrorMessage(err error) string {
	code, msg := classifyUpstreamError(err)
	return code + ": " + msg
}

// pageHandler returns an http.Handler for the /page endpoint.
func pageHandler(cfg *config, client *http.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// CORS preflight.
		if r.Method == http.MethodOptions {
			writeCORSHeaders(w, r, cfg)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		target, ok := authorizeRequest(w, r, cfg, http.MethodGet)
		if !ok {
			return
		}
		rawTarget := target.String()

		// One budget for the whole endpoint. Derived from r.Context() so that a
		// client disconnect aborts every upstream request still in flight, and
		// bounded so that a target serving slow redirects cannot keep this
		// handler (and its connections) alive indefinitely.
		reqCtx, cancelBudget := context.WithTimeout(r.Context(), cfg.pageBudget())
		defer cancelBudget()

		// ---- Phase 1: Trace redirect chain --------------------------------
		const maxRedirects = 20
		hops, finalURL := traceRedirectChain(reqCtx, client, rawTarget, r, maxRedirects, cfg)

		// Check if the chain ended with an error.
		if len(hops) > 0 && hops[len(hops)-1].Error != "" {
			result := pageResponse{
				URL:           rawTarget,
				FinalURL:      finalURL,
				RedirectChain: hops,
				Error:         &proxyError{Error: "upstream_error", Message: hops[len(hops)-1].Error, Status: 502},
			}
			writeCORSHeaders(w, r, cfg)
			writeJSON(w, http.StatusOK, result)
			return
		}

		// ---- Phase 2: HEAD probe for true Content-Encoding ----------------
		var serverContentEncoding string
		{
			ctx, cancel := context.WithTimeout(reqCtx, cfg.requestTimeout)
			headReq, err := http.NewRequestWithContext(ctx, http.MethodHead, finalURL, nil)
			if err == nil {
				copyRequestHeaders(r, headReq)
				headResp, err := client.Do(headReq)
				if err == nil {
					serverContentEncoding = headResp.Header.Get("Content-Encoding")
					headResp.Body.Close()
				}
			}
			cancel()
		}

		// ---- Phase 3: GET final page with body ----------------------------
		ctx, cancel := context.WithTimeout(reqCtx, cfg.requestTimeout)
		defer cancel()

		ct := &connTrace{}
		requestStart := time.Now()
		ctx = ct.attach(ctx)

		getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, finalURL, nil)
		if err != nil {
			writeJSONError(w, r, cfg, "upstream_error", "could not build request", http.StatusBadGateway)
			return
		}
		copyRequestHeaders(r, getReq)
		getReq.Header.Set("Accept-Encoding", "gzip, deflate")

		resp, err := client.Do(getReq)
		if err != nil {
			log.Printf("page upstream error: %v", err)
			code, message := classifyUpstreamError(err)
			result := pageResponse{
				URL:           rawTarget,
				FinalURL:      finalURL,
				RedirectChain: hops,
				Error:         &proxyError{Error: code, Message: message, Status: 502},
			}
			writeCORSHeaders(w, r, cfg)
			writeJSON(w, http.StatusOK, result)
			return
		}
		defer resp.Body.Close()

		// Read body — first buffer raw bytes (for transfer size), then decompress.
		var rawSource io.Reader = resp.Body
		if cfg.maxResponseBytes > 0 {
			rawSource = io.LimitReader(resp.Body, cfg.maxResponseBytes)
		}

		rawBytes, err := io.ReadAll(rawSource)
		if err != nil {
			log.Printf("warn: error reading page body: %v", err)
		}

		// Transfer size = raw compressed bytes received from upstream. Prefer
		// the upstream Content-Length, but only when it is a sane value — it is
		// attacker-controlled and would otherwise land in the JSON verbatim.
		transferSize := len(rawBytes)
		if cl := resp.Header.Get("Content-Length"); cl != "" {
			if n, convErr := strconv.Atoi(cl); convErr == nil && n >= 0 {
				transferSize = n
			}
		}

		// Decompress the raw bytes based on Content-Encoding.
		// Cap the decompressed stream to guard against zip-bomb-style payloads
		// where a small compressed body expands to gigabytes.
		actualEncoding := resp.Header.Get("Content-Encoding")
		bodyBytes := rawBytes
		if dec, decErr := newDecompressor(bytes.NewReader(rawBytes), actualEncoding); decErr != nil {
			log.Printf("warn: could not decompress page body (%s): %v", actualEncoding, decErr)
		} else if dec != nil {
			var limited io.Reader = dec
			if cfg.maxResponseBytes > 0 {
				limited = io.LimitReader(dec, cfg.maxResponseBytes)
			}
			decoded, readErr := io.ReadAll(limited)
			dec.Close()
			if readErr != nil {
				log.Printf("warn: error decompressing page body (%s): %v", actualEncoding, readErr)
			} else {
				bodyBytes = decoded
			}
		}

		// Determine the content encoding to report.
		contentEncoding := serverContentEncoding
		if contentEncoding == "" {
			contentEncoding = actualEncoding
		}

		// Build headers map, preserving multi-valued headers as slices.
		// Set-Cookie in particular MUST NOT be joined: cookie expiry dates
		// contain literal commas, indistinguishable from a "," separator (RFC 6265 §3).
		hdrs := make(map[string][]string, len(resp.Header))
		for k, v := range resp.Header {
			hdrs[k] = v
		}
		// Restore true Content-Encoding from HEAD probe.
		if serverContentEncoding != "" {
			hdrs["Content-Encoding"] = []string{serverContentEncoding}
		}

		// Build timing map.
		timingMap := ct.timingMap(requestStart)
		timingMap["downloadSize"] = float64(len(bodyBytes))
		timingMap["speed"] = 0

		// Append final hop to redirect chain.
		finalHop := pageHop{
			Hop:        len(hops) + 1,
			URL:        finalURL,
			Status:     resp.StatusCode,
			SSL:        strings.HasPrefix(finalURL, "https://"),
			IP:         ct.remoteIP(),
			Timing:     timingMap["total"],
			Server:     resp.Header.Get("Server"),
			RawHeaders: formatRawHeaders(resp.Header),
		}
		hops = append(hops, finalHop)

		result := pageResponse{
			URL:             rawTarget,
			FinalURL:        finalURL,
			Status:          resp.StatusCode,
			HTTPVersion:     resp.Proto,
			HTTP3:           altSvcAdvertisesHTTP3(resp.Header),
			Headers:         hdrs,
			RawHeaders:      formatRawHeaders(resp.Header),
			HTML:            string(bodyBytes),
			RedirectChain:   hops,
			SSL:             extractSSLInfo(resp.TLS),
			Timing:          timingMap,
			IP:              ct.remoteIP(),
			Size:            len(bodyBytes),
			TransferSize:    transferSize,
			ContentEncoding: contentEncoding,
			Error:           nil,
		}

		writeCORSHeaders(w, r, cfg)
		writeJSON(w, http.StatusOK, result)
	})
}

// -----------------------------------------------------------------------
// CORS helpers
// -----------------------------------------------------------------------

// writeCORSHeaders sets the Access-Control-* headers needed for the browser
// to accept responses from localhost.
func writeCORSHeaders(w http.ResponseWriter, r *http.Request, cfg *config) {
	origin := r.Header.Get("Origin")

	// Always vary on Origin: the response body and headers differ per origin,
	// so an intermediary (or the browser's own cache) must not reuse a response
	// generated for a different one — including the case where no
	// Allow-Origin header was emitted at all.
	w.Header().Add("Vary", "Origin")

	// Echo back the request origin if it is allowed; otherwise use a wildcard
	// only when there is no origin restriction configured.
	if isOriginAllowed(origin, cfg.allowedOrigins) && origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	} else if len(cfg.allowedOrigins) == 0 {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}

	w.Header().Set("Access-Control-Allow-Methods", "GET, HEAD, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Proxy-Token")
	w.Header().Set("Access-Control-Allow-Private-Network", "true")
	w.Header().Set("Access-Control-Max-Age", "600")
	// Note: Access-Control-Expose-Headers is NOT set here because the
	// wildcard "*" only works with "Access-Control-Allow-Origin: *".
	// When a specific origin is used, headers must be listed explicitly.
	// Callers set Expose-Headers themselves after knowing which headers
	// are present (e.g. proxyHandler enumerates upstream response headers).
}

// -----------------------------------------------------------------------
// Origin validation
// -----------------------------------------------------------------------

// isOriginAllowed returns true when the given origin matches one of the
// configured allowed origins. When the allowedOrigins slice is empty every
// origin is permitted (useful for development / testing only).
func isOriginAllowed(origin string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, a := range allowed {
		if strings.EqualFold(a, origin) {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------
// SSRF protection
// -----------------------------------------------------------------------

// errBlockedTarget is returned by the dialer when a connection would reach a
// private or otherwise reserved address. It is wrapped by net.OpError/url.Error
// on its way out of http.Client, so classifyUpstreamError uses errors.Is.
var errBlockedTarget = errors.New("target address is blocked")

// privateRangeCIDRs contains CIDR blocks that must never be targeted by the
// proxy. Beyond the obvious RFC 1918 / loopback ranges this covers three
// classes of bypass that are easy to overlook:
//
//   - Reserved and special-purpose IPv4 space (0/8, 192.0.0.0/24, 198.18/15,
//     multicast, 240/4) which can route to unexpected local destinations.
//   - NAT64 (64:ff9b::/96) and 6to4 (2002::/16), which embed an IPv4 address
//     inside an IPv6 one. On a NAT64 network, 64:ff9b::7f00:1 reaches
//     127.0.0.1 — the v4 check never sees it.
//   - IPv4-mapped IPv6 (::ffff:127.0.0.1) is handled by net.IPNet.Contains,
//     which normalises such addresses to their 4-byte form before matching.
var privateRangeCIDRs = func() []*net.IPNet {
	cidrs := []string{
		// IPv4
		"0.0.0.0/8",     // RFC 1122 "this network"
		"10.0.0.0/8",    // RFC 1918 private
		"100.64.0.0/10", // RFC 6598 Carrier-Grade NAT
		"127.0.0.0/8",   // loopback
		"169.254.0.0/16",
		"172.16.0.0/12",  // RFC 1918 private
		"192.0.0.0/24",   // RFC 6890 IETF protocol assignments
		"192.0.2.0/24",   // RFC 5737 documentation (TEST-NET-1)
		"192.168.0.0/16", // RFC 1918 private
		"198.18.0.0/15",  // RFC 2544 benchmarking
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4", // multicast
		"240.0.0.0/4", // reserved, includes 255.255.255.255
		// IPv6
		"::/128",        // unspecified
		"::1/128",       // loopback
		"64:ff9b::/96",  // RFC 6052 NAT64 — embeds IPv4
		"100::/64",      // RFC 6666 discard-only
		"2001:db8::/32", // documentation
		"2002::/16",     // RFC 3056 6to4 — embeds IPv4
		"fc00::/7",      // unique local
		"fe80::/10",     // link-local
		"ff00::/8",      // multicast
	}
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid private CIDR: " + cidr)
		}
		nets = append(nets, network)
	}
	return nets
}()

// isBlockedIP reports whether the given IP falls in a range the proxy must
// never connect to.
func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	for _, network := range privateRangeCIDRs {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// safeDialControl is a net.Dialer.Control hook and the authoritative SSRF
// boundary. It runs after DNS resolution but before the socket is connected,
// so it inspects the address the connection will actually reach.
//
// This closes the DNS-rebinding hole that a hostname pre-check cannot: a
// pre-check resolves the name once and the transport resolves it again, so an
// attacker-controlled zone with a short TTL can answer with a public address
// for the check and a loopback address for the connection. Here there is only
// one resolution and we see its result.
//
// It also covers every code path for free — redirect hops, HEAD probes and the
// final GET all dial through the same transport.
func safeDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Control is called post-resolution, so a non-IP here means something
		// unexpected happened. Refuse rather than guess.
		return fmt.Errorf("%w: unresolved address %q", errBlockedTarget, host)
	}
	if isBlockedIP(ip) {
		return fmt.Errorf("%w: %s", errBlockedTarget, ip)
	}
	return nil
}

// isPrivateHost resolves the hostname and reports whether any of its addresses
// fall in a blocked range.
//
// This is a fast pre-flight rejection so obvious cases fail before a connection
// is attempted; it is deliberately fail-open, because a lookup failure here
// would otherwise block legitimate domains during a DNS hiccup. Failing open is
// safe precisely because safeDialControl re-checks the real address later.
func isPrivateHost(ctx context.Context, hostname string, resolver *net.Resolver) bool {
	// Strip port if present.
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		host = hostname
	}

	// A literal IP needs no lookup — and must not be able to dodge the check by
	// being unresolvable.
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		return isBlockedIP(ip)
	}

	if resolver == nil {
		resolver = net.DefaultResolver
	}

	// Bound the lookup: a black-holed DNS server would otherwise hang the
	// handler indefinitely, since this runs outside the upstream request's
	// own timeout.
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addrs, err := resolver.LookupHost(lookupCtx, host)
	if err != nil {
		return false
	}

	for _, addr := range addrs {
		if isBlockedIP(net.ParseIP(addr)) {
			return true
		}
	}
	return false
}

// -----------------------------------------------------------------------
// Host-header validation
// -----------------------------------------------------------------------

// isLocalHostname reports whether the host portion of a Host header refers to
// this machine's loopback interface.
func isLocalHostname(hostHeader string) bool {
	host := hostHeader
	if h, _, err := net.SplitHostPort(hostHeader); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")

	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// localhostOnly rejects requests whose Host header does not name the loopback
// interface. Without it, an attacker's page can point a hostname it controls at
// 127.0.0.1 and reach the proxy from the browser — DNS rebinding against the
// proxy itself. The Origin allowlist defends against this too, but only when
// --origin was actually passed, and the default permits every origin.
//
// 127.0.0.0/8, localhost and [::1] are all accepted, because users type the
// address by hand and "localhost" is at least as natural as "127.0.0.1".
func localhostOnly(cfg *config, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cfg.allowAnyHost && !isLocalHostname(r.Host) {
			log.Printf("rejected request with non-local Host header: %q", r.Host)
			http.Error(w, "forbidden: proxy must be addressed as localhost", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// -----------------------------------------------------------------------
// Header forwarding
// -----------------------------------------------------------------------

// hopByHopHeaders lists headers that must not be forwarded between hops.
var hopByHopHeaders = map[string]struct{}{
	"connection":          {},
	"keep-alive":          {},
	"proxy-authenticate":  {},
	"proxy-authorization": {},
	"proxy-connection":    {},
	"te":                  {},
	"trailers":            {},
	"transfer-encoding":   {},
	"upgrade":             {},
	// Proxy-internal headers.
	"x-proxy-token": {},
}

// sensitiveRequestHeaders lists headers that must never travel from the browser
// to an arbitrary third-party target.
//
// Origin, Referer and the Sec-Fetch-* set are attached by the browser and would
// otherwise tell every host the proxy touches which tool the request came from.
// Cookie and Authorization cannot currently be sent — a cross-origin fetch
// omits credentials unless it opts in — but forwarding them would silently
// hand a caller's credentials to whatever URL it names, so they are refused
// here rather than left to depend on how the caller happens to call fetch().
var sensitiveRequestHeaders = map[string]struct{}{
	"authorization":       {},
	"cookie":              {},
	"cookie2":             {},
	"proxy-authorization": {},
	"origin":              {},
	"referer":             {},
	"sec-fetch-dest":      {},
	"sec-fetch-mode":      {},
	"sec-fetch-site":      {},
	"sec-fetch-user":      {},
	// Set by net/http from the request body; a copied value would conflict.
	"content-length": {},
	"host":           {},
}

// connectionTokens returns the header names listed in the Connection header.
// RFC 9110 §7.6.1 makes those hop-by-hop for this message regardless of what
// the static list says, so they must be dropped as well.
func connectionTokens(h http.Header) map[string]struct{} {
	tokens := make(map[string]struct{})
	for _, value := range h.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if token = strings.ToLower(strings.TrimSpace(token)); token != "" {
				tokens[token] = struct{}{}
			}
		}
	}
	return tokens
}

// copyRequestHeaders copies safe headers from the incoming browser request to
// the upstream request, skipping hop-by-hop, proxy-specific and sensitive ones.
func copyRequestHeaders(src *http.Request, dst *http.Request) {
	dynamic := connectionTokens(src.Header)
	for key, values := range src.Header {
		lower := strings.ToLower(key)
		if _, skip := hopByHopHeaders[lower]; skip {
			continue
		}
		if _, skip := sensitiveRequestHeaders[lower]; skip {
			continue
		}
		if _, skip := dynamic[lower]; skip {
			continue
		}
		for _, v := range values {
			dst.Header.Add(key, v)
		}
	}
}

// copyResponseHeaders copies safe upstream response headers to the client
// response, skipping hop-by-hop headers.
func copyResponseHeaders(src *http.Response, dst http.ResponseWriter) {
	dynamic := connectionTokens(src.Header)
	for key, values := range src.Header {
		lower := strings.ToLower(key)
		if _, skip := hopByHopHeaders[lower]; skip {
			continue
		}
		if _, skip := dynamic[lower]; skip {
			continue
		}
		// Strip upstream CORS headers — we set our own.
		if strings.HasPrefix(lower, "access-control-") {
			continue
		}
		for _, v := range values {
			dst.Header().Add(key, v)
		}
	}
}

// -----------------------------------------------------------------------
// Upstream HTTP client
// -----------------------------------------------------------------------

// newUpstreamClient builds the http.Client used for every outbound request.
//
// The dialer carries safeDialControl, which is where SSRF is actually enforced
// (see its documentation). Note that the DNS resolver deliberately uses its own
// plain dialer: with --dns system the configured nameserver may itself be a
// loopback address such as systemd-resolved on 127.0.0.53, and applying the
// guard there would break name resolution entirely.
func newUpstreamClient(cfg *config) *http.Client {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  cfg.resolver,
		Control:   safeDialControl,
	}
	transport := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.requestTimeout,
		MaxIdleConns:          50,
		IdleConnTimeout:       60 * time.Second,
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true, // Fresh connection per request — accurate httptrace timing and IP.
		// TLS verification is intentionally left enabled (InsecureSkipVerify: false).
	}
	return &http.Client{
		Transport: transport,
		// Do not follow redirects automatically; let the browser handle them.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// -----------------------------------------------------------------------
// Entry point
// -----------------------------------------------------------------------

func main() {
	// ---- CLI flags -------------------------------------------------------
	port := flag.Int("port", 0, "TCP port to listen on (0 = random free port)")
	rawOrigins := flag.String("origin", "", "Comma-separated list of allowed Origins, e.g. https://mytool.example.com")
	timeoutSec := flag.Int("timeout", 30, "Upstream request timeout in seconds")
	maxMB := flag.Int64("max-mb", 50, "Maximum upstream response size in megabytes (0 = unlimited)")
	rawDNS := flag.String("dns", "1.1.1.1,8.8.8.8", `Comma-separated DNS servers (e.g. "9.9.9.9,8.8.4.4"), or "system" for OS defaults`)
	allowAnyHost := flag.Bool("allow-any-host", false, "Accept requests with a non-localhost Host header (not recommended)")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("localproxy %s\n", Version)
		fmt.Printf("License: %s\n", License)
		fmt.Printf("Author:  %s [%s]\n", Author, AuthorURL)
		fmt.Printf("Repo:    %s\n", RepoURL)
		os.Exit(0)
	}

	// ---- Validate flags --------------------------------------------------
	// Caught here rather than surfacing later as a mystery: a zero timeout
	// produces a context that is already past its deadline, so every single
	// upstream request would fail instantly.
	if *port < 0 || *port > 65535 {
		log.Fatalf("fatal: --port must be between 0 and 65535, got %d", *port)
	}
	if *timeoutSec < 1 {
		log.Fatalf("fatal: --timeout must be at least 1 second, got %d", *timeoutSec)
	}
	const maxAllowedMB = 1024 * 1024 // 1 TB; guards the byte multiplication below
	if *maxMB < 0 || *maxMB > maxAllowedMB {
		log.Fatalf("fatal: --max-mb must be between 0 and %d, got %d", maxAllowedMB, *maxMB)
	}

	// ---- Parse origins ---------------------------------------------------
	var origins []string
	if *rawOrigins != "" {
		for _, o := range strings.Split(*rawOrigins, ",") {
			trimmed := strings.TrimSpace(o)
			if trimmed != "" {
				origins = append(origins, trimmed)
			}
		}
	}

	// ---- Generate session token ------------------------------------------
	token, err := generateToken(24) // 48 hex chars
	if err != nil {
		log.Fatalf("fatal: %v", err)
	}

	// ---- Build DNS resolver -----------------------------------------------
	var resolver *net.Resolver
	var dnsLabel string
	if strings.EqualFold(strings.TrimSpace(*rawDNS), "system") {
		resolver = net.DefaultResolver
		dnsLabel = "system"
	} else {
		var dnsServers []string
		for _, s := range strings.Split(*rawDNS, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				// Ensure host:port format.
				if _, _, err := net.SplitHostPort(s); err != nil {
					s = net.JoinHostPort(s, "53")
				}
				dnsServers = append(dnsServers, s)
			}
		}
		if len(dnsServers) == 0 {
			log.Fatal("fatal: --dns requires at least one server or \"system\"")
		}
		dnsLabel = strings.Join(dnsServers, ", ")
		var dnsIndex atomic.Uint64
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				// Round-robin across configured servers.
				idx := int(dnsIndex.Add(1)-1) % len(dnsServers)
				var d net.Dialer
				return d.DialContext(ctx, network, dnsServers[idx])
			},
		}
	}

	cfg := &config{
		port:             *port,
		allowedOrigins:   origins,
		sessionToken:     token,
		requestTimeout:   time.Duration(*timeoutSec) * time.Second,
		maxResponseBytes: *maxMB * 1024 * 1024,
		resolver:         resolver,
		allowAnyHost:     *allowAnyHost,
	}

	httpClient := newUpstreamClient(cfg)

	// ---- Create listener on localhost only -------------------------------
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.port))
	if err != nil {
		log.Fatalf("fatal: could not bind to port %d: %v", cfg.port, err)
	}
	// Retrieve the actual port (relevant when port 0 was requested).
	actualPort := listener.Addr().(*net.TCPAddr).Port
	cfg.port = actualPort

	// ---- Register routes -------------------------------------------------
	mux := http.NewServeMux()
	mux.Handle("/proxy", proxyHandler(cfg, httpClient))
	mux.Handle("/inspect", inspectHandler(cfg, httpClient))
	mux.Handle("/page", pageHandler(cfg, httpClient))

	// Health / ping endpoint — no auth needed but needs CORS for browser access.
	mux.HandleFunc("/ping", func(w http.ResponseWriter, r *http.Request) {
		writeCORSHeaders(w, r, cfg)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		fmt.Fprintln(w, "localproxy ok")
	})

	// Version endpoint — no auth needed, returns version info as JSON.
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeCORSHeaders(w, r, cfg)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{
			"version": Version,
			"license": License,
			"author":  Author,
			"url":     AuthorURL,
			"repo":    RepoURL,
		})
	})

	server := &http.Server{
		// Every route sits behind the Host check, including /ping and /version.
		Handler:           localhostOnly(cfg, mux),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// ---- Print startup information ---------------------------------------
	title := fmt.Sprintf("localproxy %s  —  ready", Version)
	addressLine := fmt.Sprintf("  Address  :  http://127.0.0.1:%d", actualPort)
	tokenLine := fmt.Sprintf("  Token    :  %s", token)
	dnsLine := fmt.Sprintf("  DNS      :  %s", dnsLabel)
	var originsLine string
	if len(origins) > 0 {
		originsLine = fmt.Sprintf("  Origins  :  %s", strings.Join(origins, ", "))
	} else {
		originsLine = "  Origins  :  (all — pass --origin for production)"
	}
	hostLine := "  Host     :  localhost only"
	if cfg.allowAnyHost {
		hostLine = "  Host     :  ANY (--allow-any-host — not recommended)"
	}
	licenseLine := fmt.Sprintf("  License  :  %s", License)
	authorLine := fmt.Sprintf("  Author   :  %s [%s]", Author, AuthorURL)
	repoLine := fmt.Sprintf("  Repo     :  %s", RepoURL)

	// Determine box width from the longest content line (rune-aware for UTF-8)
	runeWidth := func(s string) int { return utf8.RuneCountInString(s) }
	innerWidth := runeWidth(title)
	for _, line := range []string{addressLine, tokenLine, dnsLine, originsLine, hostLine, licenseLine, authorLine, repoLine} {
		if w := runeWidth(line); w > innerWidth {
			innerWidth = w
		}
	}
	innerWidth += 4 // 2 spaces padding on each side

	hBar := strings.Repeat("═", innerWidth)
	pad := func(s string) string {
		gap := innerWidth - runeWidth(s) - 2 // subtract the 2 leading spaces inside ║
		if gap < 0 {
			gap = 0
		}
		return "║  " + s + strings.Repeat(" ", gap) + "║"
	}

	// Center the title
	titlePad := (innerWidth - runeWidth(title)) / 2
	titleRight := innerWidth - runeWidth(title) - titlePad
	centeredTitle := "║" + strings.Repeat(" ", titlePad) + title + strings.Repeat(" ", titleRight) + "║"

	thinBar := "╟" + strings.Repeat("─", innerWidth) + "╢"

	fmt.Println()
	fmt.Println("╔" + hBar + "╗")
	fmt.Println(centeredTitle)
	fmt.Println("╠" + hBar + "╣")
	fmt.Println(pad(addressLine))
	fmt.Println(pad(tokenLine))
	fmt.Println(thinBar)
	fmt.Println(pad(dnsLine))
	fmt.Println(pad(originsLine))
	fmt.Println(pad(hostLine))
	fmt.Println(thinBar)
	fmt.Println(pad(licenseLine))
	fmt.Println(pad(authorLine))
	fmt.Println(pad(repoLine))
	fmt.Println("╚" + hBar + "╝")
	fmt.Println()
	fmt.Println("  Enter the address and token in your online tool.")
	fmt.Println("  Press Ctrl+C to stop.")
	fmt.Println()

	// ---- Graceful shutdown -----------------------------------------------
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Fatalf("fatal: server error: %v", err)
		}
	}()

	<-quit
	fmt.Println("\nShutting down…")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("warn: shutdown error: %v", err)
	}
	fmt.Println("Bye.")
}
