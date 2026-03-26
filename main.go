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
	"bytes"
	"compress/flate"
	"compress/gzip"
	"context"
	"crypto/rand"
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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf8"
)

// Version is set at build time via -ldflags "-X main.Version=...".
// Local builds show "dev"; release builds get the git tag (e.g. "v1.0.1").
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
	// to a private address. Defaults to isPrivateHost in production; tests may
	// override it with a no-op to allow localhost targets.
	ssrfCheck func(string) bool

	// resolver is the DNS resolver used for upstream lookups and SSRF checks.
	// nil means net.DefaultResolver (system DNS).
	resolver *net.Resolver
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
func writeJSONError(w http.ResponseWriter, r *http.Request, cfg *config, code string, message string, status int) {
	writeCORSHeaders(w, r, cfg)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(proxyError{Error: code, Message: message, Status: status})
}

// classifyUpstreamError inspects the error chain from an upstream request and
// returns an error code and a safe, human-readable message.
func classifyUpstreamError(err error) (code string, message string) {
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
		// 1. Only GET, HEAD and POST are forwarded; OPTIONS is handled below.
		// ------------------------------------------------------------------
		if r.Method == http.MethodOptions {
			writeCORSHeaders(w, r, cfg)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// ------------------------------------------------------------------
		// 2. Origin check — reject requests from unknown origins.
		// ------------------------------------------------------------------
		if !isOriginAllowed(r.Header.Get("Origin"), cfg.allowedOrigins) {
			http.Error(w, "forbidden: origin not allowed", http.StatusForbidden)
			return
		}

		// ------------------------------------------------------------------
		// 3. Session-token check.
		// ------------------------------------------------------------------
		if r.Header.Get("X-Proxy-Token") != cfg.sessionToken {
			http.Error(w, "forbidden: invalid proxy token", http.StatusForbidden)
			return
		}

		// ------------------------------------------------------------------
		// 4. Parse & validate the target URL.
		// ------------------------------------------------------------------
		rawTarget := r.URL.Query().Get("url")
		if rawTarget == "" {
			http.Error(w, "bad request: missing 'url' query parameter", http.StatusBadRequest)
			return
		}

		target, err := url.ParseRequestURI(rawTarget)
		if err != nil || (target.Scheme != "https" && target.Scheme != "http") {
			http.Error(w, "bad request: 'url' must be a valid http/https URL", http.StatusBadRequest)
			return
		}

		// Disallow requests back to localhost / private ranges to prevent SSRF.
		checkSSRF := cfg.ssrfCheck
		if checkSSRF == nil {
			checkSSRF = func(h string) bool { return isPrivateHost(h, cfg.resolver) }
		}
		if checkSSRF(target.Hostname()) {
			http.Error(w, "forbidden: target resolves to a private address", http.StatusForbidden)
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
			http.Error(w, "internal error: could not build upstream request", http.StatusInternalServerError)
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
		} {
			exposeSet[h] = struct{}{}
		}
		exposeKeys := make([]string, 0, len(exposeSet))
		for k := range exposeSet {
			exposeKeys = append(exposeKeys, k)
		}
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(exposeKeys, ", "))

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
			// Known size — set header and stream normally.
			w.Header().Set("X-Upstream-Content-Length", cl)
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
type inspectResponse struct {
	Status   int                    `json:"status"`
	Headers  map[string]string      `json:"headers"`
	SSL      *sslInfo               `json:"ssl"`
	Timing   map[string]float64     `json:"timing"`
	IP       string                 `json:"ip"`
	Protocol string                 `json:"protocol"`
	Body     string                 `json:"body,omitempty"`
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
		SANs:               leaf.DNSNames,
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

		// CORS preflight.
		if r.Method == http.MethodOptions {
			writeCORSHeaders(w, r, cfg)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Origin check.
		if !isOriginAllowed(r.Header.Get("Origin"), cfg.allowedOrigins) {
			http.Error(w, "forbidden: origin not allowed", http.StatusForbidden)
			return
		}

		// Token check.
		if r.Header.Get("X-Proxy-Token") != cfg.sessionToken {
			http.Error(w, "forbidden: invalid proxy token", http.StatusForbidden)
			return
		}

		// Parse target URL.
		rawTarget := r.URL.Query().Get("url")
		if rawTarget == "" {
			http.Error(w, "bad request: missing 'url' query parameter", http.StatusBadRequest)
			return
		}
		target, err := url.ParseRequestURI(rawTarget)
		if err != nil || (target.Scheme != "https" && target.Scheme != "http") {
			http.Error(w, "bad request: 'url' must be a valid http/https URL", http.StatusBadRequest)
			return
		}

		// SSRF protection.
		checkSSRF := cfg.ssrfCheck
		if checkSSRF == nil {
			checkSSRF = func(h string) bool { return isPrivateHost(h, cfg.resolver) }
		}
		if checkSSRF(target.Hostname()) {
			http.Error(w, "forbidden: target resolves to a private address", http.StatusForbidden)
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
				http.Error(w, "internal error: could not build upstream request", http.StatusInternalServerError)
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
			http.Error(w, "internal error: could not build upstream request", http.StatusInternalServerError)
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

		// Collect response headers as flat map.
		hdrs := make(map[string]string, len(resp.Header))
		for k, v := range resp.Header {
			hdrs[k] = strings.Join(v, ", ")
		}

		// Restore the server's true Content-Encoding from the HEAD probe.
		// The GET response may show "gzip" because we limited Accept-Encoding,
		// but the HEAD reveals the server's actual preferred encoding (e.g. zstd, br).
		if serverContentEncoding != "" {
			hdrs["Content-Encoding"] = serverContentEncoding
		}

		// Read body if requested, decompressing based on Content-Encoding.
		var body string
		if includeBody {
			var bodySource io.Reader = resp.Body
			if cfg.maxResponseBytes > 0 {
				bodySource = io.LimitReader(resp.Body, cfg.maxResponseBytes)
			}

			// Decompress based on actual GET response encoding (gzip/deflate via stdlib).
			switch strings.ToLower(resp.Header.Get("Content-Encoding")) {
			case "gzip":
				if gz, err := gzip.NewReader(bodySource); err == nil {
					defer gz.Close()
					bodySource = gz
				} else {
					log.Printf("warn: failed to create gzip reader: %v", err)
				}
			case "deflate":
				fr := flate.NewReader(bodySource)
				defer fr.Close()
				bodySource = fr
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
			Body:     body,
		}

		writeCORSHeaders(w, r, cfg)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(result)
	})
}

// -----------------------------------------------------------------------
// /page endpoint — full page analysis (redirect chain + body + SSL + timing)
// -----------------------------------------------------------------------

// pageHop represents a single hop in the redirect chain.
type pageHop struct {
	Hop        int    `json:"hop"`
	URL        string `json:"url"`
	Status     int    `json:"status"`
	Timing     float64 `json:"timing"`
	SSL        bool   `json:"ssl"`
	IP         string `json:"ip"`
	Server     string `json:"server,omitempty"`
	RawHeaders string `json:"rawHeaders,omitempty"`
	Error      string `json:"error,omitempty"`
}

// pageResponse is the JSON envelope returned by the /page endpoint.
type pageResponse struct {
	URL             string             `json:"url"`
	FinalURL        string             `json:"finalUrl"`
	Status          int                `json:"status"`
	HTTPVersion     string             `json:"httpVersion"`
	Headers         map[string]string  `json:"headers"`
	RawHeaders      string             `json:"rawHeaders"`
	HTML            string             `json:"html"`
	RedirectChain   []pageHop          `json:"redirectChain"`
	SSL             *sslInfo           `json:"ssl"`
	Timing          map[string]float64 `json:"timing"`
	IP              string             `json:"ip"`
	Size            int                `json:"size"`
	TransferSize    int                `json:"transferSize"`
	ContentEncoding string             `json:"contentEncoding"`
	Error           *proxyError        `json:"error"`
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
func traceRedirectChain(client *http.Client, startURL string, browserReq *http.Request, maxHops int, cfg *config) ([]pageHop, string) {
	var hops []pageHop
	currentURL := startURL
	visited := make(map[string]bool)

	for i := 0; i < maxHops; i++ {
		if visited[currentURL] {
			hops = append(hops, pageHop{Hop: i + 1, URL: currentURL, Error: "redirect loop detected"})
			break
		}
		visited[currentURL] = true

		ctx, cancel := context.WithTimeout(context.Background(), cfg.requestTimeout)
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

		hop.Status = resp.StatusCode
		hop.Server = resp.Header.Get("Server")
		hop.RawHeaders = formatRawHeaders(resp.Header)
		resp.Body.Close()

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

			// SSRF check on each redirect target.
			parsedNext, err := url.Parse(nextURL)
			if err != nil {
				break
			}
			checkSSRF := cfg.ssrfCheck
			if checkSSRF == nil {
				checkSSRF = func(h string) bool { return isPrivateHost(h, cfg.resolver) }
			}
			if checkSSRF(parsedNext.Hostname()) {
				hops = append(hops, pageHop{
					Hop:   i + 2,
					URL:   nextURL,
					Error: "redirect target resolves to a private address",
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
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Origin check.
		if !isOriginAllowed(r.Header.Get("Origin"), cfg.allowedOrigins) {
			http.Error(w, "forbidden: origin not allowed", http.StatusForbidden)
			return
		}

		// Token check.
		if r.Header.Get("X-Proxy-Token") != cfg.sessionToken {
			http.Error(w, "forbidden: invalid proxy token", http.StatusForbidden)
			return
		}

		// Parse target URL.
		rawTarget := r.URL.Query().Get("url")
		if rawTarget == "" {
			http.Error(w, "bad request: missing 'url' query parameter", http.StatusBadRequest)
			return
		}
		target, err := url.ParseRequestURI(rawTarget)
		if err != nil || (target.Scheme != "https" && target.Scheme != "http") {
			http.Error(w, "bad request: 'url' must be a valid http/https URL", http.StatusBadRequest)
			return
		}

		// SSRF check.
		checkSSRF := cfg.ssrfCheck
		if checkSSRF == nil {
			checkSSRF = func(h string) bool { return isPrivateHost(h, cfg.resolver) }
		}
		if checkSSRF(target.Hostname()) {
			http.Error(w, "forbidden: target resolves to a private address", http.StatusForbidden)
			return
		}

		// ---- Phase 1: Trace redirect chain --------------------------------
		const maxRedirects = 20
		hops, finalURL := traceRedirectChain(client, rawTarget, r, maxRedirects, cfg)

		// Check if the chain ended with an error.
		if len(hops) > 0 && hops[len(hops)-1].Error != "" {
			result := pageResponse{
				URL:           rawTarget,
				FinalURL:      finalURL,
				RedirectChain: hops,
				Error:         &proxyError{Error: "upstream_error", Message: hops[len(hops)-1].Error, Status: 502},
			}
			writeCORSHeaders(w, r, cfg)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(result)
			return
		}

		// ---- Phase 2: HEAD probe for true Content-Encoding ----------------
		var serverContentEncoding string
		{
			ctx, cancel := context.WithTimeout(context.Background(), cfg.requestTimeout)
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
		ctx, cancel := context.WithTimeout(context.Background(), cfg.requestTimeout)
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
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(result)
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

		// Transfer size = raw compressed bytes received from upstream.
		var transferSize int
		if cl := resp.Header.Get("Content-Length"); cl != "" {
			transferSize, _ = strconv.Atoi(cl)
		} else {
			transferSize = len(rawBytes)
		}

		// Decompress the raw bytes based on Content-Encoding.
		actualEncoding := resp.Header.Get("Content-Encoding")
		var bodyBytes []byte
		switch strings.ToLower(actualEncoding) {
		case "gzip":
			if gz, err := gzip.NewReader(bytes.NewReader(rawBytes)); err == nil {
				bodyBytes, err = io.ReadAll(gz)
				gz.Close()
				if err != nil {
					log.Printf("warn: error decompressing gzip body: %v", err)
					bodyBytes = rawBytes // fallback to raw
				}
			} else {
				log.Printf("warn: failed to create gzip reader: %v", err)
				bodyBytes = rawBytes
			}
		case "deflate":
			fr := flate.NewReader(bytes.NewReader(rawBytes))
			bodyBytes, err = io.ReadAll(fr)
			fr.Close()
			if err != nil {
				log.Printf("warn: error decompressing deflate body: %v", err)
				bodyBytes = rawBytes
			}
		default:
			bodyBytes = rawBytes
		}

		// Determine the content encoding to report.
		contentEncoding := serverContentEncoding
		if contentEncoding == "" {
			contentEncoding = actualEncoding
		}

		// Build headers map.
		hdrs := make(map[string]string, len(resp.Header))
		for k, v := range resp.Header {
			hdrs[k] = strings.Join(v, ", ")
		}
		// Restore true Content-Encoding from HEAD probe.
		if serverContentEncoding != "" {
			hdrs["Content-Encoding"] = serverContentEncoding
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
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(result)
	})
}

// -----------------------------------------------------------------------
// CORS helpers
// -----------------------------------------------------------------------

// writeCORSHeaders sets the Access-Control-* headers needed for the browser
// to accept responses from localhost.
func writeCORSHeaders(w http.ResponseWriter, r *http.Request, cfg *config) {
	origin := r.Header.Get("Origin")

	// Echo back the request origin if it is allowed; otherwise use a wildcard
	// only when there is no origin restriction configured.
	if isOriginAllowed(origin, cfg.allowedOrigins) && origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Vary", "Origin")
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

// privateRangeCIDRs contains CIDR blocks that must never be targeted by the proxy.
var privateRangeCIDRs = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",      // RFC 1122 "this network"
		"10.0.0.0/8",
		"100.64.0.0/10",  // RFC 6598 Carrier-Grade NAT
		"127.0.0.0/8",
		"169.254.0.0/16", // link-local
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
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

// isPrivateHost resolves the hostname to its IP addresses and checks whether
// any of them fall within a private/loopback range.
func isPrivateHost(hostname string, resolver *net.Resolver) bool {
	// Strip port if present.
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		host = hostname
	}

	if resolver == nil {
		resolver = net.DefaultResolver
	}
	addrs, err := resolver.LookupHost(context.Background(), host)
	if err != nil {
		// Treat unresolvable hosts as safe — the upstream request will fail
		// naturally and we don't want to accidentally block valid domains.
		return false
	}

	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		for _, network := range privateRangeCIDRs {
			if network.Contains(ip) {
				return true
			}
		}
	}
	return false
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

// copyRequestHeaders copies safe headers from the incoming browser request to
// the upstream request, skipping hop-by-hop and proxy-specific ones.
func copyRequestHeaders(src *http.Request, dst *http.Request) {
	for key, values := range src.Header {
		if _, skip := hopByHopHeaders[strings.ToLower(key)]; skip {
			continue
		}
		for _, v := range values {
			dst.Header.Add(key, v)
		}
	}
	// Ensure we don't accidentally forward the host header.
	dst.Header.Del("Host")
}

// copyResponseHeaders copies safe upstream response headers to the client
// response, skipping hop-by-hop headers.
func copyResponseHeaders(src *http.Response, dst http.ResponseWriter) {
	for key, values := range src.Header {
		if _, skip := hopByHopHeaders[strings.ToLower(key)]; skip {
			continue
		}
		// Strip upstream CORS headers — we set our own.
		lower := strings.ToLower(key)
		if strings.HasPrefix(lower, "access-control-") {
			continue
		}
		for _, v := range values {
			dst.Header().Add(key, v)
		}
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
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("localproxy %s\n", Version)
		fmt.Printf("License: %s\n", License)
		fmt.Printf("Author:  %s [%s]\n", Author, AuthorURL)
		fmt.Printf("Repo:    %s\n", RepoURL)
		os.Exit(0)
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
	}

	// ---- Build HTTP client -----------------------------------------------
	// Use a dedicated transport with sane timeouts and TLS verification enabled.
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  resolver,
	}
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: time.Duration(*timeoutSec) * time.Second,
		MaxIdleConns:          50,
		IdleConnTimeout:       60 * time.Second,
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:    true, // Fresh connection per request — accurate httptrace timing and IP.
		// TLS verification is intentionally left enabled (InsecureSkipVerify: false).
	}
	httpClient := &http.Client{
		Transport: transport,
		// Do not follow redirects automatically; let the browser handle them.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

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
		fmt.Fprintln(w, "localproxy ok")
	})

	// Version endpoint — no auth needed, returns version info as JSON.
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

	server := &http.Server{
		Handler:           mux,
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
	licenseLine := fmt.Sprintf("  License  :  %s", License)
	authorLine := fmt.Sprintf("  Author   :  %s [%s]", Author, AuthorURL)
	repoLine := fmt.Sprintf("  Repo     :  %s", RepoURL)

	// Determine box width from the longest content line (rune-aware for UTF-8)
	runeWidth := func(s string) int { return utf8.RuneCountInString(s) }
	innerWidth := runeWidth(title)
	for _, line := range []string{addressLine, tokenLine, dnsLine, originsLine, licenseLine, authorLine, repoLine} {
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
