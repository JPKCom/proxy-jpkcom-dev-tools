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
	"crypto"
	"crypto/dsa" //lint:ignore SA1019 only to describe legacy DSA certificate keys
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"os/signal"
	"regexp"
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

	// ssrfCheck replaces the SSRF pre-check (precheck) with a plain "is this
	// hostname blocked?" test. Test-only: main never sets it, and nil means
	// the built-in pre-check with --allow-local and block reasons. A hook that
	// blocks reports reason "private", the v1.3.0 case.
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

	// dialControl replaces safeDialControl as the dialer's Control hook, for
	// the upstream client and the TLS diagnostic probe alike. Test-only: main
	// never sets it, and nil means safeDialControl — the SSRF boundary.
	dialControl func(network, address string, c syscall.RawConn) error

	// rootCAs replaces the system trust store for upstream TLS verification.
	// Test-only: main never sets it, and nil means the system roots.
	// Verification itself is never switched off for a connection that carries
	// application data; the only unverified handshake is the diagnostic probe
	// (probeTLS), which reads certificates and nothing else.
	rootCAs *x509.CertPool

	// allowLocal is the parsed --allow-local list. Empty means off: every
	// private address stays blocked, exactly as in v1.3.0. See allowEntry for
	// the syntax and localVerdict for what an entry permits.
	allowLocal []allowEntry

	// lookupIP replaces cfg.resolver for every lookup the proxy makes itself:
	// the SSRF pre-check, localGuard and — whenever it is set — the dial path
	// for targets that are not allowed as local, so a test can steer all of
	// them with one answer. Test-only: main never sets it, and nil means
	// cfg.resolver.
	lookupIP func(ctx context.Context, host string) ([]net.IPAddr, error)
}

// dialControlOrDefault returns the configured dial Control hook, falling back
// to safeDialControl, so production code can never end up dialling without it.
func (c *config) dialControlOrDefault() func(network, address string, c syscall.RawConn) error {
	if c.dialControl != nil {
		return c.dialControl
	}
	return safeDialControl
}

// precheck reports whether u must be rejected before any connection is
// attempted, and why (a blockReason value). It is the fast pre-flight check
// for the start URL and every redirect target, not the security boundary:
// localGuard and safeDialControl decide again on the address actually dialled.
//
// localStart says whether the request's start URL is an --allow-local target
// (allowLocalMatchURL); it must be the request's value, not that of u.
func (c *config) precheck(ctx context.Context, u *url.URL, localStart bool) (blocked bool, reason string) {
	if c.ssrfCheck != nil {
		// Test hook: keeps its v1.3.0 meaning, "private" being the v1.3.0 case.
		if c.ssrfCheck(u.Hostname()) {
			return true, reasonPrivate
		}
		return false, ""
	}
	host, port := hostPort(u)
	return c.precheckHost(ctx, host, port, localStart)
}

// precheckHost is precheck for a bare host (no brackets) and port. A literal
// IP is judged at once, without DNS. A name the --allow-local list covers, on
// a request whose start URL is local, is not resolved here at all: the dialer
// decides per IP (LOCAL-5). Every other name is resolved, and the strongest
// reason over all its addresses wins. A lookup failure fails open — the dialer
// re-checks the real address.
func (c *config) precheckHost(ctx context.Context, host, port string, localStart bool) (blocked bool, reason string) {
	if ip := net.ParseIP(host); ip != nil {
		reason = c.blockReason(host, port, ip, localStart)
		return reason != "", reason
	}
	if localStart && c.allowLocalMatch(host, port) {
		return false, ""
	}

	// Bound the lookup: a black-holed DNS server would otherwise hang the
	// handler indefinitely, since this runs outside the upstream request's
	// own timeout.
	lookupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ips, err := c.resolveHost(lookupCtx, host)
	if err != nil {
		return false, ""
	}
	for _, ip := range ips {
		reason = strongerReason(reason, c.blockReason(host, port, ip, localStart))
	}
	return reason != "", reason
}

// resolveHost resolves a host name through the shared lookup hook: cfg.lookupIP
// in tests, cfg.resolver otherwise. With an active --allow-local list,
// "localhost" and "*.localhost" map to 127.0.0.1 and ::1 without DNS
// (RFC 6761). A test hook reports its lookup to an httptrace attached to ctx,
// as the stdlib resolver does on its own, so X-Upstream-Timing keeps its DNS
// phase.
func (c *config) resolveHost(ctx context.Context, host string) ([]net.IP, error) {
	if c.allowLocalActive() && isLocalhostName(normHost(host)) {
		return []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, nil
	}
	var (
		addrs []net.IPAddr
		err   error
	)
	if c.lookupIP != nil {
		trace := httptrace.ContextClientTrace(ctx)
		if trace != nil && trace.DNSStart != nil {
			trace.DNSStart(httptrace.DNSStartInfo{Host: host})
		}
		addrs, err = c.lookupIP(ctx, host)
		if trace != nil && trace.DNSDone != nil {
			trace.DNSDone(httptrace.DNSDoneInfo{Addrs: addrs, Err: err})
		}
	} else {
		resolver := c.resolver
		if resolver == nil {
			resolver = net.DefaultResolver
		}
		addrs, err = resolver.LookupIPAddr(ctx, host)
	}
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no addresses", Name: host, IsNotFound: true}
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
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
	// Type is a human-readable class with the semantics of the PHP proxy's
	// error.type ("Certificate expired", "Could not resolve host", …). Set on
	// every upstream failure and on a /proxy redirect hop refused by the SSRF
	// pre-check; absent on the request-validation 4xx from authorizeRequest.
	Type string `json:"type,omitempty"`
	// Reason is a machine-readable sub-code for branching (since v1.4.0): set on
	// auth_refused and blocked_target. Error stays the primary code; Type stays
	// display text.
	Reason string `json:"reason,omitempty"`
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

// writeJSONErrorReason is writeJSONError with a reason sub-code, for the
// request-validation rejections that carry one (blocked_target). Like
// writeJSONError it sets no type.
func writeJSONErrorReason(w http.ResponseWriter, r *http.Request, cfg *config, code, reason, message string, status int) {
	writeUpstreamError(w, r, cfg, &proxyError{Error: code, Message: message, Status: status, Reason: reason})
}

// writeUpstreamError writes the JSON error for a failed upstream request. The
// status inside the body always matches the HTTP status of the response.
func writeUpstreamError(w http.ResponseWriter, r *http.Request, cfg *config, pe *proxyError) {
	writeCORSHeaders(w, r, cfg)
	writeJSON(w, pe.Status, pe)
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

// authorizedRequest is what authorizeRequest hands a handler that may proceed.
type authorizedRequest struct {
	// target is the parsed, pre-checked target URL.
	target *url.URL
	// localStart reports that target is an --allow-local target. Only then may
	// the request — and every redirect hop it follows — reach a local address
	// (LOCAL-6). The handler puts it on the request context (withLocalStart),
	// from which every upstream request and the dialer read it.
	localStart bool
}

// authorizeRequest runs the checks every authenticated endpoint shares: method,
// CORS preflight, origin, token, target URL and the SSRF pre-check.
//
// It returns the parsed target and true when the caller should proceed. When it
// returns false it has already written the complete response — including the
// 204 for a preflight — and the caller must return immediately.
func authorizeRequest(w http.ResponseWriter, r *http.Request, cfg *config, allowedMethods ...string) (*authorizedRequest, bool) {
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

	// Purely syntactic (no DNS): is the start URL itself an --allow-local
	// target? Decides whether this request may reach local addresses at all.
	localStart := cfg.allowLocalMatchURL(target)

	if blocked, reason := cfg.precheck(r.Context(), target, localStart); blocked {
		writeJSONErrorReason(w, r, cfg, "blocked_target", reason, "target resolves to a private or reserved address", http.StatusForbidden)
		return nil, false
	}

	return &authorizedRequest{target: target, localStart: localStart}, true
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

	// Timeouts arrive in many shapes — a dial timeout as *net.OpError, an
	// expired request context, the transport's TLS-handshake or header-wait
	// deadline — and each would otherwise be filed under connection_error or
	// upstream_error. Checked before DNS so a timed-out lookup counts as a
	// timeout, as cURL's errno 28 does on the PHP side.
	if isTimeout(err) {
		return "timeout", "upstream request timed out"
	}

	// DNS resolution failure.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "dns_error", "could not resolve hostname"
	}

	// TLS certificate verification errors. The specific x509 errors come
	// first: crypto/tls wraps them in a *tls.CertificateVerificationError, and
	// checking that wrapper first would make them unreachable.
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
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return "tls_error", "TLS certificate verification failed"
	}

	// The target answered, but not with TLS — typically a plain HTTP server
	// behind an https:// URL. http.Client replaces the RecordHeaderError with
	// ErrSchemeMismatch when the answer looks like HTTP, which is the usual
	// case (https:// on port 80); a bare handshake still sees the former.
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) || errors.Is(err, http.ErrSchemeMismatch) {
		return "tls_error", "upstream did not respond with TLS"
	}

	// Connection refused / unreachable — but not every *net.OpError is a socket
	// failure. crypto/tls reports handshake alerts (protocol version, cipher
	// suite, certificate_required, …) as an *net.OpError with Op "remote error"
	// or "local error", wrapping an unexported alert type that errors.As cannot
	// reach. Without this split those land in connection_error and the caller
	// cannot tell "host is down" from "TLS could not be negotiated".
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		if opErr.Op == "remote error" || opErr.Op == "local error" {
			return "tls_error", "TLS handshake failed"
		}
		return "connection_error", "could not connect to upstream host"
	}

	// Everything else crypto/tls rejects locally is a bare fmt.Errorf carrying
	// no type at all — the package's "tls: " message prefix is the only marker
	// (261 such errors in Go 1.27). The one that matters here is a server still
	// stuck on TLS 1.0/1.1: "tls: server selected unsupported protocol version
	// 301". Read the prefix off the innermost error, never off the chain — the
	// wrapping *url.Error carries the caller-supplied URL, so matching the
	// flattened message would let a query string forge a TLS verdict.
	if leaf := leafError(err); leaf != nil && strings.HasPrefix(leaf.Error(), "tls: ") {
		return "tls_error", "TLS handshake failed"
	}

	return "upstream_error", "upstream request failed"
}

// isTimeout reports whether err stems from a deadline: an expired context or a
// net.Error that says so itself.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

// upstreamFailure turns a failed upstream request into the complete JSON error
// object: code, display-safe message, HTTP status (504 for a timeout, 502
// otherwise) and the PHP-style type text. ctx is the request's own context; its
// expired deadline is authoritative even when the transport reports the
// cancellation in some other shape.
func upstreamFailure(ctx context.Context, err error) *proxyError {
	code, message := classifyUpstreamError(err)
	if ctx != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		code, message = "timeout", "upstream request timed out"
	}
	status := http.StatusBadGateway
	if code == "timeout" {
		status = http.StatusGatewayTimeout
	}
	pe := &proxyError{Error: code, Message: message, Status: status, Type: proxyErrorType(code, err)}
	// A dialer block names its reason (private, not_allowlisted, always_blocked).
	var be *blockedError
	if code == "blocked_target" && errors.As(err, &be) {
		pe.Reason = be.reason
	}
	return pe
}

// proxyErrorType returns the human-readable class for an error code, matching
// the texts the PHP proxy reports in error.type. For tls_error it is the
// classified TLS failure, using the server's unverified chain when crypto/tls
// handed one over.
func proxyErrorType(code string, err error) string {
	switch code {
	case "tls_error":
		var certs []*x509.Certificate
		var cve *tls.CertificateVerificationError
		if errors.As(err, &cve) {
			certs = cve.UnverifiedCertificates
		}
		errorType, _ := classifyTLSFailure(err, certs, time.Now())
		return errorType
	case "dns_error":
		return "Could not resolve host"
	case "connection_error":
		return "Could not connect to host"
	case "timeout":
		return "Connection timeout"
	case "blocked_target":
		return "Blocked target"
	// The /page redirect tracer stops a chain for reasons of its own.
	case "redirect_loop":
		return "Redirect loop detected"
	case "too_many_redirects":
		return "Too many redirects"
	case "bad_request":
		return "Invalid URL"
	default:
		return "Upstream error"
	}
}

// leafError unwraps err down to the innermost error in the chain. Returns nil
// for a nil error, so callers must nil-check before calling Error on it.
func leafError(err error) error {
	for err != nil {
		next := errors.Unwrap(err)
		if next == nil {
			break
		}
		err = next
	}
	return err
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
		// Only a successful connect counts. With Happy Eyeballs several dials
		// race, and a losing racer's late, failed ConnectDone would otherwise
		// overwrite the winner — reporting an IP (and a probe target) that
		// never served the response.
		ConnectDone: func(_, addr string, err error) {
			if err != nil {
				return
			}
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

// maxProxyRedirects is how many redirects /proxy follows with follow=1 — the
// limit the PHP proxy's fetchUrl uses.
const maxProxyRedirects = 5

// isFollowableRedirect reports a status whose Location /proxy follows. 300 and
// 304 carry no single target to go to; they are returned as they are.
func isFollowableRedirect(status int) bool {
	switch status {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		return true
	}
	return false
}

// proxyHandler returns an http.Handler that validates requests and forwards
// them to the upstream URL supplied in the "url" query parameter.
//
// A redirect is never handed to the browser as such: Location is dropped and
// the resolved target travels as X-Upstream-Location instead. With Location
// present, fetch() would follow it straight to the target — carrying the
// X-Proxy-Token header to a third party whenever that target's CORS policy
// let the preflight through.
//
// With "follow=1" (GET and HEAD only; ignored for POST, which must not be
// replayed) the proxy follows up to maxProxyRedirects redirects itself, each
// target passing the SSRF pre-check first, and reports where it ended up in
// X-Upstream-Final-URL and X-Upstream-Redirects.
func proxyHandler(cfg *config, client *http.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		// ------------------------------------------------------------------
		// 1.-4. Method, CORS preflight, origin, token, target URL, SSRF.
		// ------------------------------------------------------------------
		auth, ok := authorizeRequest(w, r, cfg,
			http.MethodGet, http.MethodHead, http.MethodPost)
		if !ok {
			return
		}
		target := auth.target
		// Every upstream request below derives its context from r, so the
		// dialer sees whether this request may reach local targets.
		r = r.WithContext(withLocalStart(r.Context(), auth.localStart))
		follow := r.URL.Query().Get("follow") == "1" && r.Method != http.MethodPost

		// ------------------------------------------------------------------
		// 5. Execute the upstream request — and, with follow=1, each redirect
		//    hop. Every hop gets a connTrace of its own, so the metadata
		//    headers below describe the response actually returned. All hops
		//    share one timeout.
		// ------------------------------------------------------------------
		ctx, cancel := context.WithTimeout(r.Context(), cfg.requestTimeout)
		defer cancel()

		// Only POST forwards the browser's body; GET and HEAD send none.
		var attachBody func(*http.Request)
		if r.Method == http.MethodPost {
			attachBody = func(req *http.Request) { req.Body = r.Body }
		}

		current := target
		visited := map[string]bool{current.String(): true}
		redirects := 0
		var (
			resp         *http.Response
			ct           *connTrace
			requestStart time.Time
		)
		for {
			var err error
			resp, ct, requestStart, err = doTraced(ctx, client, r.Method, current.String(), r, attachBody)
			if err != nil {
				log.Printf("upstream error: %v", err)
				writeUpstreamError(w, r, cfg, upstreamFailure(ctx, err))
				return
			}
			if !follow || !isFollowableRedirect(resp.StatusCode) || redirects == maxProxyRedirects {
				break
			}
			// A redirect without a usable target, or back to a URL already
			// visited, is returned as it is — the caller sees the 3xx.
			next, err := resolveRedirect(current, lastLocation(resp.Header))
			if err != nil || visited[next.String()] {
				break
			}
			// A public start never leads into an --allow-local target: a
			// compromised site could otherwise redirect into the user's own
			// network (LOCAL-6). Checked before the pre-check, which would
			// report the hop as merely private or not allowlisted.
			if !auth.localStart && cfg.allowLocalMatchURL(next) {
				resp.Body.Close()
				writeUpstreamError(w, r, cfg, &proxyError{
					Error:   "blocked_target",
					Message: "redirect from a public start URL into a local target",
					Status:  http.StatusForbidden,
					Type:    proxyErrorType("blocked_target", nil),
					Reason:  reasonRedirectIntoLocal,
				})
				return
			}
			// SSRF pre-check on each redirect target, as for the original URL.
			// The dialer enforces this again for the actual connection.
			if blocked, reason := cfg.precheck(ctx, next, auth.localStart); blocked {
				resp.Body.Close()
				writeUpstreamError(w, r, cfg, &proxyError{
					Error:   "blocked_target",
					Message: "redirect target resolves to a private or reserved address",
					Status:  http.StatusForbidden,
					Type:    proxyErrorType("blocked_target", nil),
					Reason:  reason,
				})
				return
			}
			resp.Body.Close()
			visited[next.String()] = true
			current = next
			redirects++
		}
		defer resp.Body.Close()

		// ------------------------------------------------------------------
		// 6. Write CORS headers + upstream response headers to the client.
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
		// Where a redirect points, resolved against the URL that returned it
		// (RFC 3986), in place of the Location header that is never forwarded.
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			if loc := lastLocation(resp.Header); loc != "" {
				if next, err := resolveRedirect(current, loc); err == nil {
					w.Header().Set("X-Upstream-Location", next.String())
				}
			}
		}
		if follow {
			w.Header().Set("X-Upstream-Final-URL", current.String())
			w.Header().Set("X-Upstream-Redirects", strconv.Itoa(redirects))
		}
		// Build explicit Access-Control-Expose-Headers from the forwarded
		// response headers (wildcard "*" doesn't work with specific origins
		// per spec).
		exposeSet := make(map[string]struct{})
		dynamic := connectionTokens(resp.Header)
		for key := range resp.Header {
			if forwardsResponseHeader(strings.ToLower(key), dynamic) {
				exposeSet[key] = struct{}{}
			}
		}
		// Include our custom metadata headers.
		for _, h := range []string{
			"X-Upstream-Protocol", "X-Upstream-IP", "X-Upstream-Timing",
			"X-Upstream-Content-Encoding", "X-Upstream-Content-Length",
			"X-Upstream-Truncated", "X-Upstream-Location",
			"X-Upstream-Final-URL", "X-Upstream-Redirects",
		} {
			exposeSet[h] = struct{}{}
		}
		w.Header().Set("Access-Control-Expose-Headers", strings.Join(slices.Sorted(maps.Keys(exposeSet)), ", "))
		w.Header().Set("X-Content-Type-Options", "nosniff")

		cl := resp.Header.Get("Content-Length")
		ce := resp.Header.Get("Content-Encoding")

		// ------------------------------------------------------------------
		// 7. Stream the response body (capped at maxResponseBytes if set).
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
			// Compressed but chunked — buffer to count transfer size. Because
			// the whole (capped) body is read before WriteHeader, a cut can
			// still be announced here, unlike in the plain streaming branch
			// below. readCapped reads one byte past the cap to know.
			bodyBytes, truncated, err := readCapped(resp.Body, cfg.maxResponseBytes)
			if err != nil {
				log.Printf("warn: error buffering response body: %v", err)
			}
			// No upstream Content-Length reaches the client in this branch
			// (cl == ""); make sure none is sent, so net/http frames the
			// buffered bytes itself and never promises more than delivered.
			w.Header().Del("Content-Length")
			// On truncation this is the cap, i.e. a lower bound of the size.
			w.Header().Set("X-Upstream-Content-Length", strconv.Itoa(len(bodyBytes)))
			if truncated {
				w.Header().Set("X-Upstream-Truncated", "1")
				log.Printf("warn: chunked %s body truncated to %d bytes", ce, cfg.maxResponseBytes)
			}
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
	// Method is the method of the request this result describes: "HEAD", or
	// "GET" with body=1, with get=1, or after the target answered a HEAD with
	// 405/501.
	Method string `json:"method"`
	// Location is the response's last Location value, resolved against the
	// target URL (RFC 3986) to an absolute URL without userinfo. Empty unless
	// the response is a 3xx with a usable Location.
	Location string `json:"location,omitempty"`
	// Truncated reports that the body (body=1) hit MaxBodySize, either on the
	// wire or after decoding.
	Truncated bool `json:"truncated"`
	// MaxBodySize is the configured body cap in bytes; 0 means unlimited.
	MaxBodySize int64 `json:"maxBodySize"`
	// DecodeError reports that the body (body=1) carries a Content-Encoding
	// that could not be decoded. Body then holds only what was decoded — never
	// the raw compressed bytes.
	DecodeError bool `json:"decodeError,omitempty"`
	// Error is only set with diag=1, when the upstream request failed. The
	// response is then HTTP 200 with Status 0, so the caller gets the error
	// class and — for tls_error — the certificate details in one object.
	Error *proxyError `json:"error,omitempty"`
}

// sslInfo holds TLS certificate details extracted from the connection.
//
// The first twelve fields are the original v1.0 shape and keep Go's naming.
// The rest mirrors what the PHP proxy reports (OpenSSL naming), so the tools
// can render both modes with the same code.
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

	// Protocol is the TLS version in OpenSSL notation ("TLSv1.3", "TLSv1"),
	// which the tools match against; Version keeps the Go-style name.
	Protocol string `json:"protocol"`
	// Cipher is the OpenSSL name of the negotiated suite, CipherSuite its IANA
	// name and Bits its symmetric strength. Empty/0 when no handshake state is
	// available (certSource "verify-error").
	Cipher      string `json:"cipher"`
	CipherSuite string `json:"cipherSuite"`
	Bits        int    `json:"bits"`
	// Verified reports whether the content connection passed verification
	// against the trust store; Valid is the same value under the name the seo
	// tool reads.
	Verified bool `json:"verified"`
	Valid    bool `json:"valid"`
	// Error is the failure in OpenSSL verify-result wording (seo ssl.error),
	// ErrorType the classified failure (dns-ssl error.type). Null if verified.
	Error     *string `json:"error"`
	ErrorType *string `json:"errorType"`
	// HostMatch reports whether the leaf covers the requested host (RFC 6125).
	// Null when the host is unknown or not ASCII (Go has no IDNA in the stdlib,
	// so a U-label cannot be compared with the A-labels in the certificate).
	HostMatch  *bool       `json:"hostMatch"`
	SelfSigned bool        `json:"selfSigned"`
	Issues     []certIssue `json:"issues"`
	// CertSource says where the chain came from: "connection" (the verified
	// content connection), "probe" (the handshake-only diagnostic probe) or
	// "verify-error" (the chain crypto/tls attached to its verification error).
	CertSource string `json:"certSource"`
	// ProbeError is a generic note that the diagnostic probe failed; the
	// details only go to the log.
	ProbeError string `json:"probeError,omitempty"`
}

// certIssue is one finding about a certificate chain, as the PHP proxy's
// certificateIssues() reports it.
type certIssue struct {
	Type string `json:"type"` // "error" | "warning"
	Msg  string `json:"msg"`
}

// chainLink represents one certificate in the chain.
//
// Subject and Issuer are the original v1.0 fields. Everything else mirrors the
// PHP proxy's describeProxyCertificate() and buildProxyCertificateChain() in
// names, formats and semantics.
type chainLink struct {
	Subject string `json:"subject"` // first CN, else first O, else "Unknown"
	Issuer  string `json:"issuer"`

	Position           int      `json:"position"`       // 1-based, server order
	Label              string   `json:"label"`          // "Server certificate", "Intermediate CA", …
	SignatureValid     *bool    `json:"signatureValid"` // signed by the next cert (or itself); null if the issuer was not sent
	SubjectOrg         *string  `json:"subjectOrg"`
	SubjectDN          string   `json:"subjectDN"` // "C=US, O=Example, CN=example.com" (DER order)
	IssuerOrg          *string  `json:"issuerOrg"`
	IssuerDN           string   `json:"issuerDN"`
	SelfIssued         bool     `json:"selfIssued"`
	IsCA               bool     `json:"isCA"`
	ValidFrom          string   `json:"validFrom"` // "2006-01-02 15:04:05 UTC"
	ValidUntil         string   `json:"validUntil"`
	ValidFromTs        int64    `json:"validFromTs"` // Unix seconds
	ValidUntilTs       int64    `json:"validUntilTs"`
	DaysLeft           int      `json:"daysLeft"`           // floored, negative once expired
	Serial             string   `json:"serial"`             // "01:EE:…"
	SignatureAlgorithm string   `json:"signatureAlgorithm"` // OpenSSL long name
	Key                string   `json:"key"`                // "RSA 2048 bit", "EC P-256 (256 bit)", …
	KeyBits            *int     `json:"keyBits"`            // RSA only
	SANs               []string `json:"sans"`               // DNS names, then IP addresses
	SHA256             string   `json:"sha256"`
	SHA1               string   `json:"sha1"`
	PEM                string   `json:"pem"`
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

// tlsProtocolName maps a TLS version to OpenSSL's notation, which is what the
// PHP proxy reports and what the tools test for outdated protocols.
func tlsProtocolName(v uint16) string {
	switch v {
	case 0x0300: // SSL 3.0 — the tls constant is deprecated; Go never negotiates it
		return "SSLv3"
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return ""
	}
}

// openSSLCipher is the OpenSSL name and symmetric strength of a cipher suite.
type openSSLCipher struct {
	name string
	bits int
}

// openSSLCiphers covers every suite in tls.CipherSuites() and
// tls.InsecureCipherSuites() (a test keeps it complete). TLS 1.3 suites carry
// their IANA names in OpenSSL too.
var openSSLCiphers = map[uint16]openSSLCipher{
	tls.TLS_AES_128_GCM_SHA256:       {"TLS_AES_128_GCM_SHA256", 128},
	tls.TLS_AES_256_GCM_SHA384:       {"TLS_AES_256_GCM_SHA384", 256},
	tls.TLS_CHACHA20_POLY1305_SHA256: {"TLS_CHACHA20_POLY1305_SHA256", 256},

	tls.TLS_RSA_WITH_RC4_128_SHA:        {"RC4-SHA", 128},
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:   {"DES-CBC3-SHA", 112},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA:    {"AES128-SHA", 128},
	tls.TLS_RSA_WITH_AES_256_CBC_SHA:    {"AES256-SHA", 256},
	tls.TLS_RSA_WITH_AES_128_CBC_SHA256: {"AES128-SHA256", 128},
	tls.TLS_RSA_WITH_AES_128_GCM_SHA256: {"AES128-GCM-SHA256", 128},
	tls.TLS_RSA_WITH_AES_256_GCM_SHA384: {"AES256-GCM-SHA384", 256},

	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:              {"ECDHE-ECDSA-RC4-SHA", 128},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:          {"ECDHE-ECDSA-AES128-SHA", 128},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:          {"ECDHE-ECDSA-AES256-SHA", 256},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:       {"ECDHE-ECDSA-AES128-SHA256", 128},
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       {"ECDHE-ECDSA-AES128-GCM-SHA256", 128},
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       {"ECDHE-ECDSA-AES256-GCM-SHA384", 256},
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: {"ECDHE-ECDSA-CHACHA20-POLY1305", 256},

	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:              {"ECDHE-RSA-RC4-SHA", 128},
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:         {"ECDHE-RSA-DES-CBC3-SHA", 112},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:          {"ECDHE-RSA-AES128-SHA", 128},
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:          {"ECDHE-RSA-AES256-SHA", 256},
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:       {"ECDHE-RSA-AES128-SHA256", 128},
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:       {"ECDHE-RSA-AES128-GCM-SHA256", 128},
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:       {"ECDHE-RSA-AES256-GCM-SHA384", 256},
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: {"ECDHE-RSA-CHACHA20-POLY1305", 256},
}

// openSSLCipherName returns the OpenSSL name and strength of a suite, falling
// back to the IANA name (and 0 bits) for anything the table does not know.
func openSSLCipherName(id uint16) (name string, bits int) {
	if c, ok := openSSLCiphers[id]; ok {
		return c.name, c.bits
	}
	return tls.CipherSuiteName(id), 0
}

// openSSLSigAlgName maps a signature algorithm to OpenSSL's long name. The
// weak-algorithm rule in certificateIssues matches on these names.
func openSSLSigAlgName(a x509.SignatureAlgorithm) string {
	switch a {
	case x509.MD2WithRSA:
		return "md2WithRSAEncryption"
	case x509.MD5WithRSA:
		return "md5WithRSAEncryption"
	case x509.SHA1WithRSA:
		return "sha1WithRSAEncryption"
	case x509.SHA256WithRSA:
		return "sha256WithRSAEncryption"
	case x509.SHA384WithRSA:
		return "sha384WithRSAEncryption"
	case x509.SHA512WithRSA:
		return "sha512WithRSAEncryption"
	case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
		return "rsassaPss"
	case x509.DSAWithSHA1:
		return "dsaWithSHA1"
	case x509.DSAWithSHA256:
		return "dsa_with_SHA256"
	case x509.ECDSAWithSHA1:
		return "ecdsa-with-SHA1"
	case x509.ECDSAWithSHA256:
		return "ecdsa-with-SHA256"
	case x509.ECDSAWithSHA384:
		return "ecdsa-with-SHA384"
	case x509.ECDSAWithSHA512:
		return "ecdsa-with-SHA512"
	case x509.PureEd25519:
		return "ED25519"
	default:
		return a.String()
	}
}

var (
	oidCommonName   = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidOrganization = asn1.ObjectIdentifier{2, 5, 4, 10}
)

// dnShortNames maps attribute OIDs to OpenSSL's short names. Anything else is
// printed as a dotted OID.
var dnShortNames = map[string]string{
	"2.5.4.6":                    "C",
	"2.5.4.8":                    "ST",
	"2.5.4.7":                    "L",
	"2.5.4.10":                   "O",
	"2.5.4.11":                   "OU",
	"2.5.4.3":                    "CN",
	"2.5.4.5":                    "serialNumber",
	"2.5.4.9":                    "street",
	"2.5.4.17":                   "postalCode",
	"2.5.4.4":                    "SN",
	"2.5.4.42":                   "GN",
	"2.5.4.15":                   "businessCategory",
	"2.5.4.97":                   "organizationIdentifier",
	"1.2.840.113549.1.9.1":       "emailAddress",
	"0.9.2342.19200300.100.1.25": "DC",
	"1.3.6.1.4.1.311.60.2.1.1":   "jurisdictionL",
	"1.3.6.1.4.1.311.60.2.1.2":   "jurisdictionST",
	"1.3.6.1.4.1.311.60.2.1.3":   "jurisdictionC",
}

// nameAttributes returns the attributes of n in DER order. A parsed name has
// them in Names; a name built in code only has the convenience fields, so the
// sequence is rebuilt from those.
func nameAttributes(n pkix.Name) []pkix.AttributeTypeAndValue {
	if len(n.Names) > 0 {
		return n.Names
	}
	var attrs []pkix.AttributeTypeAndValue
	for _, rdn := range n.ToRDNSequence() {
		attrs = append(attrs, rdn...)
	}
	return attrs
}

// formatDN renders a distinguished name the way the PHP proxy does: short
// names in DER order, "key=value" joined by ", ". A repeated key emits all its
// values at the position of its first occurrence ("OU=a, OU=b, CN=x") — a
// quirk of PHP's parsed-array representation, kept for identical output.
func formatDN(n pkix.Name) string {
	var order []string
	values := make(map[string][]string)
	for _, atv := range nameAttributes(n) {
		key, ok := dnShortNames[atv.Type.String()]
		if !ok {
			key = atv.Type.String()
		}
		if _, seen := values[key]; !seen {
			order = append(order, key)
		}
		values[key] = append(values[key], fmt.Sprint(atv.Value))
	}
	parts := make([]string, 0, len(order))
	for _, key := range order {
		for _, v := range values[key] {
			parts = append(parts, key+"="+v)
		}
	}
	return strings.Join(parts, ", ")
}

// firstAttr returns the first value of the given attribute, or "". The first
// one, not the last: pkix.Name.CommonName keeps the last CN, PHP the first.
func firstAttr(n pkix.Name, oid asn1.ObjectIdentifier) string {
	for _, atv := range nameAttributes(n) {
		if atv.Type.Equal(oid) {
			return fmt.Sprint(atv.Value)
		}
	}
	return ""
}

// nameLabel is the short display name of a certificate name: the first CN,
// else the first O, else "Unknown".
func nameLabel(n pkix.Name) string {
	if cn := firstAttr(n, oidCommonName); cn != "" {
		return cn
	}
	if o := firstAttr(n, oidOrganization); o != "" {
		return o
	}
	return "Unknown"
}

// optionalString returns nil for "", so the JSON carries null like PHP does.
func optionalString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// describePublicKey describes the certificate's public key like the PHP
// proxy. rsaBits is set for RSA keys only — it feeds the weak-key rule.
func describePublicKey(c *x509.Certificate) (desc string, rsaBits *int) {
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		if pub == nil || pub.N == nil {
			return "Unknown", nil
		}
		bits := pub.N.BitLen()
		return fmt.Sprintf("RSA %d bit", bits), &bits
	case *ecdsa.PublicKey:
		if pub == nil || pub.Curve == nil {
			return "Unknown", nil
		}
		params := pub.Curve.Params()
		name := params.Name
		if name == "P-224" {
			// PHP only shortens the three common NIST curves; any other keeps
			// its OpenSSL name.
			name = "secp224r1"
		}
		return fmt.Sprintf("EC %s (%d bit)", name, params.BitSize), nil
	case ed25519.PublicKey:
		return "Ed25519", nil
	case *dsa.PublicKey:
		if pub == nil || pub.P == nil {
			return "Unknown", nil
		}
		return fmt.Sprintf("DSA %d bit", pub.P.BitLen()), nil
	default:
		// Includes a nil key, and X25519 (*ecdh.PublicKey) — the only other key
		// type crypto/x509 parses, which a TLS server certificate cannot use.
		// PHP's "Other (N bit)" branch therefore has no Go equivalent.
		return "Unknown", nil
	}
}

// colonHex renders bytes as upper-case hex pairs joined by ":".
func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}

// certTimeLayout is the PHP proxy's date format, gmdate('Y-m-d H:i:s \U\T\C').
const certTimeLayout = "2006-01-02 15:04:05 UTC"

// daysUntil returns the whole days from now until t, floored like the PHP
// proxy's floor((validTo - time()) / 86400) — negative once t has passed.
// Integer Unix seconds, never time.Duration: t.Sub saturates at ~292 years,
// and a NotAfter of 9999-12-31 (RFC 5280's "no expiration") is far beyond.
func daysUntil(t, now time.Time) int {
	d := t.Unix() - now.Unix()
	days := d / 86400
	if d%86400 != 0 && d < 0 {
		days-- // Go truncates toward zero; floor rounds down
	}
	return int(days)
}

// isSelfIssued reports whether subject and issuer are the same name. An empty
// raw name (a certificate built in code rather than parsed) never counts.
func isSelfIssued(c *x509.Certificate) bool {
	return len(c.RawSubject) > 0 && bytes.Equal(c.RawSubject, c.RawIssuer)
}

// isSelfSigned reports whether the certificate is self-issued and carries a
// valid signature made with its own key.
func isSelfSigned(c *x509.Certificate) bool {
	return isSelfIssued(c) && signatureValid(c, c)
}

// servedChainReachesRoot reports whether the leaf (certs[0]) links up to a
// self-signed certificate through the certificates the server sent — each
// step an issuer whose subject matches and whose key made the signature, in
// any order. Like OpenSSL's verify error 19 versus 20: a self-signed root
// the leaf cannot reach (intermediate missing or wrong) leaves the chain
// incomplete rather than ending in an untrusted root. Each step moves to a
// certificate not yet visited, so the walk ends after len(certs) steps.
func servedChainReachesRoot(certs []*x509.Certificate) bool {
	if len(certs) < 2 {
		return false
	}
	visited := make([]bool, len(certs))
	visited[0] = true
	cur := certs[0]
	for {
		next := -1
		for i, c := range certs {
			if !visited[i] && bytes.Equal(c.RawSubject, cur.RawIssuer) && signatureValid(cur, c) {
				next = i
				break
			}
		}
		if next < 0 {
			return false
		}
		if isSelfSigned(certs[next]) {
			return true
		}
		visited[next] = true
		cur = certs[next]
	}
}

// describeCertificate builds the per-certificate report, everything except
// the chain-dependent Position, Label and SignatureValid.
func describeCertificate(c *x509.Certificate, now time.Time) chainLink {
	key, keyBits := describePublicKey(c)

	sans := make([]string, 0, len(c.DNSNames)+len(c.IPAddresses))
	sans = append(sans, c.DNSNames...)
	for _, ip := range c.IPAddresses {
		sans = append(sans, ip.String())
	}

	// SerialNumber is nil only for a certificate built in code; a parsed one
	// always has it. Bytes() is the magnitude — negative serials never get
	// here, crypto/x509 refuses to parse them.
	serial := ""
	if c.SerialNumber != nil {
		if serial = colonHex(c.SerialNumber.Bytes()); serial == "" {
			serial = "00"
		}
	}

	sum256 := sha256.Sum256(c.Raw)
	sum1 := sha1.Sum(c.Raw)
	pemText := ""
	if len(c.Raw) > 0 {
		pemText = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}

	return chainLink{
		Subject:            nameLabel(c.Subject),
		Issuer:             nameLabel(c.Issuer),
		SubjectOrg:         optionalString(firstAttr(c.Subject, oidOrganization)),
		SubjectDN:          formatDN(c.Subject),
		IssuerOrg:          optionalString(firstAttr(c.Issuer, oidOrganization)),
		IssuerDN:           formatDN(c.Issuer),
		SelfIssued:         isSelfIssued(c),
		IsCA:               c.BasicConstraintsValid && c.IsCA,
		ValidFrom:          c.NotBefore.UTC().Format(certTimeLayout),
		ValidUntil:         c.NotAfter.UTC().Format(certTimeLayout),
		ValidFromTs:        c.NotBefore.Unix(),
		ValidUntilTs:       c.NotAfter.Unix(),
		DaysLeft:           daysUntil(c.NotAfter, now),
		Serial:             serial,
		SignatureAlgorithm: openSSLSigAlgName(c.SignatureAlgorithm),
		Key:                key,
		KeyBits:            keyBits,
		SANs:               sans,
		SHA256:             colonHex(sum256[:]),
		SHA1:               colonHex(sum1[:]),
		PEM:                pemText,
	}
}

// signatureValid reports whether parent's key made child's signature — a pure
// signature check like openssl_x509_verify, nothing else. Not
// CheckSignatureFrom: that also demands that parent is a CA, which would
// report a self-signed leaf as broken.
func signatureValid(child, parent *x509.Certificate) bool {
	if child == nil || parent == nil || parent.PublicKey == nil {
		return false
	}
	err := parent.CheckSignature(child.SignatureAlgorithm, child.RawTBSCertificate, child.Signature)
	if err == nil {
		return true
	}
	// crypto/x509 refuses MD5 outright, OpenSSL still checks it. Only the
	// display depends on this; nothing is ever trusted because of it.
	var insecure x509.InsecureAlgorithmError
	if errors.As(err, &insecure) && child.SignatureAlgorithm == x509.MD5WithRSA {
		if pub, ok := parent.PublicKey.(*rsa.PublicKey); ok {
			sum := md5.Sum(child.RawTBSCertificate)
			return rsa.VerifyPKCS1v15(pub, crypto.MD5, sum[:], child.Signature) == nil
		}
	}
	return false
}

// maxChainCerts caps how many certificates of a served chain are described.
const maxChainCerts = 10

// rootWord matches a CA named "… Root …"; such a CA with an issuer other than
// itself is a cross-signed root acting as an intermediate.
var rootWord = regexp.MustCompile(`(?i)\broot\b`)

// buildCertificateChain describes the chain in server order (leaf first), with
// each certificate's position, label and whether the next one signed it.
func buildCertificateChain(certs []*x509.Certificate, now time.Time) []chainLink {
	if len(certs) > maxChainCerts {
		certs = certs[:maxChainCerts]
	}
	chain := make([]chainLink, 0, len(certs))
	for i, c := range certs {
		link := describeCertificate(c, now)
		link.Position = i + 1

		switch {
		case link.SelfIssued:
			v := signatureValid(c, c)
			link.SignatureValid = &v
		case i+1 < len(certs):
			v := signatureValid(c, certs[i+1])
			link.SignatureValid = &v
		}

		switch {
		case i == 0:
			link.Label = "Server certificate"
		case link.SelfIssued && link.SignatureValid != nil && *link.SignatureValid:
			link.Label = "Root CA (self-signed)"
		case link.IsCA && rootWord.MatchString(link.Subject):
			link.Label = "Cross-signed root (acts as intermediate)"
		case link.IsCA:
			link.Label = "Intermediate CA"
		default:
			link.Label = "Certificate"
		}
		chain = append(chain, link)
	}
	return chain
}

// isASCII reports whether s contains only ASCII bytes.
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

// certMatchesHost reports whether the certificate names cover host, with the
// rules of the PHP proxy (RFC 6125): the SANs, or the subject if there are
// none; exact match after lower-casing and dropping trailing dots; a "*."
// wildcard covers exactly one non-empty label. IP hosts are compared as IPs,
// which also matches an IPv6 SAN written differently.
//
// Returns nil when there is no host to check, or when it is not ASCII: Go has
// no IDNA in the stdlib, and a U-label never equals the A-labels a certificate
// carries, so any answer would be a false "not covered".
func certMatchesHost(host string, sans []string, cn string) *bool {
	h := strings.TrimRight(strings.ToLower(strings.Trim(host, "[]")), ".")
	if h == "" || !isASCII(h) {
		return nil
	}
	names := sans
	if len(names) == 0 {
		names = []string{cn}
	}
	hostIP := net.ParseIP(h)

	match := false
	for _, name := range names {
		n := strings.TrimRight(strings.ToLower(name), ".")
		if hostIP != nil {
			if ip := net.ParseIP(n); ip != nil && ip.Equal(hostIP) {
				match = true
				break
			}
			continue
		}
		if n == h {
			match = true
			break
		}
		if strings.HasPrefix(n, "*.") {
			suffix := n[1:]
			if strings.HasSuffix(h, suffix) {
				if label := h[:len(h)-len(suffix)]; label != "" && !strings.Contains(label, ".") {
					match = true
					break
				}
			}
		}
	}
	return &match
}

// weakSigAlg is the PHP rule for weak signature algorithms. PHP's pattern
// misses "ecdsa-with-SHA1"; certificateIssues adds that case explicitly.
var weakSigAlg = regexp.MustCompile(`(?i)md5|sha1With|sha1-`)

// certificateIssues is a port of the dns-ssl tool's certificateIssues(): the
// same rules, order and English messages.
func certificateIssues(chain []chainLink, hostMatch *bool, selfSigned bool, now time.Time) []certIssue {
	issues := []certIssue{}
	if len(chain) == 0 {
		return issues
	}
	add := func(typ, format string, args ...any) {
		issues = append(issues, certIssue{Type: typ, Msg: fmt.Sprintf(format, args...)})
	}

	leaf := chain[0]
	switch ts := now.Unix(); {
	case leaf.ValidUntilTs < ts:
		days := leaf.DaysLeft
		if days < 0 {
			days = -days
		}
		add("error", "The certificate expired %d days ago.", days)
	case leaf.ValidFromTs > ts:
		add("error", "The certificate is not valid yet.")
	case leaf.DaysLeft <= 14:
		add("warning", "The certificate expires in %d days.", leaf.DaysLeft)
	}

	if hostMatch != nil && !*hostMatch {
		add("error", "The host name is not covered by the certificate (CN/SAN).")
	}
	if selfSigned {
		add("error", "The certificate is self-signed — browsers will not trust it.")
	}

	for _, c := range chain {
		weak := weakSigAlg.MatchString(c.SignatureAlgorithm) ||
			strings.HasSuffix(strings.ToUpper(c.SignatureAlgorithm), "-SHA1")
		if weak && !(c.SelfIssued && c.Position > 1) {
			add("warning", "%s: weak signature algorithm (%s).", c.Subject, c.SignatureAlgorithm)
		}
		if c.KeyBits != nil && *c.KeyBits < 2048 {
			add("warning", "%s: RSA key with only %d bit.", c.Subject, *c.KeyBits)
		}
	}

	last := chain[len(chain)-1]
	if len(chain) == 1 && !selfSigned {
		add("warning", "The server sends no intermediate certificate — some clients cannot build the chain.")
	} else if last.SignatureValid != nil && !*last.SignatureValid {
		add("error", "The chain is broken: %s is not signed by the next certificate.", last.Subject)
	}

	for _, c := range chain {
		if c.Position < len(chain) && c.SignatureValid != nil && !*c.SignatureValid {
			add("error", "Chain order or content is wrong: %s is not signed by the following certificate.", c.Subject)
			break
		}
	}
	return issues
}

// -----------------------------------------------------------------------
// TLS verdict and the handshake-only diagnostic probe
// -----------------------------------------------------------------------

// classifyTLSFailure explains a failed TLS connection in the PHP proxy's two
// vocabularies: errorType as the dns-ssl tool shows it (classifyProxySslError)
// and verifyText as OpenSSL's verify result (seo ssl.error).
//
// err — the content connection's real error — is authoritative: it carries
// the platform's actual trust decision. certs (from the probe, or the chain
// crypto/tls attached to the error) only sub-classify an unknown authority.
func classifyTLSFailure(err error, certs []*x509.Certificate, now time.Time) (errorType, verifyText string) {
	var invalid x509.CertificateInvalidError
	if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
		// crypto/x509 uses Expired for both ends of the validity window.
		notYet := strings.Contains(invalid.Detail, "is before")
		if invalid.Cert != nil {
			notYet = now.Before(invalid.Cert.NotBefore)
		}
		if notYet {
			return "Certificate not yet valid", "Certificate is not yet valid"
		}
		return "Certificate expired", "Certificate has expired"
	}

	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return "Host name does not match the certificate", "Hostname mismatch"
	}

	var unknown x509.UnknownAuthorityError
	var noRoots x509.SystemRootsError
	if errors.As(err, &unknown) || errors.As(err, &noRoots) {
		if len(certs) > 0 && isSelfSigned(certs[0]) {
			return "Self-signed certificate", "Self-signed certificate"
		}
		if servedChainReachesRoot(certs) {
			return "Untrusted root certificate in the chain", "Self-signed certificate in chain"
		}
		return "Incomplete chain or unknown issuer", "Unable to get local issuer certificate"
	}

	// Any other verification failure: a CA not allowed to sign, no valid chain
	// (e.g. a distrusted root), a wrong key usage, or an untyped error from a
	// platform verifier (macOS, Windows).
	var cve *tls.CertificateVerificationError
	if errors.As(err, &invalid) || errors.As(err, &cve) {
		return "TLS/SSL error", "Certificate not trusted"
	}

	// Handshake failures. A plain-HTTP answer surfaces as RecordHeaderError
	// (or http.ErrSchemeMismatch, see classifyUpstreamError);
	// a protocol-version mismatch either as the peer's alert or as crypto/tls'
	// own untyped error. Both carry "protocol version" in the innermost error
	// — read there, never off the chain, which includes the caller's URL.
	var recordErr tls.RecordHeaderError
	if errors.As(err, &recordErr) || errors.Is(err, http.ErrSchemeMismatch) {
		return "TLS protocol not supported", "TLS protocol not supported"
	}
	if leaf := leafError(err); leaf != nil && strings.Contains(leaf.Error(), "protocol version") {
		return "TLS protocol not supported", "TLS protocol not supported"
	}
	return "TLS/SSL error", "TLS handshake failed"
}

// tlsProbeTimeout bounds the diagnostic handshake (dial included).
const tlsProbeTimeout = 10 * time.Second

// probeFailedMessage is all the client learns about a failed probe.
const probeFailedMessage = "TLS handshake for certificate details failed"

// errNoProbeAddress is logged when there is no connected address to probe.
var errNoProbeAddress = errors.New("no connected address to probe")

// probeTLS performs a handshake-only TLS connection to ip:port to read what a
// failing server presents: protocol, cipher and its certificate chain.
//
// It runs only on request (diag=1) after a tls_error, against the IP the failed
// request had already connected to — so there is no second DNS lookup and no
// rebinding window — and it dials through the configured Control hook, i.e.
// safeDialControl in production, which re-checks that literal IP.
//
// For a request whose start URL is an --allow-local target (localStartFrom on
// ctx) the probe decides exactly as localGuard does: when localVerdict allows
// host on that IP, it may dial that one ip:port and nothing else (LOCAL-5).
func probeTLS(ctx context.Context, cfg *config, host, port, ip string) (*tls.ConnectionState, error) {
	ctx, cancel := context.WithTimeout(ctx, tlsProbeTimeout) // never exceeds the parent's deadline
	defer cancel()

	control := cfg.dialControlOrDefault()
	if parsed := net.ParseIP(ip); parsed != nil && localStartFrom(ctx) &&
		cfg.localVerdict(host, port, parsed) == verdictAllowed {
		control = exactAddressControl(parsed, port, control)
	}
	dialer := &net.Dialer{Timeout: tlsProbeTimeout, Control: control}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return nil, err
	}
	defer raw.Close()

	// No SNI for a literal IP (as PHP does), nor for a non-ASCII host, which
	// is not a valid server_name and would need IDNA to become one.
	sni := host
	if net.ParseIP(host) != nil || !isASCII(host) {
		sni = ""
	}

	// Every suite Go still implements, so servers stuck on RSA key exchange,
	// 3DES or RC4 still show their certificate.
	suites := make([]uint16, 0, len(openSSLCiphers))
	for _, s := range tls.CipherSuites() {
		suites = append(suites, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		suites = append(suites, s.ID)
	}

	// SECURITY: handshake-only diagnostic. InsecureSkipVerify is required to
	// *see* a chain that fails verification. This connection never carries
	// application data: nothing is written or read after the handshake, and it
	// is never handed to an http.Transport. The trust verdict reported to the
	// client comes from the verified content connection (classifyTLSFailure),
	// not from this probe.
	tc := tls.Client(raw, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		CipherSuites:       suites,
	})
	if deadline, ok := ctx.Deadline(); ok {
		_ = tc.SetDeadline(deadline)
	}
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	state := tc.ConnectionState()
	_ = tc.Close()
	return &state, nil
}

// diagnoseTLSFailure builds the certificate report for a request that failed
// with a tls_error: the chain and handshake details from the probe, or — when
// the probe fails — the unverified chain crypto/tls attached to the error.
// Returns nil when neither is available.
func diagnoseTLSFailure(ctx context.Context, cfg *config, target *url.URL, ip string, reqErr error, now time.Time) *sslInfo {
	host := target.Hostname()
	port := target.Port()
	if port == "" {
		port = "443"
	}

	var state *tls.ConnectionState
	probeErr := errNoProbeAddress
	if ip != "" {
		state, probeErr = probeTLS(ctx, cfg, host, port, ip)
	}

	var (
		certs  []*x509.Certificate
		source string
		note   string
	)
	var cve *tls.CertificateVerificationError
	switch {
	case probeErr == nil && len(state.PeerCertificates) > 0:
		certs, source = state.PeerCertificates, "probe"
	case errors.As(reqErr, &cve) && len(cve.UnverifiedCertificates) > 0:
		log.Printf("tls probe for %s failed: %v", host, probeErr)
		certs, source, note = cve.UnverifiedCertificates, "verify-error", probeFailedMessage
		state = nil
	default:
		log.Printf("tls probe for %s failed: %v", host, probeErr)
		return nil
	}

	errorType, verifyText := classifyTLSFailure(reqErr, certs, now)
	info := buildSSLInfo(certs, state, host, false, &verifyText, &errorType, source, now)
	if info != nil {
		info.ProbeError = note
	}
	return info
}

// diagnoseRequestTLS runs diagnoseTLSFailure for a diag=1 request with a budget
// of its own, derived from the client's request: the upstream timeout may
// already be used up by the request that failed.
func diagnoseRequestTLS(r *http.Request, cfg *config, target *url.URL, ip string, reqErr error) *sslInfo {
	ctx, cancel := context.WithTimeout(r.Context(), tlsProbeTimeout)
	defer cancel()
	return diagnoseTLSFailure(ctx, cfg, target, ip, reqErr, time.Now())
}

// buildSSLInfo assembles the certificate report. certs is the chain in server
// order; state, when known, supplies the negotiated protocol and cipher.
// verified is the content connection's verdict, with verifyText and errorType
// explaining a failure (nil when verified).
func buildSSLInfo(certs []*x509.Certificate, state *tls.ConnectionState, host string, verified bool,
	verifyText, errorType *string, source string, now time.Time) *sslInfo {
	if len(certs) == 0 {
		return nil
	}
	leaf := certs[0]
	chain := buildCertificateChain(certs, now)

	info := &sslInfo{
		Subject:            leaf.Subject.CommonName,
		Issuer:             leaf.Issuer.CommonName,
		ValidFrom:          leaf.NotBefore.UTC().Format(time.RFC3339),
		ValidTo:            leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysLeft:           daysUntil(leaf.NotAfter, now),
		SANs:               chain[0].SANs, // DNS names and IPs: an IP-only cert would otherwise report none
		Chain:              chain,
		SignatureAlgorithm: leaf.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: leaf.PublicKeyAlgorithm.String(),
		Verified:           verified,
		Valid:              verified,
		Error:              verifyText,
		ErrorType:          errorType,
		CertSource:         source,
	}
	if len(leaf.Subject.Organization) > 0 {
		info.Organization = leaf.Subject.Organization[0]
	}
	if len(leaf.Issuer.Organization) > 0 {
		info.IssuerOrg = leaf.Issuer.Organization[0]
	}
	if state != nil {
		info.Version = tlsVersionName(state.Version)
		info.Protocol = tlsProtocolName(state.Version)
		info.Cipher, info.Bits = openSSLCipherName(state.CipherSuite)
		info.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	}

	info.HostMatch = certMatchesHost(host, chain[0].SANs, chain[0].Subject)
	info.SelfSigned = chain[0].SelfIssued && chain[0].SignatureValid != nil && *chain[0].SignatureValid
	info.Issues = certificateIssues(chain, info.HostMatch, info.SelfSigned, now)
	return info
}

// extractSSLInfo builds an sslInfo struct from a verified TLS connection to
// host. An empty host leaves hostMatch null.
func extractSSLInfo(state *tls.ConnectionState, host string) *sslInfo {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}
	return buildSSLInfo(state.PeerCertificates, state, host, true, nil, nil, "connection", time.Now())
}

// doTraced performs one upstream request with a connTrace of its own, attached
// to that request only — so timing and IP describe exactly this request, not a
// probe that ran before it. The caller closes resp.Body.
func doTraced(ctx context.Context, client *http.Client, method, target string, browserReq *http.Request,
	tweak func(*http.Request)) (resp *http.Response, ct *connTrace, start time.Time, err error) {
	ct = &connTrace{}
	start = time.Now()
	req, err := http.NewRequestWithContext(ct.attach(ctx), method, target, nil)
	if err != nil {
		return nil, ct, start, err
	}
	copyRequestHeaders(browserReq, req)
	if tweak != nil {
		tweak(req)
	}
	resp, err = client.Do(req)
	return resp, ct, start, err
}

// isHeadRefused reports a status that means "this server does not do HEAD".
// /inspect and the /page redirect tracer then repeat the request with GET.
func isHeadRefused(status int) bool {
	return status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented
}

// probeContentEncoding asks the target with a HEAD — carrying the browser's
// full Accept-Encoding — which Content-Encoding it really prefers (br, zstd,
// …). The body GET that follows only accepts what the stdlib can decode, so
// its own header would hide that. The HEAD is untraced: reported timing and
// IP belong to the GET. Returns "" on failure; the GET reports the error.
func probeContentEncoding(ctx context.Context, client *http.Client, target string, browserReq *http.Request) string {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return ""
	}
	copyRequestHeaders(browserReq, req)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	resp.Body.Close()
	return resp.Header.Get("Content-Encoding")
}

// inspectHandler returns an http.Handler that performs a request to the
// target URL and returns connection metadata (SSL, timing, headers, IP,
// protocol) as a JSON response. The response body is included when the
// "body" query parameter is set to "1".
//
// With "get=1" (and no body=1), the headers come from a GET whose body is
// closed unread instead of a HEAD — what the PHP proxy's headers-only fetch
// (cURL CUSTOMREQUEST GET + NOBODY) puts on the wire. Some servers send
// different headers to HEAD; www.google.com, for instance, only sends
// Strict-Transport-Security on GET.
//
// With "diag=1", an upstream failure is reported inline (HTTP 200 with an
// error object) and a tls_error additionally carries the certificate details
// the failing server presented.
func inspectHandler(cfg *config, client *http.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		auth, ok := authorizeRequest(w, r, cfg, http.MethodGet, http.MethodHead)
		if !ok {
			return
		}
		target := auth.target
		// Carried to the dialer and the TLS probe (see proxyHandler).
		r = r.WithContext(withLocalStart(r.Context(), auth.localStart))

		query := r.URL.Query()
		includeBody := query.Get("body") == "1"
		headersViaGET := query.Get("get") == "1" && !includeBody
		diag := query.Get("diag") == "1"

		ctx, cancel := context.WithTimeout(r.Context(), cfg.requestTimeout)
		defer cancel()

		// When body=1, we need two pieces of information:
		// 1. The server's true preferred Content-Encoding (may be zstd, br, etc.)
		// 2. A decompressed body (only gzip/deflate possible with stdlib)
		//
		// Strategy: send a HEAD request first with the browser's full
		// Accept-Encoding to discover the server's preferred encoding,
		// then send the GET with Accept-Encoding limited to gzip/deflate
		// so we can decompress the body. The HEAD-detected encoding is
		// restored in the final header map.
		//
		// The HEAD runs untraced: the reported timing and IP belong to the GET.
		var serverContentEncoding string
		if includeBody {
			serverContentEncoding = probeContentEncoding(ctx, client, target.String(), r)
		}

		// HEAD unless the body (or a headers-only GET) is wanted. For body
		// requests, limit Accept-Encoding to what stdlib can decompress
		// (gzip, deflate).
		method := http.MethodHead
		var limitEncoding func(*http.Request)
		if includeBody {
			method = http.MethodGet
			limitEncoding = func(req *http.Request) { req.Header.Set("Accept-Encoding", "gzip, deflate") }
		} else if headersViaGET {
			method = http.MethodGet
		}
		resp, ct, requestStart, err := doTraced(ctx, client, method, target.String(), r, limitEncoding)

		// get=1: headers only. Close the body unread — with keep-alives
		// disabled the connection goes with it, so the page is never
		// downloaded (same as the 405/501 fallback below).
		if err == nil && headersViaGET {
			resp.Body.Close()
		}

		// Some servers refuse HEAD (405) or never implemented it (501). Repeat
		// with GET, as the PHP proxy does, but only for the headers: the body
		// is closed unread, and with keep-alives disabled the connection goes
		// with it — a large page is never downloaded.
		if err == nil && method == http.MethodHead && isHeadRefused(resp.StatusCode) {
			resp.Body.Close()
			method = http.MethodGet
			resp, ct, requestStart, err = doTraced(ctx, client, method, target.String(), r, nil)
			if err == nil {
				resp.Body.Close()
			}
		}

		if err != nil {
			log.Printf("inspect upstream error: %v", err)
			failure := upstreamFailure(ctx, err)
			if !diag {
				writeUpstreamError(w, r, cfg, failure)
				return
			}
			result := inspectResponse{
				Headers:     map[string][]string{},
				Timing:      ct.timingMap(requestStart),
				IP:          ct.remoteIP(),
				Method:      method,
				MaxBodySize: cfg.maxResponseBytes,
				Error:       failure,
			}
			if failure.Error == "tls_error" {
				result.SSL = diagnoseRequestTLS(r, cfg, target, result.IP, err)
			}
			writeCORSHeaders(w, r, cfg)
			writeJSON(w, http.StatusOK, result)
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

		// Read body if requested, decompressing based on the GET's actual
		// Content-Encoding. Both the wire bytes and the decoded text are capped.
		var body cappedBody
		if includeBody {
			body = readDecodedBody(resp.Body, resp.Header.Get("Content-Encoding"), cfg.maxResponseBytes)
		}

		// Where a redirect points, already resolved — the caller follows it
		// with another /inspect without re-implementing RFC 3986.
		var location string
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			if loc := lastLocation(resp.Header); loc != "" {
				if next, err := resolveRedirect(target, loc); err == nil {
					location = next.String()
				}
			}
		}

		result := inspectResponse{
			Status:      resp.StatusCode,
			Headers:     hdrs,
			SSL:         extractSSLInfo(resp.TLS, target.Hostname()),
			Timing:      timingMap,
			IP:          ct.remoteIP(),
			Protocol:    resp.Proto,
			HTTP3:       altSvcAdvertisesHTTP3(resp.Header),
			Body:        string(body.data),
			Method:      method,
			Location:    location,
			Truncated:   body.truncated,
			MaxBodySize: cfg.maxResponseBytes,
			DecodeError: body.decodeError,
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
// (nil, nil) for any other value (identity, empty, one the stdlib cannot decode
// such as br/zstd, or an unknown token). readDecodedBody decides what to do
// with those bytes.
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

// readCapped reads at most limit bytes (limit <= 0: unlimited) and reports
// whether the stream held more. It reads one byte past the cap to know.
func readCapped(r io.Reader, limit int64) (data []byte, truncated bool, err error) {
	if limit <= 0 {
		data, err = io.ReadAll(r)
		return data, false, err
	}
	data, err = io.ReadAll(io.LimitReader(r, limit+1))
	if int64(len(data)) > limit {
		return data[:limit], true, err
	}
	return data, false, err
}

// trimPartialUTF8 drops an incomplete UTF-8 sequence at the end of b — what a
// byte cap leaves behind when it cuts through a multi-byte character (the
// equivalent of PHP's mb_strcut). Invalid bytes are left alone.
func trimPartialUTF8(b []byte) []byte {
	for i := len(b) - 1; i >= 0 && i >= len(b)-utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if !utf8.FullRune(b[i:]) {
				return b[:i]
			}
			return b
		}
	}
	return b
}

// cappedBody is an upstream body read under the size cap and decoded.
type cappedBody struct {
	data        []byte // decoded text — never raw compressed bytes
	rawSize     int    // bytes read off the wire, before decoding
	truncated   bool   // the wire bytes or the decoded text hit the cap
	decodeError bool   // the Content-Encoding could not be decoded; data is what was
}

// knownContentCodings holds the registered compressing or encrypting content
// codings (IANA "HTTP Content Coding Registry", RFC 9110 §8.4.1) other than
// identity. A body in one of them is never text as it stands. gzip, x-gzip and
// deflate are decoded; the rest the stdlib cannot decode.
var knownContentCodings = map[string]struct{}{
	"gzip": {}, "x-gzip": {}, "deflate": {},
	"br": {}, "zstd": {}, "compress": {}, "x-compress": {},
	"dcb": {}, "dcz": {}, "aes128gcm": {}, "exi": {}, "pack200-gzip": {},
}

// contentCodings splits a Content-Encoding field into its lower-case tokens,
// dropping empty ones and identity.
func contentCodings(field string) []string {
	var out []string
	for _, tok := range strings.Split(field, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok != "" && tok != "identity" {
			out = append(out, tok)
		}
	}
	return out
}

// readDecodedBody reads r under limit (applied to the wire bytes and again to
// the decoded text, against zip-bomb-style payloads) and decodes it according
// to encoding.
//
// Encodings are handled in three classes:
//
//   - a single gzip, x-gzip or deflate is decoded;
//   - a registered coding the stdlib cannot decode (br, zstd, compress, dcb,
//     dcz, …; see knownContentCodings), or a stack of codings ("gzip, br"),
//     yields no data and decodeError: handing the compressed bytes on as if
//     they were text would put binary garbage into a JSON string;
//   - any other token is a server misconfiguration ("none", "UTF-8",
//     "text/html", "binary", …) that real sites send with a plain body. The
//     bytes are passed through when they are valid UTF-8 (as v1.2.4 did);
//     otherwise they get the same treatment as an undecodable coding.
//
// A stream that breaks off midway keeps what was decoded, also with
// decodeError — unless the cap cut the wire bytes, which ends every decoder
// early and is truncation, not corruption.
func readDecodedBody(r io.Reader, encoding string, limit int64) cappedBody {
	raw, rawTruncated, err := readCapped(r, limit)
	if err != nil {
		log.Printf("warn: error reading upstream body: %v", err)
	}
	body := cappedBody{data: raw, rawSize: len(raw), truncated: rawTruncated}

	codings := contentCodings(encoding)
	if len(codings) > 0 && len(raw) > 0 {
		enc := strings.Join(codings, ", ")
		known := false
		for _, c := range codings {
			if _, ok := knownContentCodings[c]; ok {
				known = true
			}
		}
		var dec io.ReadCloser
		var err error
		if len(codings) == 1 {
			dec, err = newDecompressor(bytes.NewReader(raw), enc)
		}
		switch {
		case err != nil:
			log.Printf("warn: could not decompress body (%s): %v", enc, err)
			body.data, body.decodeError = nil, true
		case dec == nil && !known:
			// Unregistered token: plain text mislabelled, or binary. A cut
			// through a multi-byte character at the cap is not binary.
			check := raw
			if rawTruncated {
				check = trimPartialUTF8(raw)
			}
			if !utf8.Valid(check) {
				log.Printf("warn: unknown Content-Encoding %q with a non-UTF-8 body", enc)
				body.data, body.decodeError = nil, true
			}
		case dec == nil:
			body.data, body.decodeError = nil, true
		default:
			decoded, decodedTruncated, readErr := readCapped(dec, limit)
			dec.Close()
			body.data = decoded
			body.truncated = body.truncated || decodedTruncated
			if readErr != nil && !rawTruncated {
				log.Printf("warn: error decompressing body (%s): %v", enc, readErr)
				body.decodeError = true
			}
		}
	}

	if body.truncated {
		body.data = trimPartialUTF8(body.data)
	}
	return body
}

// -----------------------------------------------------------------------
// Redirect targets
// -----------------------------------------------------------------------

// errUnsupportedRedirectScheme is returned for a redirect that leaves
// http/https (javascript:, data:, ftp:, …).
var errUnsupportedRedirectScheme = errors.New("redirect target uses an unsupported scheme")

// lastLocation returns the last Location value, or "". With several values the
// last one wins, as in the PHP proxy.
func lastLocation(h http.Header) string {
	vals := h.Values("Location")
	if len(vals) == 0 {
		return ""
	}
	return vals[len(vals)-1]
}

// resolveRedirect resolves a Location value against the URL that returned it
// (RFC 3986 §5.2, which url.ResolveReference implements). Userinfo is dropped,
// like the PHP proxy does, and only http/https targets are accepted.
func resolveRedirect(base *url.URL, loc string) (*url.URL, error) {
	ref, err := url.Parse(strings.TrimSpace(loc))
	if err != nil {
		return nil, err
	}
	next := base.ResolveReference(ref)
	next.User = nil
	if next.Scheme != "http" && next.Scheme != "https" {
		return nil, errUnsupportedRedirectScheme
	}
	return next, nil
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
	// Method is "HEAD", or "GET" when the target refused HEAD with 405/501 or
	// for the final hop. Absent on hops the tracer stopped without a request
	// (loop, hop limit, blocked target), like the PHP proxy's {hop, url, error}.
	Method string `json:"method,omitempty"`
	// Location is the resolved, absolute target of a 3xx hop.
	Location string `json:"location,omitempty"`
	// ErrorCategory is the proxy error code of a failed hop (tls_error,
	// dns_error, timeout, redirect_loop, too_many_redirects, blocked_target, …).
	ErrorCategory string `json:"errorCategory,omitempty"`
	// ErrorReason is the error's reason sub-code (since v1.4.0), set where the
	// top-level error carries one — a blocked_target hop.
	ErrorReason string `json:"errorReason,omitempty"`
	// ErrorType is the classified failure text, only for a tls_error hop.
	ErrorType string `json:"errorType,omitempty"`
	// Certificate summary of the hop's verified connection (https only).
	// CertCN is the leaf's common name alone — no O fallback, as in PHP.
	CertCN       string `json:"certCN,omitempty"`
	CertExpiry   string `json:"certExpiry,omitempty"` // "2006-01-02"
	CertDaysLeft *int   `json:"certDaysLeft,omitempty"`
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
	// Truncated reports that the body hit MaxBodySize, on the wire or after
	// decoding; HTML then ends at the cap (on a UTF-8 boundary).
	Truncated bool `json:"truncated"`
	// MaxBodySize is the configured body cap in bytes; 0 means unlimited.
	MaxBodySize int64 `json:"maxBodySize"`
	// DecodeError reports a Content-Encoding that could not be decoded. HTML
	// then holds only what was decoded — never the raw compressed bytes.
	DecodeError bool `json:"decodeError,omitempty"`
}

// formatRawHeaders renders response headers as a raw string (one per line),
// keys sorted: Go cannot recover the server's order, so at least make it
// deterministic.
func formatRawHeaders(h http.Header) string {
	var sb strings.Builder
	for _, key := range slices.Sorted(maps.Keys(h)) {
		for _, v := range h[key] {
			sb.WriteString(key)
			sb.WriteString(": ")
			sb.WriteString(v)
			sb.WriteByte('\n')
		}
	}
	return sb.String()
}

// statusLine renders the response's status line the way it appears in a raw
// header block: "HTTP/1.1 301 Moved Permanently". HTTP/2 and later have no
// reason phrase on the wire (Go synthesises one), so they read "HTTP/2 200" —
// what cURL shows on the PHP side.
func statusLine(resp *http.Response) string {
	if resp.ProtoMajor >= 2 {
		return fmt.Sprintf("HTTP/%d %d", resp.ProtoMajor, resp.StatusCode)
	}
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	status := resp.Status
	if status == "" {
		status = strings.TrimSpace(strconv.Itoa(resp.StatusCode) + " " + http.StatusText(resp.StatusCode))
	}
	return proto + " " + status
}

// rawHeaderBlock is the status line followed by the sorted header lines.
func rawHeaderBlock(resp *http.Response) string {
	return statusLine(resp) + "\n" + formatRawHeaders(resp.Header)
}

// setHopCert adds the certificate summary of a hop's verified connection.
func setHopCert(hop *pageHop, state *tls.ConnectionState, now time.Time) {
	if state == nil || len(state.PeerCertificates) == 0 {
		return
	}
	leaf := state.PeerCertificates[0]
	days := daysUntil(leaf.NotAfter, now)
	hop.CertCN = firstAttr(leaf.Subject, oidCommonName) // the first CN, like PHP
	hop.CertExpiry = leaf.NotAfter.UTC().Format("2006-01-02")
	hop.CertDaysLeft = &days
}

// hopFailure describes where and why traceRedirectChain stopped early.
type hopFailure struct {
	// pe is the error /page reports at the top level. Its code is the failed
	// hop's errorCategory — never empty — and its message the hop's error.
	pe *proxyError
	// err is the transport error; nil when one of the tracer's own rules
	// stopped the chain (loop, hop limit, blocked target, time budget).
	err error
	// url is the URL that failed; nil when it could not be parsed.
	url *url.URL
	// ip is the address the failed request had connected to, if any — the
	// one the TLS diagnostic probe may contact.
	ip string
}

// chainStop builds the top-level error for a chain stopped by one of the
// tracer's own rules. message is the hop's error text, reason its sub-code
// ("" for none).
func chainStop(code, reason, message string) *proxyError {
	status := http.StatusBadGateway
	if code == "timeout" {
		status = http.StatusGatewayTimeout
	}
	return &proxyError{Error: code, Message: message, Status: status, Type: proxyErrorType(code, nil), Reason: reason}
}

// traceRedirectChain follows redirect hops via HEAD requests, recording
// timing, IP, headers, status and the certificate summary for each 3xx hop.
// A server that refuses HEAD (405/501) is asked again with GET, whose body is
// closed unread. Returns the chain, the final URL (which may be the original
// URL if no redirects occurred) and — when the chain stopped early — why. The
// last hop then carries the error.
//
// The parent context carries the overall budget for the /page request. Each hop
// additionally gets its own per-request timeout, but the parent deadline always
// wins — otherwise maxHops slow redirects could keep the handler alive for
// maxHops × requestTimeout, and a client disconnect would not stop any of it.
//
// Whether the chain may reach --allow-local targets is read from parent
// (localStartFrom): a public start never redirects into one.
func traceRedirectChain(parent context.Context, client *http.Client, startURL string, browserReq *http.Request,
	maxHops int, cfg *config) (hops []pageHop, finalURL string, fail *hopFailure) {
	visited := make(map[string]bool)
	localStart := localStartFrom(parent)

	// stop appends an error-only hop for a rule that ended the chain.
	stop := func(hop int, rawURL string, u *url.URL, code, reason, message string) {
		hops = append(hops, pageHop{Hop: hop, URL: rawURL, Error: message, ErrorCategory: code, ErrorReason: reason})
		fail = &hopFailure{pe: chainStop(code, reason, message), url: u}
	}

	current, err := url.Parse(startURL)
	if err != nil {
		stop(1, startURL, nil, "bad_request", "", "invalid URL")
		return hops, startURL, fail
	}

	for i := 0; ; i++ {
		currentURL := current.String()
		if parent.Err() != nil {
			stop(i+1, currentURL, current, "timeout", "", "timeout: redirect chain exceeded the time budget")
			break
		}
		if visited[currentURL] {
			stop(i+1, currentURL, current, "redirect_loop", "", "redirect loop detected")
			break
		}
		// maxHops redirects followed, and the last request still redirected
		// here — a 21st redirect. Like the Fetch standard, exactly maxHops
		// redirects are fine.
		if i > maxHops {
			stop(i+1, currentURL, current, "too_many_redirects", "", fmt.Sprintf("too_many_redirects: more than %d redirects", maxHops))
			break
		}
		visited[currentURL] = true

		method := http.MethodHead
		ctx, cancel := context.WithTimeout(parent, cfg.requestTimeout)
		resp, ct, start, err := doTraced(ctx, client, method, currentURL, browserReq, nil)

		// Some servers refuse HEAD (405) or never implemented it (501), and
		// may well redirect a GET. Ask again with GET under a fresh per-hop
		// timeout, for the headers only: the body is closed unread, and with
		// keep-alives disabled the connection goes with it.
		if err == nil && isHeadRefused(resp.StatusCode) {
			resp.Body.Close()
			cancel()
			method = http.MethodGet
			ctx, cancel = context.WithTimeout(parent, cfg.requestTimeout)
			resp, ct, start, err = doTraced(ctx, client, method, currentURL, browserReq, nil)
		}

		hop := pageHop{
			Hop:    i + 1,
			URL:    currentURL,
			Method: method,
			SSL:    current.Scheme == "https",
			IP:     ct.remoteIP(),
			Timing: math.Round(ct.timingMap(start)["total"]*10) / 10,
		}

		if err != nil {
			// Classified before cancel(): the per-hop context's own deadline
			// tells a timeout apart from any other failure.
			pe := upstreamFailure(ctx, err)
			cancel()
			log.Printf("page redirect trace error: %v", err)
			hop.Error = pe.Error + ": " + pe.Message
			hop.ErrorCategory = pe.Error
			hop.ErrorReason = pe.Reason
			if pe.Error == "tls_error" {
				hop.ErrorType = pe.Type
			}
			pe.Message = hop.Error
			hops = append(hops, hop)
			fail = &hopFailure{pe: pe, err: err, url: current, ip: hop.IP}
			break
		}
		resp.Body.Close()
		cancel()

		hop.Status = resp.StatusCode
		hop.Server = resp.Header.Get("Server")
		hop.RawHeaders = rawHeaderBlock(resp)
		setHopCert(&hop, resp.TLS, time.Now())

		// Only record redirect hops (3xx). The final non-redirect hop is
		// handled by the caller (pageHandler) which does a GET with body.
		if resp.StatusCode < 300 || resp.StatusCode >= 400 {
			break
		}
		loc := lastLocation(resp.Header)
		if loc == "" {
			hops = append(hops, hop)
			break
		}
		next, err := resolveRedirect(current, loc)
		if err != nil {
			hops = append(hops, hop)
			if errors.Is(err, errUnsupportedRedirectScheme) {
				stop(i+2, strings.TrimSpace(loc), nil, "blocked_target", reasonUnsupportedScheme, "blocked_target: redirect target uses an unsupported scheme")
			} else {
				stop(i+2, strings.TrimSpace(loc), nil, "bad_request", "", "bad_request: invalid redirect target")
			}
			break
		}
		hop.Location = next.String()
		hops = append(hops, hop)

		// No redirect from a public start into an --allow-local target
		// (LOCAL-6); checked before the pre-check, as on /proxy.
		if !localStart && cfg.allowLocalMatchURL(next) {
			stop(i+2, next.String(), next, "blocked_target", reasonRedirectIntoLocal, "blocked_target: redirect from a public start URL into a local target")
			break
		}

		// SSRF pre-check on each redirect target. The dialer enforces this
		// again for the actual connection; this only fails faster and
		// records a clearer reason in the chain.
		if blocked, reason := cfg.precheck(parent, next, localStart); blocked {
			stop(i+2, next.String(), next, "blocked_target", reason, "blocked_target: redirect target resolves to a private or reserved address")
			break
		}
		current = next
	}

	return hops, current.String(), fail
}

// pageHandler returns an http.Handler for the /page endpoint.
//
// With "diag=1", a tls_error — in the redirect chain or on the final GET —
// additionally carries the certificate details the failing server presented,
// and finalUrl names that server's URL.
func pageHandler(cfg *config, client *http.Client) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		auth, ok := authorizeRequest(w, r, cfg, http.MethodGet)
		if !ok {
			return
		}
		target := auth.target
		// Carried to the redirect tracer, the dialer and the TLS probe (see
		// proxyHandler).
		r = r.WithContext(withLocalStart(r.Context(), auth.localStart))
		rawTarget := target.String()
		diag := r.URL.Query().Get("diag") == "1"

		// One budget for the whole endpoint. Derived from r.Context() so that a
		// client disconnect aborts every upstream request still in flight, and
		// bounded so that a target serving slow redirects cannot keep this
		// handler (and its connections) alive indefinitely.
		reqCtx, cancelBudget := context.WithTimeout(r.Context(), cfg.pageBudget())
		defer cancelBudget()

		// ---- Phase 1: Trace redirect chain --------------------------------
		const maxRedirects = 20
		hops, finalURL, fail := traceRedirectChain(reqCtx, client, rawTarget, r, maxRedirects, cfg)

		// The chain ended with an error: report it with its real code. The
		// final GET is skipped — there is no trustworthy URL to fetch.
		if fail != nil {
			result := pageResponse{
				URL:           rawTarget,
				FinalURL:      finalURL,
				RedirectChain: hops,
				IP:            fail.ip,
				MaxBodySize:   cfg.maxResponseBytes,
				Error:         fail.pe,
			}
			if diag && fail.pe.Error == "tls_error" && fail.url != nil {
				// As the PHP proxy does: the certificate report describes
				// the URL where the chain stopped.
				result.FinalURL = fail.url.String()
				result.SSL = diagnoseRequestTLS(r, cfg, fail.url, fail.ip, fail.err)
			}
			writeCORSHeaders(w, r, cfg)
			writeJSON(w, http.StatusOK, result)
			return
		}

		final, err := url.Parse(finalURL)
		if err != nil {
			// Unreachable: finalURL was produced by url.URL.String().
			final = target
		}

		// ---- Phase 2: HEAD probe for true Content-Encoding ----------------
		var serverContentEncoding string
		{
			ctx, cancel := context.WithTimeout(reqCtx, cfg.requestTimeout)
			serverContentEncoding = probeContentEncoding(ctx, client, finalURL, r)
			cancel()
		}

		// ---- Phase 3: GET final page with body ----------------------------
		ctx, cancel := context.WithTimeout(reqCtx, cfg.requestTimeout)
		defer cancel()

		limitEncoding := func(req *http.Request) { req.Header.Set("Accept-Encoding", "gzip, deflate") }
		resp, ct, requestStart, err := doTraced(ctx, client, http.MethodGet, finalURL, r, limitEncoding)
		if err != nil {
			log.Printf("page upstream error: %v", err)
			// upstreamFailure checks ctx — the final GET's own timeout, which
			// also expires with the overall budget — so a deadline is
			// reported as timeout (504) whatever shape the transport gave it.
			result := pageResponse{
				URL:           rawTarget,
				FinalURL:      finalURL,
				RedirectChain: hops,
				IP:            ct.remoteIP(),
				MaxBodySize:   cfg.maxResponseBytes,
				Error:         upstreamFailure(ctx, err),
			}
			if diag && result.Error.Error == "tls_error" {
				result.SSL = diagnoseRequestTLS(r, cfg, final, result.IP, err)
			}
			writeCORSHeaders(w, r, cfg)
			writeJSON(w, http.StatusOK, result)
			return
		}
		defer resp.Body.Close()

		// Read the body under the cap and decode it. Undecodable or corrupt
		// encodings never hand compressed bytes on as HTML (see readDecodedBody).
		actualEncoding := resp.Header.Get("Content-Encoding")
		body := readDecodedBody(resp.Body, actualEncoding, cfg.maxResponseBytes)

		// Transfer size = raw compressed bytes received from upstream. Prefer
		// the upstream Content-Length, but only when it is a sane value — it is
		// attacker-controlled and would otherwise land in the JSON verbatim.
		transferSize := body.rawSize
		if cl := resp.Header.Get("Content-Length"); cl != "" {
			if n, convErr := strconv.Atoi(cl); convErr == nil && n >= 0 {
				transferSize = n
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
		timingMap["downloadSize"] = float64(len(body.data))
		timingMap["speed"] = 0

		rawHeaders := rawHeaderBlock(resp)

		// Append final hop to redirect chain.
		finalHop := pageHop{
			Hop:        len(hops) + 1,
			URL:        finalURL,
			Method:     http.MethodGet,
			Status:     resp.StatusCode,
			SSL:        final.Scheme == "https",
			IP:         ct.remoteIP(),
			Timing:     timingMap["total"],
			Server:     resp.Header.Get("Server"),
			RawHeaders: rawHeaders,
		}
		setHopCert(&finalHop, resp.TLS, time.Now())
		hops = append(hops, finalHop)

		result := pageResponse{
			URL:             rawTarget,
			FinalURL:        finalURL,
			Status:          resp.StatusCode,
			HTTPVersion:     resp.Proto,
			HTTP3:           altSvcAdvertisesHTTP3(resp.Header),
			Headers:         hdrs,
			RawHeaders:      rawHeaders,
			HTML:            string(body.data),
			RedirectChain:   hops,
			SSL:             extractSSLInfo(resp.TLS, final.Hostname()),
			Timing:          timingMap,
			IP:              ct.remoteIP(),
			Size:            len(body.data),
			TransferSize:    transferSize,
			ContentEncoding: contentEncoding,
			Error:           nil,
			Truncated:       body.truncated,
			MaxBodySize:     cfg.maxResponseBytes,
			DecodeError:     body.decodeError,
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
// final GET all dial through the same transport, and the TLS diagnostic probe
// (probeTLS) dials with the same hook.
//
// It knows neither the requested host name nor the proxy's own port, so its
// blockedError says "private" or "always_blocked"; localGuard refines that
// (refineBlocked) where it knows more.
func safeDialControl(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Control is called post-resolution, so a non-IP here means something
		// unexpected happened. Refuse rather than guess.
		return &blockedError{detail: fmt.Sprintf("unresolved address %q", host), reason: reasonAlwaysBlocked}
	}
	if isBlockedIP(ip) {
		reason := reasonPrivate
		if isAlwaysBlockedIP(ip) {
			reason = reasonAlwaysBlocked
		}
		return &blockedError{ip: ip, addr: address, detail: ip.String(), reason: reason}
	}
	return nil
}

// blockedError is a connection the SSRF guard refused. It unwraps to
// errBlockedTarget, so classifyUpstreamError keeps reporting blocked_target,
// and upstreamFailure copies reason into the JSON error. Its text is the one
// v1.3.0 logged ("target address is blocked: 127.0.0.1").
type blockedError struct {
	ip     net.IP // the refused address; nil when there was none to parse
	addr   string // the dialled "ip:port", when known
	detail string // what Error() names after the common prefix
	reason string // reasonPrivate, reasonNotAllowlisted or reasonAlwaysBlocked
}

func (e *blockedError) Error() string { return errBlockedTarget.Error() + ": " + e.detail }
func (e *blockedError) Unwrap() error { return errBlockedTarget }

// isPrivateHost resolves the hostname and reports whether any of its addresses
// fall in a blocked range — the v1.3.0 pre-check without --allow-local, port
// and reason. A port or brackets in hostname are ignored.
//
// This is a fast pre-flight rejection so obvious cases fail before a connection
// is attempted; it is deliberately fail-open, because a lookup failure here
// would otherwise block legitimate domains during a DNS hiccup. Failing open is
// safe precisely because safeDialControl re-checks the real address later.
func isPrivateHost(ctx context.Context, hostname string, resolver *net.Resolver) bool {
	host, _, err := net.SplitHostPort(hostname)
	if err != nil {
		host = hostname
	}
	blocked, _ := (&config{resolver: resolver}).precheckHost(ctx, strings.Trim(host, "[]"), "", false)
	return blocked
}

// -----------------------------------------------------------------------
// Local targets (--allow-local)
// -----------------------------------------------------------------------
//
// Off by default. With --allow-local the user names the local sites the proxy
// may reach (a DDEV project, wp-env, an intranet host). The rules, in short:
//
//   - A name entry (exact or *.suffix) reaches loopback only — unless the
//     address also lies in an IP/CIDR entry. A spoofed DNS answer for a
//     listed name therefore cannot point the proxy into the LAN.
//   - An IP/CIDR entry allows URLs with an IP literal in that range, and opens
//     that range to the name entries.
//   - Without a port an entry covers 80 and 443 only.
//   - Some addresses are never reachable, whatever the list says
//     (isAlwaysBlockedIP, and loopback on the proxy's own port).
//   - Only a request whose start URL is on the list may reach a local target;
//     a redirect from a public start into one is refused (LOCAL-6).
//
// The decision falls in the dialer (localGuard), where the requested name and
// the address actually dialled are both known; the pre-check (precheck) and the
// TLS probe (probeTLS) apply the same rules through localVerdict.

// Reason sub-codes of blocked_target (proxyError.Reason, LOCAL-7).
const (
	// reasonPrivate: a private address, and --allow-local is not set — the
	// v1.3.0 case.
	reasonPrivate = "private"
	// reasonNotAllowlisted: --allow-local is set, but this target (name, port
	// or address) is not covered by it.
	reasonNotAllowlisted = "not_allowlisted"
	// reasonAlwaysBlocked: never reachable, with or without --allow-local.
	reasonAlwaysBlocked = "always_blocked"
	// reasonRedirectIntoLocal: a redirect from a public start URL into an
	// --allow-local target.
	reasonRedirectIntoLocal = "redirect_into_local"
	// reasonUnsupportedScheme: /page only, a redirect to a scheme other than
	// http/https.
	reasonUnsupportedScheme = "unsupported_scheme"
)

// strongerReason returns the stronger of two block reasons: always_blocked
// beats not_allowlisted beats private beats "" (not blocked).
func strongerReason(a, b string) string {
	rank := func(r string) int {
		switch r {
		case reasonAlwaysBlocked:
			return 3
		case reasonNotAllowlisted:
			return 2
		case reasonPrivate:
			return 1
		}
		return 0
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

// mustParseCIDRs parses a fixed CIDR table at startup.
func mustParseCIDRs(cidrs ...string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid CIDR: " + cidr)
		}
		nets = append(nets, network)
	}
	return nets
}

// allowableClasses are the parts of privateRangeCIDRs an --allow-local entry
// can open: loopback, RFC 1918, CGNAT and IPv6 unique local. Everything else in
// privateRangeCIDRs stays blocked whatever the list says (LOCAL-3).
var allowableClasses = mustParseCIDRs(
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
	"fc00::/7",
)

// metadataAddrs are cloud metadata services inside the allowable classes. They
// stay blocked even when an entry's range contains them.
var metadataAddrs = mustParseCIDRs(
	"fd00:ec2::254/128",  // AWS IMDS over IPv6 (in fc00::/7)
	"100.100.100.200/32", // Alibaba Cloud metadata (in 100.64.0.0/10)
)

// inAnyNet reports whether ip lies in one of nets.
func inAnyNet(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isAlwaysBlockedIP reports an address no --allow-local entry can open: a
// blocked range outside the allowable classes (link-local with the cloud
// metadata address 169.254.169.254, 0/8, multicast, documentation, NAT64 and
// 6to4, …) or one of metadataAddrs. nil counts as blocked.
func isAlwaysBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if !isBlockedIP(ip) {
		return false
	}
	return !inAnyNet(allowableClasses, ip) || inAnyNet(metadataAddrs, ip)
}

// allowEntryKind tells the three kinds of --allow-local entry apart.
type allowEntryKind int

const (
	entryName     allowEntryKind = iota // exactly this host name
	entryWildcard                       // any name ending in "."+host
	entryNet                            // an IP address or CIDR range
)

// allowEntry is one parsed --allow-local entry.
type allowEntry struct {
	kind allowEntryKind
	// host is the name (entryName) or the suffix after "*." (entryWildcard):
	// lower case, without a trailing dot.
	host string
	// network is the range of an entryNet; a single address is a /32 or /128.
	network *net.IPNet
	// port is the one port the entry allows; "" means 80 and 443.
	port string
}

// String renders the entry in its canonical form, as the banner shows it.
func (e allowEntry) String() string {
	var s string
	switch e.kind {
	case entryWildcard:
		s = "*." + e.host
	case entryNet:
		ones, bits := e.network.Mask.Size()
		s = e.network.IP.String()
		if ones != bits {
			s = e.network.String()
		}
		if e.network.IP.To4() == nil {
			s = "[" + s + "]"
		}
	default:
		s = e.host
	}
	if e.port != "" {
		s += ":" + e.port
	}
	return s
}

// portAllows applies the entry's port rule to a target port.
func (e allowEntry) portAllows(port string) bool {
	if e.port == "" {
		return port == "80" || port == "443"
	}
	return port == e.port
}

// matchesName reports whether a (normalised) host name falls under a name or
// wildcard entry, ignoring the port.
func (e allowEntry) matchesName(host string) bool {
	switch e.kind {
	case entryName:
		return host == e.host
	case entryWildcard:
		// At least one label in front: "*.ddev.site" covers "a.ddev.site" and
		// "a.b.ddev.site", but neither "ddev.site" nor "xddev.site".
		return strings.HasSuffix(host, "."+e.host) && len(host) > len(e.host)+1
	}
	return false
}

// dangerousPorts are services that must not be opened to browser pages, even
// on a local host the user trusts: an HTTP request there can reconfigure or
// read out the service.
var dangerousPorts = map[int]string{
	2375:  "Docker API",
	2376:  "Docker API (TLS)",
	2379:  "etcd",
	3306:  "MySQL",
	5432:  "PostgreSQL",
	6379:  "Redis",
	9200:  "Elasticsearch",
	10250: "kubelet",
	11211: "memcached",
	27017: "MongoDB",
}

// wildcardDNSServices are public DNS zones that resolve any name with an
// embedded IP to that IP (10.0.0.1.nip.io → 10.0.0.1). A wildcard on them
// would cover every address the user's network has.
var wildcardDNSServices = []string{"nip.io", "sslip.io", "xip.io", "localtest.me", "lvh.me", "traefik.me"}

// homeNetworkSuffixes name every device on a home network (router, NAS,
// printer — some routers change settings on a GET). Only exact names may use
// them.
var homeNetworkSuffixes = []string{"home.arpa", "fritz.box"}

// parseAllowLocal parses the --allow-local values (the flag may be repeated;
// each value is a comma-separated list) into entries. listenPort is --port; an
// entry may not name it. Every error names the offending entry.
func parseAllowLocal(values []string, listenPort int) ([]allowEntry, error) {
	var entries []allowEntry
	for _, value := range values {
		for _, raw := range strings.Split(value, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			e, err := parseAllowEntry(raw, listenPort)
			if err != nil {
				return nil, fmt.Errorf("--allow-local entry %q: %w", raw, err)
			}
			entries = append(entries, e)
		}
	}
	if len(entries) == 0 {
		return nil, errors.New("--allow-local is empty; to keep local targets off, leave the flag out")
	}
	return entries, nil
}

// quoteChars are the straight and typographic quotation marks that can reach
// an --allow-local value when a shell or a copied example leaves them in.
const quoteChars = "\"'\u201c\u201d\u201e\u2018\u2019\u201a\u00ab\u00bb"

// parseAllowEntry parses one --allow-local entry (see parseAllowLocal).
func parseAllowEntry(raw string, listenPort int) (allowEntry, error) {
	// Windows PowerShell 5.1, cmd.exe wrappers, shortcuts and typographic
	// quotes copied from a document can leave the quotation marks inside the
	// value; every later check would then report something misleading.
	if strings.ContainsAny(raw, quoteChars) {
		return allowEntry{}, errors.New("remove the quotation marks: they reached the proxy as part of the value (quote for the shell, not inside the value)")
	}
	hostPart, portPart, bracketed := raw, "", false
	hasPort := false
	switch {
	case strings.Contains(raw, "://"):
		// A pasted URL would otherwise fail later as a confusing "port".
		return allowEntry{}, errors.New(`write the host without a scheme or path, e.g. "wp.test" or "wp.test:8443"`)
	case strings.HasPrefix(raw, "["):
		end := strings.Index(raw, "]")
		if end < 0 {
			return allowEntry{}, errors.New(`missing "]"`)
		}
		hostPart, bracketed = raw[1:end], true
		if rest := raw[end+1:]; rest != "" {
			if !strings.HasPrefix(rest, ":") {
				return allowEntry{}, errors.New(`unexpected text after "]"`)
			}
			portPart, hasPort = rest[1:], true
		}
	case strings.Count(raw, ":") > 1:
		// fd00::5:8443 is itself a valid address; a port meant here would
		// silently become part of a different IP.
		return allowEntry{}, errors.New(`IPv6 addresses must be in brackets, e.g. "[fd00::5]" or "[fd00::5]:8443"`)
	case strings.Contains(raw, ":"):
		i := strings.LastIndex(raw, ":")
		hostPart, portPart, hasPort = raw[:i], raw[i+1:], true
	}

	e := allowEntry{}
	if hasPort {
		port, err := parseAllowPort(portPart, listenPort)
		if err != nil {
			return allowEntry{}, err
		}
		e.port = port
	}

	switch {
	case strings.Contains(hostPart, "/"):
		ip, network, err := net.ParseCIDR(hostPart)
		if err != nil {
			return allowEntry{}, errors.New("not a valid CIDR range")
		}
		if err := checkBrackets(ip, bracketed); err != nil {
			return allowEntry{}, err
		}
		if !ip.Equal(network.IP) {
			return allowEntry{}, fmt.Errorf("has host bits set; the range starts at %s", network.IP)
		}
		ones, bits := network.Mask.Size()
		switch {
		case ones == 0:
			return allowEntry{}, errors.New("would allow every address")
		case bits == 32 && ones < 16:
			return allowEntry{}, errors.New("IPv4 ranges must be /16 or narrower")
		case bits == 128 && ones < 48:
			return allowEntry{}, errors.New("IPv6 ranges must be /48 or narrower")
		}
		e.kind, e.network = entryNet, network
	case net.ParseIP(hostPart) != nil:
		ip := net.ParseIP(hostPart)
		if err := checkBrackets(ip, bracketed); err != nil {
			return allowEntry{}, err
		}
		if v4 := ip.To4(); v4 != nil {
			e.network = &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
		} else {
			e.network = &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
		}
		e.kind = entryNet
	default:
		if bracketed {
			return allowEntry{}, errors.New("brackets are for IPv6 addresses only")
		}
		kind, host, err := parseAllowName(hostPart)
		if err != nil {
			return allowEntry{}, err
		}
		e.kind, e.host = kind, host
	}

	if e.kind == entryNet {
		if err := checkAllowRange(e.network); err != nil {
			return allowEntry{}, err
		}
	}
	return e, nil
}

// parseAllowPort validates the port of an entry: digits only (no "*", no
// ranges), 1–65535, not the proxy's own port, not a dangerous service.
func parseAllowPort(s string, listenPort int) (string, error) {
	if s == "" {
		return "", errors.New("empty port")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return "", errors.New("the port must be a single number (no wildcards or ranges)")
		}
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return "", errors.New("the port must be between 1 and 65535")
	}
	if listenPort != 0 && n == listenPort {
		return "", fmt.Errorf("port %d is the proxy's own --port", n)
	}
	if name, ok := dangerousPorts[n]; ok {
		return "", fmt.Errorf("port %d (%s) is never allowed: a request from a web page could reconfigure or read out that service", n, name)
	}
	return strconv.Itoa(n), nil
}

// checkBrackets enforces "IPv6 in brackets, IPv4 without". An IPv4-mapped
// IPv6 form (::ffff:a.b.c.d) must be written as plain IPv4.
func checkBrackets(ip net.IP, bracketed bool) error {
	isV4 := ip.To4() != nil
	switch {
	case isV4 && bracketed:
		return errors.New("write IPv4 addresses without brackets")
	case !isV4 && !bracketed:
		return errors.New(`IPv6 addresses must be in brackets, e.g. "[fd00::5]"`)
	}
	return nil
}

// checkAllowRange accepts a range only when it lies wholly inside exactly one
// allowable class and is not one of the always-blocked metadata addresses.
func checkAllowRange(n *net.IPNet) error {
	first, last := n.IP, lastIP(n)
	for _, class := range allowableClasses {
		if class.Contains(first) && class.Contains(last) {
			for _, m := range metadataAddrs {
				if m.Contains(first) && m.Contains(last) {
					return errors.New("is a cloud metadata address and always blocked")
				}
			}
			return nil
		}
	}
	overlaps := false
	for _, blocked := range privateRangeCIDRs {
		if blocked.Contains(first) && blocked.Contains(last) {
			return errors.New("lies in a range that is always blocked (link-local, metadata, multicast, reserved or documentation space)")
		}
		if blocked.Contains(first) || blocked.Contains(last) || n.Contains(blocked.IP) {
			overlaps = true
		}
	}
	if overlaps {
		return errors.New("mixes address classes; use ranges that lie wholly inside 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10, [::1] or [fc00::/7]")
	}
	return errors.New("is a public range; public addresses are allowed anyway and need no entry")
}

// lastIP returns the last address of n.
func lastIP(n *net.IPNet) net.IP {
	last := make(net.IP, len(n.IP))
	for i := range n.IP {
		last[i] = n.IP[i] | ^n.Mask[i]
	}
	return last
}

// parseAllowName validates a host name entry: an exact name, or a wildcard
// "*.suffix" whose suffix is "test", "localhost" or has at least two labels —
// and is neither a home-network suffix nor a wildcard DNS service.
func parseAllowName(s string) (allowEntryKind, string, error) {
	h := normHost(s)
	if h == "*" {
		return 0, "", errors.New(`"*" would allow every name`)
	}
	kind, base := entryName, h
	if strings.HasPrefix(h, "*.") {
		kind, base = entryWildcard, h[2:]
	}
	if strings.Contains(base, "*") {
		return 0, "", errors.New(`a wildcard is allowed only as the whole first label, e.g. "*.ddev.site"`)
	}
	if !isASCII(base) {
		return 0, "", errors.New("internationalised names must be written in Punycode (xn--…)")
	}
	if !validHostName(base) {
		return 0, "", errors.New("not a valid host name")
	}
	if kind == entryName {
		return kind, base, nil
	}

	if base != "test" && base != "localhost" && !strings.Contains(base, ".") {
		return 0, "", fmt.Errorf("*.%s would cover every device named on the network; list exact names (e.g. \"nas.%s\") instead", base, base)
	}
	for _, suffix := range homeNetworkSuffixes {
		// Below these endings only exact names: "*.nas.home.arpa" would
		// still cover whatever the router names in that subzone.
		if base == suffix {
			return 0, "", fmt.Errorf("*.%s would cover every device on the home network; list exact names (e.g. \"wp.%s\") instead", base, base)
		}
		if strings.HasSuffix(base, "."+suffix) {
			return 0, "", fmt.Errorf("below .%s only exact names are allowed, no wildcards; list them (e.g. \"wp.%s\") instead", suffix, base)
		}
	}
	for _, svc := range wildcardDNSServices {
		if base == svc || strings.HasSuffix(base, "."+svc) {
			return 0, "", fmt.Errorf("%s is a public wildcard DNS service that resolves names to any embedded IP address; a wildcard on it would open the whole network", svc)
		}
	}
	return kind, base, nil
}

// validHostName checks LDH host name syntax: labels of 1–63 letters, digits
// and hyphens, not starting or ending with a hyphen, at most 253 characters,
// and a last label that is not all digits (which would look like an IP).
func validHostName(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	labels := strings.Split(h, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	last := labels[len(labels)-1]
	return strings.Trim(last, "0123456789") != ""
}

// normHost lower-cases a host name and drops a trailing dot.
func normHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

// isLocalhostName reports "localhost" and its subdomains (RFC 6761), which the
// proxy maps to loopback without DNS once --allow-local is active.
func isLocalhostName(h string) bool {
	return h == "localhost" || strings.HasSuffix(h, ".localhost")
}

// hostPort returns u's host (no brackets) and its effective port.
func hostPort(u *url.URL) (host, port string) {
	host, port = u.Hostname(), u.Port()
	if port == "" {
		port = "80"
		if strings.EqualFold(u.Scheme, "https") {
			port = "443"
		}
	}
	return host, port
}

// allowLocalActive reports whether --allow-local is set.
func (c *config) allowLocalActive() bool {
	return len(c.allowLocal) > 0
}

// allowLocalMatch is the syntactic test, without DNS: is host:port an
// --allow-local target? A name is matched against the name and wildcard
// entries, an IP literal against the IP/CIDR entries — never across:
// "localhost:8888" does not cover "127.0.0.1:8888".
func (c *config) allowLocalMatch(host, port string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return c.netEntryAllows(ip, port)
	}
	return c.nameEntryAllows(normHost(host), port)
}

// nameEntryAllows reports whether a name or wildcard entry covers the
// normalised host name h on port. h must pass the same syntax check as a name
// entry (validHostName): "a..ddev.site" is not covered by "*.ddev.site".
func (c *config) nameEntryAllows(h, port string) bool {
	if !validHostName(h) {
		return false
	}
	for _, e := range c.allowLocal {
		if e.matchesName(h) && e.portAllows(port) {
			return true
		}
	}
	return false
}

// allowLocalMatchURL is allowLocalMatch for a URL.
func (c *config) allowLocalMatchURL(u *url.URL) bool {
	if !c.allowLocalActive() {
		return false
	}
	host, port := hostPort(u)
	return c.allowLocalMatch(host, port)
}

// netEntryAllows reports whether an IP/CIDR entry covers ip on port.
func (c *config) netEntryAllows(ip net.IP, port string) bool {
	for _, e := range c.allowLocal {
		if e.kind == entryNet && e.network.Contains(ip) && e.portAllows(port) {
			return true
		}
	}
	return false
}

// inNetEntries reports whether ip lies in the range of any IP/CIDR entry,
// whatever that entry's port: the second role of those entries, opening their
// range to the name entries.
func (c *config) inNetEntries(ip net.IP) bool {
	for _, e := range c.allowLocal {
		if e.kind == entryNet && e.network.Contains(ip) {
			return true
		}
	}
	return false
}

// isOwnPort reports loopback on the proxy's own listening port — the proxy
// would call itself.
func (c *config) isOwnPort(ip net.IP, port string) bool {
	return c.port != 0 && ip.IsLoopback() && port == strconv.Itoa(c.port)
}

// verdict is localVerdict's answer for one address.
type verdict int

const (
	verdictPublic         verdict = iota // not a private address: the normal path
	verdictAllowed                       // a local address the list opens for this host:port
	verdictNotAllowlisted                // a private address the list does not open
	verdictAlwaysBlocked                 // never reachable
)

// localVerdict decides whether host:port may be reached on ip (LOCAL-2). host
// is the requested name or IP literal, ip the address that would be dialled.
func (c *config) localVerdict(host, port string, ip net.IP) verdict {
	if !isBlockedIP(ip) {
		return verdictPublic
	}
	if isAlwaysBlockedIP(ip) || c.isOwnPort(ip, port) {
		return verdictAlwaysBlocked
	}
	if lit := net.ParseIP(host); lit != nil {
		if lit.Equal(ip) && c.netEntryAllows(ip, port) {
			return verdictAllowed
		}
		return verdictNotAllowlisted
	}
	// Name entries reach loopback only, or a range an IP/CIDR entry opens
	// explicitly.
	if c.nameEntryAllows(normHost(host), port) && (ip.IsLoopback() || c.inNetEntries(ip)) {
		return verdictAllowed
	}
	return verdictNotAllowlisted
}

// blockReason is the reason for refusing host:port on ip, or "" when it may be
// reached. localStart is the request's own value: an allowed target is only
// allowed for a request that started there. Pre-check, dialer and TLS probe
// all use it, so they report the same reason (LOCAL-7).
func (c *config) blockReason(host, port string, ip net.IP, localStart bool) string {
	switch c.localVerdict(host, port, ip) {
	case verdictPublic:
		return ""
	case verdictAlwaysBlocked:
		return reasonAlwaysBlocked
	case verdictAllowed:
		if localStart {
			return ""
		}
		return reasonNotAllowlisted
	}
	if !c.allowLocalActive() {
		return reasonPrivate
	}
	return reasonNotAllowlisted
}

// localStartKey is the context key for the request's localStart value.
type localStartKey struct{}

// withLocalStart records on ctx whether the request's start URL is an
// --allow-local target. The stdlib carries context values down to the
// transport's DialContext, where localGuard reads them.
func withLocalStart(ctx context.Context, localStart bool) context.Context {
	return context.WithValue(ctx, localStartKey{}, localStart)
}

// localStartFrom reads the value withLocalStart recorded. A missing value
// means false: a code path that forgot to set it can only block, never open.
func localStartFrom(ctx context.Context) bool {
	v, _ := ctx.Value(localStartKey{}).(bool)
	return v
}

// exactAddressControl returns a dial Control hook that lets exactly ip:port
// through and hands every other address to next — normally safeDialControl,
// which keeps refusing private ones.
func exactAddressControl(ip net.IP, port string, next func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, rc syscall.RawConn) error {
		if h, p, err := net.SplitHostPort(address); err == nil && p == port {
			if got := net.ParseIP(h); got != nil && got.Equal(ip) {
				return nil
			}
		}
		return next(network, address, rc)
	}
}

// refineBlocked adds what safeDialControl cannot know to its blockedError:
// loopback on the proxy's own port is always_blocked, and with --allow-local
// active a private address is not_allowlisted rather than private. Any other
// error is returned unchanged.
func (c *config) refineBlocked(err error) error {
	var be *blockedError
	if !errors.As(err, &be) || be.ip == nil || be.reason != reasonPrivate {
		return err
	}
	if _, port, splitErr := net.SplitHostPort(be.addr); splitErr == nil && c.isOwnPort(be.ip, port) {
		be.reason = reasonAlwaysBlocked
	} else if c.allowLocalActive() {
		be.reason = reasonNotAllowlisted
	}
	return err
}

// localGuard wraps the transport's dialer and is where --allow-local is
// enforced (LOCAL-4). The transport hands it the target's host:port
// unresolved (no Transport.Proxy is set), so it knows the requested name; it
// then resolves that name itself and dials IP literals, so there is exactly
// one resolution and the address checked is the address connected to —
// rebinding has nothing to gain.
//
//   - No list and no test hook: base.DialContext, exactly the v1.3.0 path.
//   - The request did not start at a local target (localStartFrom), or
//     host:port is not on the list: the base dialer, whose safeDialControl
//     keeps every private address blocked.
//   - Otherwise each address in turn: public → the base dialer; allowed by
//     localVerdict → a dialer that lets exactly that ip:port through; anything
//     else is refused. The first successful connection wins.
//
// Whether a connection may reach a local address depends on the request that
// dialled it, so a connection must never serve a request of the other class.
// DisableKeepAlives makes HTTP/1.1 connections single-use, but it does not
// stop HTTP/2: concurrent requests to the same authority may share a fresh h2
// connection. With --allow-local active newUpstreamClient therefore keeps two
// transports, one per localStart value (localSplitTransport). Within one class
// the verdict depends only on the authority — the h2 pool key — so sharing
// there opens nothing a fresh dial would not.
func localGuard(cfg *config, base *net.Dialer) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		if !cfg.allowLocalActive() && cfg.lookupIP == nil {
			conn, err := base.DialContext(ctx, network, addr)
			return conn, cfg.refineBlocked(err)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		local := localStartFrom(ctx) && cfg.allowLocalMatch(host, port)
		if !local && cfg.lookupIP == nil {
			conn, err := base.DialContext(ctx, network, addr)
			return conn, cfg.refineBlocked(err)
		}

		// Resolve here: for a local target always, for any other target only
		// when the test hook is set, so the base path sees its answers too.
		var ips []net.IP
		if ip := net.ParseIP(host); ip != nil {
			ips = []net.IP{ip}
		} else if ips, err = cfg.resolveHost(ctx, host); err != nil {
			return nil, &net.OpError{Op: "dial", Net: network, Err: err}
		}

		var blocked *blockedError
		var dialErr error
		for _, ip := range ips {
			target := net.JoinHostPort(ip.String(), port)
			d := base
			if local {
				switch cfg.localVerdict(host, port, ip) {
				case verdictPublic:
				case verdictAllowed:
					exact := *base
					exact.Control = exactAddressControl(ip, port, cfg.dialControlOrDefault())
					d = &exact
				default:
					be := &blockedError{ip: ip, addr: target, detail: ip.String(), reason: cfg.blockReason(host, port, ip, true)}
					if blocked == nil || strongerReason(blocked.reason, be.reason) != blocked.reason {
						blocked = be
					}
					continue
				}
			}
			conn, err := d.DialContext(ctx, network, target)
			if err == nil {
				return conn, nil
			}
			err = cfg.refineBlocked(err)
			var be *blockedError
			if errors.As(err, &be) {
				if blocked == nil || strongerReason(blocked.reason, be.reason) != blocked.reason {
					blocked = be
				}
			} else if dialErr == nil {
				dialErr = err
			}
			if ctx.Err() != nil {
				break
			}
		}
		// An address that was allowed but could not be reached says more than
		// the addresses that were refused.
		if dialErr != nil {
			return nil, dialErr
		}
		if blocked != nil {
			return nil, &net.OpError{Op: "dial", Net: network, Err: blocked}
		}
		return nil, &net.OpError{Op: "dial", Net: network, Err: errors.New("no address to dial")}
	}
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

// forwardsResponseHeader reports whether an upstream response header (lower
// case) reaches the client. dynamic holds the response's Connection-listed
// names (connectionTokens).
func forwardsResponseHeader(lower string, dynamic map[string]struct{}) bool {
	if _, skip := hopByHopHeaders[lower]; skip {
		return false
	}
	if _, skip := dynamic[lower]; skip {
		return false
	}
	// Strip upstream CORS headers — we set our own.
	if strings.HasPrefix(lower, "access-control-") {
		return false
	}
	// Never hand the browser a redirect to follow: fetch() would go straight
	// to the target with the proxy token attached. proxyHandler reports the
	// resolved target as X-Upstream-Location instead.
	return lower != "location"
}

// copyResponseHeaders copies safe upstream response headers to the client
// response, skipping hop-by-hop headers, upstream CORS headers and Location.
func copyResponseHeaders(src *http.Response, dst http.ResponseWriter) {
	dynamic := connectionTokens(src.Header)
	for key, values := range src.Header {
		if !forwardsResponseHeader(strings.ToLower(key), dynamic) {
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
// The dialer carries safeDialControl (cfg.dialControl only in tests), which is
// where SSRF is actually enforced (see its documentation); localGuard wraps it
// for --allow-local. Note that the DNS resolver deliberately uses its own
// plain dialer: with --dns system the configured nameserver may itself be a
// loopback address such as systemd-resolved on 127.0.0.53, and applying the
// guard there would break name resolution entirely.
//
// Without --allow-local the client has one *http.Transport, exactly as in
// v1.3.0. With it, a localSplitTransport routes requests with and without the
// localStart allowance to two separate transports, so no connection — HTTP/2
// pools included — is ever shared between the two classes (see localGuard).
func newUpstreamClient(cfg *config) *http.Client {
	var transport http.RoundTripper = newUpstreamTransport(cfg)
	if cfg.allowLocalActive() {
		transport = &localSplitTransport{local: newUpstreamTransport(cfg), public: newUpstreamTransport(cfg)}
	}
	return &http.Client{
		Transport: transport,
		// Never follow redirects inside the transport. Each hop must stay
		// visible to the handler — /page records it, /inspect reports its
		// Location, /proxy reports it as X-Upstream-Location or follows it
		// itself with follow=1 — and must pass the SSRF pre-check before it
		// is requested. The browser is never left to follow one (see
		// forwardsResponseHeader).
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// localSplitTransport sends each request through the transport of its class:
// local when the request's start URL is an --allow-local target
// (localStartFrom), public otherwise. Each transport keeps its own connection
// pool, so a connection dialled with the local allowance never carries a
// request without it — not even an HTTP/2 connection that a concurrent request
// to the same authority picks up before its first stream (LOCAL-4).
type localSplitTransport struct {
	local, public *http.Transport
}

func (t *localSplitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if localStartFrom(req.Context()) {
		return t.local.RoundTrip(req)
	}
	return t.public.RoundTrip(req)
}

// CloseIdleConnections lets http.Client.CloseIdleConnections reach both pools.
func (t *localSplitTransport) CloseIdleConnections() {
	t.local.CloseIdleConnections()
	t.public.CloseIdleConnections()
}

// newUpstreamTransport builds one upstream transport (see newUpstreamClient).
func newUpstreamTransport(cfg *config) *http.Transport {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
		Resolver:  cfg.resolver,
		Control:   cfg.dialControlOrDefault(),
	}
	transport := &http.Transport{
		// localGuard enforces --allow-local and, without it, is the plain
		// dialer.DialContext (see its documentation).
		DialContext:           localGuard(cfg, dialer),
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: cfg.requestTimeout,
		MaxIdleConns:          50,
		IdleConnTimeout:       60 * time.Second,
		ForceAttemptHTTP2:     true,
		// Fresh connection per request — accurate httptrace timing and IP.
		// Security: whether a connection may reach an --allow-local target
		// depends on the request that dialled it (localStartFrom); a pooled
		// HTTP/1.1 connection would carry that permission over to the next
		// request for the same host. This does not cover HTTP/2, whose
		// concurrent requests to one authority may share a connection; that
		// is why --allow-local splits the transport (localSplitTransport).
		DisableKeepAlives: true,
		// TLS verification stays enabled for every connection that carries
		// application data: this transport never sets InsecureSkipVerify
		// (test-enforced). The only unverified handshake in the program is
		// probeTLS — diag=1 after a tls_error, handshake only, never handed
		// to this transport.
	}
	if cfg.rootCAs != nil {
		// Tests only: trust a test CA instead of the system store. Still a
		// fully verified connection.
		transport.TLSClientConfig = &tls.Config{RootCAs: cfg.rootCAs}
	}
	return transport
}

// -----------------------------------------------------------------------
// Start-up flags and banner
// -----------------------------------------------------------------------

// listFlag is a repeatable string flag: every occurrence is kept, so
// "--allow-local a --allow-local b" means the same as "--allow-local a,b".
type listFlag struct {
	values []string
	set    bool // the flag appeared at least once, even with an empty value
}

func (f *listFlag) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(f.values, ",")
}

func (f *listFlag) Set(v string) error {
	f.values = append(f.values, v)
	f.set = true
	return nil
}

// startFlags are the raw command-line values validateFlags checks.
type startFlags struct {
	port         int
	timeoutSec   int
	maxMB        int64
	rawOrigins   string
	allowAnyHost bool
	// allowLocal holds every --allow-local value; allowLocalSet tells "not
	// given" (off) from "given, but empty" (a start-up error).
	allowLocal    []string
	allowLocalSet bool
	// args are the positional arguments left after the flags (flag.Args).
	args []string
}

// startConfig is what validateFlags derives from valid flags.
type startConfig struct {
	origins    []string
	allowLocal []allowEntry
	// warnings are extra banner lines (the text after the label).
	warnings []string
}

// validateFlags checks the command line before anything starts. Problems are
// caught here rather than surfacing later as a mystery: a zero timeout, for
// instance, produces a context that is already past its deadline, so every
// single upstream request would fail instantly. Every error is fatal; main
// prints it with a "fatal: " prefix.
//
// Without --allow-local the checks are exactly those of v1.3.0, plus a banner
// warning for positional arguments (which v1.3.0 ignored silently).
func validateFlags(f startFlags) (*startConfig, error) {
	if f.port < 0 || f.port > 65535 {
		return nil, fmt.Errorf("--port must be between 0 and 65535, got %d", f.port)
	}
	if f.timeoutSec < 1 {
		return nil, fmt.Errorf("--timeout must be at least 1 second, got %d", f.timeoutSec)
	}
	const maxAllowedMB = 1024 * 1024 // 1 TB; guards the byte multiplication in main
	if f.maxMB < 0 || f.maxMB > maxAllowedMB {
		return nil, fmt.Errorf("--max-mb must be between 0 and %d, got %d", maxAllowedMB, f.maxMB)
	}

	start := &startConfig{}
	for _, o := range strings.Split(f.rawOrigins, ",") {
		if trimmed := strings.TrimSpace(o); trimmed != "" {
			start.origins = append(start.origins, trimmed)
		}
	}

	// Go's flag package stops at the first non-flag argument, so everything
	// after it — further flags included — is silently ignored. PowerShell
	// produces exactly that from an unquoted list: "--allow-local a,b" arrives
	// as "a" and "b". With the new flag that would quietly drop --origin or
	// part of the list, so it is fatal; a v1.3.0 command line only gets a
	// warning, so no existing start-up breaks.
	if len(f.args) > 0 {
		if f.allowLocalSet || argsNameAllowLocal(f.args) {
			return nil, fmt.Errorf("unexpected arguments %q: they and every flag after them would be ignored; quote the list: --allow-local \"a,b\"", f.args)
		}
		start.warnings = append(start.warnings,
			fmt.Sprintf("ignored arguments %q and every flag after them (quote values with commas or spaces)", f.args))
	}

	if !f.allowLocalSet {
		return start, nil
	}

	entries, err := parseAllowLocal(f.allowLocal, f.port)
	if err != nil {
		return nil, err
	}
	if len(start.origins) == 0 {
		return nil, errors.New("--allow-local requires --origin (otherwise any website could use the proxy to reach your local network)")
	}
	if f.allowAnyHost {
		return nil, errors.New("--allow-local cannot be combined with --allow-any-host")
	}
	for _, o := range start.origins {
		if !isStrictOrigin(o) {
			return nil, fmt.Errorf("with --allow-local every --origin must be an https origin without a path (got %q)", o)
		}
	}
	start.allowLocal = entries
	return start, nil
}

// argsNameAllowLocal reports whether the left-over positional arguments
// contain --allow-local itself: an unquoted list split earlier on the command
// line (PowerShell: "--origin a,b --allow-local x") stops the flag parser
// before it, so the flag is never set although the user clearly gave it.
// v1.3.0 knew no such flag, so no working v1.3.0 command line contains it.
func argsNameAllowLocal(args []string) bool {
	for _, a := range args {
		name, ok := strings.CutPrefix(a, "--")
		if !ok {
			name, ok = strings.CutPrefix(a, "-")
		}
		if ok && (name == "allow-local" || strings.HasPrefix(name, "allow-local=")) {
			return true
		}
	}
	return false
}

// isStrictOrigin reports whether o is a bare web origin as --allow-local
// requires it: "https://host[:port]", or "http://localhost[:port]" /
// "http://127.0.0.1[:port]" for a tool served locally. No path (not even
// "/"), query, fragment or userinfo; "null" and "*" are not origins.
func isStrictOrigin(o string) bool {
	if strings.ContainsAny(o, "?#") {
		return false
	}
	u, err := url.Parse(o)
	if err != nil || u.Opaque != "" || u.User != nil || u.Path != "" || u.RawPath != "" {
		return false
	}
	host := u.Hostname()
	if host == "" || strings.HasSuffix(u.Host, ":") {
		return false
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return false
		}
	}
	switch u.Scheme {
	case "https":
		return net.ParseIP(host) != nil || validHostName(normHost(host))
	case "http":
		h := strings.ToLower(host)
		return h == "localhost" || h == "127.0.0.1"
	}
	return false
}

// bannerInfo is what the start-up banner shows.
type bannerInfo struct {
	version      string
	port         int
	token        string
	dnsLabel     string
	origins      []string
	allowAnyHost bool
	allowLocal   []allowEntry
	warnings     []string
}

// bannerLines renders the start-up banner, one string per output line. The
// --allow-local entries appear only here, in the local terminal — never in an
// HTTP response.
func bannerLines(b bannerInfo) []string {
	title := fmt.Sprintf("localproxy %s  —  ready", b.version)
	addressLine := fmt.Sprintf("  Address  :  http://127.0.0.1:%d", b.port)
	tokenLine := fmt.Sprintf("  Token    :  %s", b.token)
	dnsLine := fmt.Sprintf("  DNS      :  %s", b.dnsLabel)
	var originsLine string
	if len(b.origins) > 0 {
		originsLine = fmt.Sprintf("  Origins  :  %s", strings.Join(b.origins, ", "))
	} else {
		originsLine = "  Origins  :  (all — pass --origin for production)"
	}
	hostLine := "  Host     :  localhost only"
	if b.allowAnyHost {
		hostLine = "  Host     :  ANY (--allow-any-host — not recommended)"
	}
	// Lines after the Host line: --allow-local, then warnings. Absent
	// without the new flags and positional arguments, so the v1.3.0 banner
	// is unchanged.
	var extraLines []string
	if len(b.allowLocal) > 0 {
		names := make([]string, 0, len(b.allowLocal))
		for _, e := range b.allowLocal {
			names = append(names, e.String())
		}
		extraLines = append(extraLines,
			"  Local    :  "+strings.Join(names, ", "),
			"  WARNING  :  local network access enabled for the allowed origins")
	}
	for _, w := range b.warnings {
		extraLines = append(extraLines, "  WARNING  :  "+w)
	}
	licenseLine := fmt.Sprintf("  License  :  %s", License)
	authorLine := fmt.Sprintf("  Author   :  %s [%s]", Author, AuthorURL)
	repoLine := fmt.Sprintf("  Repo     :  %s", RepoURL)

	// Determine box width from the longest content line (rune-aware for UTF-8)
	runeWidth := func(s string) int { return utf8.RuneCountInString(s) }
	innerWidth := runeWidth(title)
	widthLines := []string{addressLine, tokenLine, dnsLine, originsLine, hostLine, licenseLine, authorLine, repoLine}
	for _, line := range append(widthLines, extraLines...) {
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

	lines := []string{
		"",
		"╔" + hBar + "╗",
		centeredTitle,
		"╠" + hBar + "╣",
		pad(addressLine),
		pad(tokenLine),
		thinBar,
		pad(dnsLine),
		pad(originsLine),
		pad(hostLine),
	}
	for _, line := range extraLines {
		lines = append(lines, pad(line))
	}
	return append(lines,
		thinBar,
		pad(licenseLine),
		pad(authorLine),
		pad(repoLine),
		"╚"+hBar+"╝",
		"",
		"  Enter the address and token in your online tool.",
		"  Press Ctrl+C to stop.",
		"",
	)
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
	var allowLocal listFlag
	flag.Var(&allowLocal, "allow-local", `Comma-separated `+"`list`"+` of local targets the proxy may reach, e.g. "mysite.ddev.site,localhost:8888,10.0.5.0/24" (quote the list; IPv6 in brackets; without a port only 80/443; names reach loopback only). Off by default; requires --origin, and every --origin must then be https://host[:port] (or http://localhost[:port], http://127.0.0.1[:port]) without a path`)
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
	start, err := validateFlags(startFlags{
		port:          *port,
		timeoutSec:    *timeoutSec,
		maxMB:         *maxMB,
		rawOrigins:    *rawOrigins,
		allowAnyHost:  *allowAnyHost,
		allowLocal:    allowLocal.values,
		allowLocalSet: allowLocal.set,
		args:          flag.Args(),
	})
	if err != nil {
		log.Fatalf("fatal: %v", err)
	}
	origins := start.origins

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
		allowLocal:       start.allowLocal,
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
	for _, line := range bannerLines(bannerInfo{
		version:      Version,
		port:         actualPort,
		token:        token,
		dnsLabel:     dnsLabel,
		origins:      origins,
		allowAnyHost: cfg.allowAnyHost,
		allowLocal:   cfg.allowLocal,
		warnings:     start.warnings,
	}) {
		fmt.Println(line)
	}

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
