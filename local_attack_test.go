package main

// Adversarial tests for --allow-local (LOCAL-1 to LOCAL-9). Every test asserts
// the secure outcome: a failing test is a confirmed bypass or a deviation from
// the requirements. Behaviour that is allowed by the requirements but worth
// knowing is only logged (t.Log).

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// attackLookup is a lookup hook over a fixed table. Like a real resolver it
// ignores case and one trailing dot. A value "fail" answers with a DNS error.
func attackLookup(hosts map[string]string, calls *atomic.Int32) func(context.Context, string) ([]net.IPAddr, error) {
	return func(_ context.Context, host string) ([]net.IPAddr, error) {
		if calls != nil {
			calls.Add(1)
		}
		v, ok := hosts[strings.TrimSuffix(strings.ToLower(host), ".")]
		if !ok || v == "fail" {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		var addrs []net.IPAddr
		for _, s := range strings.Split(v, ",") {
			addrs = append(addrs, net.IPAddr{IP: net.ParseIP(s)})
		}
		return addrs, nil
	}
}

// noDNSResolver fails every lookup without touching the network, so the
// production path (lookupIP == nil) can run offline.
func noDNSResolver() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("no DNS in this test")
		},
	}
}

// recordingControl wraps safeDialControl and records every address that
// reached the socket layer.
type recordingControl struct {
	mu    sync.Mutex
	addrs []string
}

func (r *recordingControl) control(network, address string, c syscall.RawConn) error {
	r.mu.Lock()
	r.addrs = append(r.addrs, address)
	r.mu.Unlock()
	return safeDialControl(network, address, c)
}

func (r *recordingControl) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.addrs...)
}

// --- 1. Listed names resolving into ranges a name entry must not reach -----

func TestAttack_ListedNameResolvesIntoBlockedRanges(t *testing.T) {
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	cases := []struct {
		ip     string
		reason string
	}{
		{"192.168.1.66", reasonNotAllowlisted},
		{"10.0.0.5", reasonNotAllowlisted},
		{"172.16.0.1", reasonNotAllowlisted},
		{"100.64.0.1", reasonNotAllowlisted}, // CGNAT
		{"fd00::66", reasonNotAllowlisted},   // ULA
		{"::ffff:192.168.1.66", reasonNotAllowlisted},
		{"::ffff:10.0.0.1", reasonNotAllowlisted},
		{"169.254.169.254", reasonAlwaysBlocked},
		{"::ffff:169.254.169.254", reasonAlwaysBlocked},
		{"0.0.0.0", reasonAlwaysBlocked}, // connects to the local host on Linux
		{"::", reasonAlwaysBlocked},
		{"64:ff9b::7f00:1", reasonAlwaysBlocked}, // NAT64 loopback
		{"2002:7f00:1::1", reasonAlwaysBlocked},  // 6to4 loopback
		{"fe80::1", reasonAlwaysBlocked},
		{"224.0.0.1", reasonAlwaysBlocked},
		{"100.100.100.200", reasonAlwaysBlocked}, // Alibaba metadata
		{"fd00:ec2::254", reasonAlwaysBlocked},   // AWS IMDS v6
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			cfg, _ := localCfg(t, "wp.test:"+port, nil, nil)
			cfg.lookupIP = attackLookup(map[string]string{"wp.test": tc.ip}, nil)
			rr := doProxy(t, cfg, http.MethodGet, "http://wp.test:"+port+"/", "", nil)
			wantBlocked(t, rr, http.StatusBadGateway, tc.reason)
		})
	}
	if hits.Load() != 0 {
		t.Errorf("local server saw %d requests, want 0", hits.Load())
	}

	// IPv4-mapped loopback is loopback: allowed, and the server is reached.
	cfg, _ := localCfg(t, "wp.test:"+port, nil, nil)
	cfg.lookupIP = attackLookup(map[string]string{"wp.test": "::ffff:127.0.0.1"}, nil)
	if rr := doProxy(t, cfg, http.MethodGet, "http://wp.test:"+port+"/", "", nil); rr.Code != http.StatusOK {
		t.Errorf("::ffff:127.0.0.1 for a listed name: %d — %s", rr.Code, rr.Body.String())
	}
}

// --- 2. Metadata services inside an allowed CIDR ----------------------------

func TestAttack_MetadataInsideAllowedCIDR(t *testing.T) {
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	entries := "wp.test:" + port + ",100.100.0.0/16,[fd00:ec2::/48]"
	for _, target := range []string{
		"http://100.100.100.200/",
		"http://[::ffff:100.100.100.200]/",
		"http://[::ffff:6464:64c8]/", // same address, hex form
		"http://[fd00:ec2::254]/",
		"http://[fd00:ec2:0:0:0:0:0:254]/",
		"http://[FD00:EC2::254]/",
	} {
		cfg, _ := localCfg(t, entries, nil, nil)
		wantBlocked(t, doProxy(t, cfg, http.MethodGet, target, "", nil), http.StatusForbidden, reasonAlwaysBlocked)
	}
	// A listed name pointed at the metadata address (DNS spoofing).
	for _, ip := range []string{"100.100.100.200", "::ffff:100.100.100.200", "fd00:ec2::254"} {
		cfg, _ := localCfg(t, entries, nil, nil)
		cfg.lookupIP = attackLookup(map[string]string{"wp.test": ip}, nil)
		wantBlocked(t, doProxy(t, cfg, http.MethodGet, "http://wp.test:"+port+"/", "", nil), http.StatusBadGateway, reasonAlwaysBlocked)
	}
	// The metadata address itself can never be an entry.
	for _, e := range []string{"100.100.100.200", "100.100.100.200/32", "[fd00:ec2::254]", "[fd00:ec2::254/128]", "169.254.169.254", "169.254.0.0/16"} {
		if _, err := parseAllowLocal([]string{e}, 0); err == nil {
			t.Errorf("entry %q accepted", e)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("server saw %d requests", hits.Load())
	}
}

// --- 3. Alternative IPv4 spellings in the URL -------------------------------

func TestAttack_LiteralIPEncodings(t *testing.T) {
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	for _, host := range []string{
		"2130706433", "0x7f000001", "0177.0.0.1", "127.1", "0x7f.1", "017700000001",
		"127.0.0.2", "[::1]", "[0:0:0:0:0:0:0:1]", "[::127.0.0.1]",
		"[fe80::1%25lo]", "[::ffff:7f00:2]",
	} {
		t.Run(host, func(t *testing.T) {
			// Production path: no lookup hook, a resolver that never answers.
			cfg, _ := localCfg(t, "127.0.0.1:"+port, nil, nil)
			cfg.lookupIP = nil
			cfg.resolver = noDNSResolver()
			for name, do := range map[string]func() *httptest.ResponseRecorder{
				"proxy": func() *httptest.ResponseRecorder {
					return doProxy(t, cfg, http.MethodGet, "http://"+host+":"+port+"/", "", nil)
				},
				"inspect": func() *httptest.ResponseRecorder { return doInspect(t, cfg, "http://"+host+":"+port+"/", "") },
				"page":    func() *httptest.ResponseRecorder { return doPage(t, cfg, "http://"+host+":"+port+"/", "") },
			} {
				rr := do()
				if strings.Contains(rr.Body.String(), "local ok") {
					t.Errorf("%s reached the local server via %q", name, host)
				}
			}
		})
	}
	if hits.Load() != 0 {
		t.Errorf("server saw %d requests", hits.Load())
	}

	// The IPv4-mapped spelling of a listed literal is that literal.
	cfg, _ := localCfg(t, "127.0.0.1:"+port, nil, nil)
	rr := doProxy(t, cfg, http.MethodGet, "http://[::ffff:127.0.0.1]:"+port+"/", "", nil)
	t.Logf("[::ffff:127.0.0.1] with entry 127.0.0.1: %d (equivalent address)", rr.Code)
}

// --- 4. Name spelling and wildcard edges ------------------------------------

func TestAttack_NameSpellingAndWildcards(t *testing.T) {
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	all := map[string]string{
		"wp.test": "127.0.0.1", "ddev.site": "127.0.0.1", "xddev.site": "127.0.0.1",
		"a.ddev.site": "127.0.0.1", "a.b.ddev.site": "127.0.0.1",
		"a.ddev.site.evil.example": "127.0.0.1", "a..ddev.site": "127.0.0.1",
		"ddev.site.": "127.0.0.1", "x-ddev.site": "127.0.0.1", "xn--wp-test": "127.0.0.1",
	}

	// Allowed spellings of a listed name (case, one trailing dot).
	for _, h := range []string{"WP.TEST", "wp.test.", "Wp.Test."} {
		cfg, _ := localCfg(t, "wp.test:"+port, nil, nil)
		cfg.lookupIP = attackLookup(all, nil)
		if rr := doProxy(t, cfg, http.MethodGet, "http://"+h+":"+port+"/", "", nil); rr.Code != http.StatusOK {
			t.Errorf("%q: %d — %s", h, rr.Code, rr.Body.String())
		}
	}
	before := hits.Load()

	// Spellings that must not count as the listed name.
	for _, h := range []string{"wp.test..", "ｗｐ.test", "wp。test", "wp.test%2e", "xn--wp-test"} {
		cfg, _ := localCfg(t, "wp.test:"+port, nil, nil)
		cfg.lookupIP = attackLookup(all, nil)
		rr := doProxy(t, cfg, http.MethodGet, "http://"+h+":"+port+"/", "", nil)
		if rr.Code == http.StatusOK {
			t.Errorf("%q reached the server", h)
		}
	}
	for _, h := range []string{"ddev.site", "xddev.site", "x-ddev.site", "a.ddev.site.evil.example", ".ddev.site"} {
		cfg, _ := localCfg(t, "*.ddev.site:"+port, nil, nil)
		cfg.lookupIP = attackLookup(all, nil)
		rr := doProxy(t, cfg, http.MethodGet, "http://"+h+":"+port+"/", "", nil)
		if rr.Code == http.StatusOK {
			t.Errorf("*.ddev.site matched %q", h)
		}
	}
	if got := hits.Load() - before; got != 0 {
		t.Errorf("server saw %d requests from spellings that are not on the list", got)
	}
	// A name with an empty label still matches the wildcard (only a real
	// resolver refuses it).
	{
		cfg, _ := localCfg(t, "*.ddev.site:"+port, nil, nil)
		if cfg.allowLocalMatch("a..ddev.site", port) {
			t.Logf("NOTE: *.ddev.site matches the malformed name %q", "a..ddev.site")
		}
	}
	for _, h := range []string{"a.ddev.site", "A.B.DDEV.SITE."} {
		cfg, _ := localCfg(t, "*.ddev.site:"+port, nil, nil)
		cfg.lookupIP = attackLookup(all, nil)
		if rr := doProxy(t, cfg, http.MethodGet, "http://"+h+":"+port+"/", "", nil); rr.Code != http.StatusOK {
			t.Errorf("*.ddev.site did not match %q: %d", h, rr.Code)
		}
	}
}

// --- 5. Ports: default 80/443, leading zeros, the proxy's own port ----------

func TestAttack_Ports(t *testing.T) {
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	hosts := map[string]string{"wp.test": "127.0.0.1", "x.ddev.site": "127.0.0.1"}

	// No port in the entry: only 80/443.
	cfg, _ := localCfg(t, "*.ddev.site", hosts, nil)
	wantBlocked(t, doProxy(t, cfg, http.MethodGet, "http://x.ddev.site:"+port+"/", "", nil), http.StatusForbidden, reasonNotAllowlisted)

	// Leading zeros name the same TCP port but must not match the entry.
	cfg, _ = localCfg(t, "wp.test:"+port, hosts, nil)
	rr := doProxy(t, cfg, http.MethodGet, "http://wp.test:0"+port+"/", "", nil)
	if rr.Code == http.StatusOK {
		t.Errorf("leading-zero port reached the server")
	}
	if hits.Load() != 0 {
		t.Fatalf("server saw %d requests", hits.Load())
	}

	// The proxy's own port, learned only after the list was parsed (--port 0).
	own, ownHits := countingServer(t, nil)
	ownPort := serverPort(t, own)
	ownN, _ := strconv.Atoi(ownPort)
	entries := "localhost:" + ownPort + ",127.0.0.0/16:" + ownPort + ",[::1]:" + ownPort + ",wp.test:" + ownPort + ",*.localhost:" + ownPort
	for _, tc := range []struct {
		target string
		dnsIP  string
		status int
	}{
		{"http://localhost:" + ownPort + "/ping", "", http.StatusBadGateway},
		{"http://LOCALHOST.:" + ownPort + "/ping", "", http.StatusBadGateway},
		{"http://a.localhost:" + ownPort + "/ping", "", http.StatusBadGateway},
		{"http://127.0.0.1:" + ownPort + "/ping", "", http.StatusForbidden},
		{"http://127.0.0.2:" + ownPort + "/ping", "", http.StatusForbidden},
		{"http://[::1]:" + ownPort + "/ping", "", http.StatusForbidden},
		{"http://[::ffff:127.0.0.1]:" + ownPort + "/ping", "", http.StatusForbidden},
		{"http://wp.test:" + ownPort + "/ping", "127.0.0.1", http.StatusBadGateway},
		{"http://wp.test:" + ownPort + "/ping", "::ffff:127.0.0.1", http.StatusBadGateway},
		{"http://wp.test:" + ownPort + "/ping", "127.0.0.3", http.StatusBadGateway},
	} {
		cfg, _ := localCfg(t, entries, map[string]string{"wp.test": tc.dnsIP}, nil)
		cfg.port = ownN
		rr := doProxy(t, cfg, http.MethodGet, tc.target, "", nil)
		if rr.Code == http.StatusOK || !strings.Contains(rr.Body.String(), reasonAlwaysBlocked) {
			t.Errorf("%s (dns %s): %d — %s", tc.target, tc.dnsIP, rr.Code, rr.Body.String())
		}
		// Through /page and /inspect as well.
		if prr := doPage(t, cfg, tc.target, ""); strings.Contains(prr.Body.String(), "local ok") {
			t.Errorf("/page reached the own port via %s", tc.target)
		}
		if irr := doInspect(t, cfg, tc.target, ""); strings.Contains(irr.Body.String(), `"status":200`) {
			t.Errorf("/inspect reached the own port via %s", tc.target)
		}
	}
	if ownHits.Load() != 0 {
		t.Errorf("own port saw %d requests", ownHits.Load())
	}

	// Start-up refusals.
	for _, e := range []string{"localhost:8765", "localhost:2375", "localhost:6379", "10.0.5.20:3306", "[fd00::5]:27017",
		"localhost:0", "localhost:65536", "localhost:*", "localhost:80-90", "localhost:+80", "localhost: 80"} {
		if _, err := parseAllowLocal([]string{e}, 8765); err == nil {
			t.Errorf("entry %q accepted", e)
		}
	}
}

// --- 6. Redirects from a public start into local targets --------------------

// publicCfg makes pub.test a "public" site on loopback: its port is the only
// loopback address the dialer lets through outside the list, and the
// pre-check (emulated v1.3.0-style through the lookup hook) waves it
// through. Every other address keeps the real guard.
func publicCfg(t *testing.T, entries string, pubPort string, hosts map[string]string, calls *atomic.Int32) *config {
	t.Helper()
	cfg, _ := localCfg(t, entries, nil, nil)
	cfg.lookupIP = attackLookup(hosts, calls)
	cfg.dialControl = func(network, address string, c syscall.RawConn) error {
		if _, p, err := net.SplitHostPort(address); err == nil && p == pubPort {
			return nil
		}
		return safeDialControl(network, address, c)
	}
	lookup := cfg.lookupIP
	cfg.ssrfCheck = func(h string) bool {
		if strings.EqualFold(h, "pub.test") {
			return false
		}
		if ip := net.ParseIP(h); ip != nil {
			return isBlockedIP(ip)
		}
		addrs, err := lookup(context.Background(), h)
		if err != nil {
			return false // fail-open, as in production
		}
		for _, a := range addrs {
			if isBlockedIP(a.IP) {
				return true
			}
		}
		return false
	}
	return cfg
}

func TestAttack_RedirectPublicIntoLocal(t *testing.T) {
	local, localHits := countingServer(t, nil)
	lport := serverPort(t, local)
	pub, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("to"))
		w.WriteHeader(http.StatusFound)
	})
	pport := serverPort(t, pub)
	entries := "wp.test:" + lport + ",127.0.0.1:" + lport + ",localhost:" + lport + ",*.ddev.site:" + lport

	for _, next := range []string{
		"http://wp.test:" + lport + "/",
		"http://WP.TEST.:" + lport + "/",
		"http://127.0.0.1:" + lport + "/",
		"http://[::ffff:127.0.0.1]:" + lport + "/",
		"http://localhost:" + lport + "/",
		"http://x.ddev.site:" + lport + "/",
		"http://wp.test:0" + lport + "/",
		"http://unlisted.test:" + lport + "/",
		"http://flaky.test:" + lport + "/", // pre-check lookup fails, dial resolves to loopback
		"http://[::1]:" + lport + "/",
		"http://0.0.0.0:" + lport + "/",
		"//wp.test:" + lport + "/", // scheme-relative
	} {
		hosts := map[string]string{
			"pub.test": "127.0.0.1", "wp.test": "127.0.0.1", "x.ddev.site": "127.0.0.1",
			"unlisted.test": "127.0.0.1", "flaky.test": "fail",
		}
		start := "http://pub.test:" + pport + "/r?to=" + url.QueryEscape(next)

		var calls atomic.Int32
		cfg := publicCfg(t, entries, pport, hosts, &calls)
		// flaky.test: the pre-check's lookup fails, every later one is loopback.
		cfg.lookupIP = func(ctx context.Context, h string) ([]net.IPAddr, error) {
			if strings.EqualFold(strings.TrimSuffix(h, "."), "flaky.test") && calls.Add(1) > 1 {
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
			}
			return attackLookup(hosts, nil)(ctx, h)
		}

		rr := doProxy(t, cfg, http.MethodGet, start, "&follow=1", nil)
		if rr.Code == http.StatusOK || strings.Contains(rr.Body.String(), "local ok") {
			t.Errorf("/proxy follow: public start reached %s — %d %s", next, rr.Code, rr.Body.String())
		}
		prr := doPage(t, cfg, start, "")
		if strings.Contains(prr.Body.String(), "local ok") {
			t.Errorf("/page: public start reached %s", next)
		}
		t.Logf("%-40s /proxy %d %s", next, rr.Code, strings.TrimSpace(rr.Body.String()))
	}
	if localHits.Load() != 0 {
		t.Errorf("local server saw %d requests from a public start", localHits.Load())
	}
}

// --- 7. Redirects from a local start ----------------------------------------

func TestAttack_RedirectFromLocalStart(t *testing.T) {
	other, otherHits := countingServer(t, nil)
	oport := serverPort(t, other)
	start, _ := countingServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", r.URL.Query().Get("to"))
		w.WriteHeader(http.StatusFound)
	})
	sport := serverPort(t, start)
	hosts := map[string]string{
		"wp.test": "127.0.0.1", "wp2.test": "127.0.0.1", "unlisted.test": "127.0.0.1",
		"lan.test": "192.168.1.66", "meta.test": "169.254.169.254", "flaky.test": "fail",
	}
	entries := "wp.test:" + sport + ",wp2.test:" + oport + ",lan.test:" + oport + ",meta.test:" + oport

	for _, next := range []string{
		"http://unlisted.test:" + oport + "/",
		"http://127.0.0.1:" + oport + "/",
		"http://localhost:" + oport + "/",
		"http://lan.test:" + oport + "/",
		"http://meta.test:" + oport + "/",
		"http://wp2.test:0" + oport + "/",
		"http://192.168.1.66/",
		"http://flaky.test:" + oport + "/",
	} {
		var calls atomic.Int32
		cfg, _ := localCfg(t, entries, nil, nil)
		cfg.lookupIP = func(ctx context.Context, h string) ([]net.IPAddr, error) {
			if strings.EqualFold(h, "flaky.test") && calls.Add(1) > 1 {
				return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
			}
			return attackLookup(hosts, nil)(ctx, h)
		}
		target := "http://wp.test:" + sport + "/r?to=" + url.QueryEscape(next)
		rr := doProxy(t, cfg, http.MethodGet, target, "&follow=1", nil)
		if rr.Code == http.StatusOK {
			t.Errorf("/proxy follow: local start reached %s", next)
		}
		if prr := doPage(t, cfg, target, ""); strings.Contains(prr.Body.String(), "local ok") {
			t.Errorf("/page: local start reached %s", next)
		}
	}
	if otherHits.Load() != 0 {
		t.Errorf("unlisted target saw %d requests", otherHits.Load())
	}

	// Allowed by LOCAL-6: local → other listed local target.
	cfg, _ := localCfg(t, entries, hosts, nil)
	rr := doProxy(t, cfg, http.MethodGet, "http://wp.test:"+sport+"/r?to="+url.QueryEscape("http://wp2.test:"+oport+"/"), "&follow=1", nil)
	t.Logf("local -> other listed local: %d (allowed by LOCAL-6)", rr.Code)
}

// --- 8. TLS probe -----------------------------------------------------------

func TestAttack_TLSProbe(t *testing.T) {
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	own, ownHitCount := countingServer(t, nil)
	ownPort := serverPort(t, own)
	ownN, _ := strconv.Atoi(ownPort)
	cfg, _ := localCfg(t, "wp.test:"+port+",localhost:"+ownPort+",10.0.5.0/24", nil, nil)
	cfg.port = ownN
	ctx := withLocalStart(context.Background(), true)

	for _, tc := range []struct{ host, port, ip string }{
		{"wp.test", port, "192.168.1.66"},
		{"wp.test", port, "169.254.169.254"},
		{"wp.test", port, "0.0.0.0"},
		{"wp.test", port, "127.0.0.2"},      // allowed (loopback) — but nobody listens there with TLS
		{"evil.test", port, "127.0.0.1"},    // unlisted name
		{"wp.test", ownPort, "127.0.0.1"},   // wrong port for the entry
		{"localhost", ownPort, "127.0.0.1"}, // own port
		{"127.0.0.1", port, "127.0.0.1"},    // literal not on the list
		{"10.0.5.7", port, "127.0.0.1"},     // literal on the list, different dialled IP
	} {
		_, err := probeTLS(ctx, cfg, tc.host, tc.port, tc.ip)
		if tc.ip == "127.0.0.2" {
			continue
		}
		if !errors.Is(err, errBlockedTarget) {
			t.Errorf("probeTLS(%s, %s, %s) = %v, want blocked", tc.host, tc.port, tc.ip, err)
		}
	}
	if hits.Load() != 0 || ownHitCount.Load() != 0 {
		t.Errorf("probe reached a server")
	}
}

// --- 9. Mixed answers: blocked addresses are never dialled --------------------

func TestAttack_MixedAnswersNeverDialBlocked(t *testing.T) {
	srv, _ := countingServer(t, nil)
	port := serverPort(t, srv)
	rec := &recordingControl{}
	cfg, _ := localCfg(t, "wp.test:"+port, nil, nil)
	cfg.lookupIP = attackLookup(map[string]string{"wp.test": "192.168.1.66,169.254.169.254,fd00::1,0.0.0.0,127.0.0.1"}, nil)
	cfg.dialControl = rec.control
	rr := doProxy(t, cfg, http.MethodGet, "http://wp.test:"+port+"/", "", nil)
	if rr.Code != http.StatusOK || rr.Header().Get("X-Upstream-IP") != "127.0.0.1" {
		t.Errorf("status %d ip %q", rr.Code, rr.Header().Get("X-Upstream-IP"))
	}
	for _, a := range rec.seen() {
		if a != "127.0.0.1:"+port {
			t.Errorf("socket layer saw %s", a)
		}
	}
}

// --- 10. HTTP/2 connection sharing between requests ----------------------------

// The allowance for a local target lives on the request context and is
// checked when a connection is dialled. localGuard documents that it
// "relies on one connection per request". With HTTP/2 the transport keeps
// its own pool keyed by host:port: a request B that does not carry the
// allowance may be put on a connection another request A just dialled
// with it, and B then never reaches the dialer.
func TestAttack_H2ConnectionSharing(t *testing.T) {
	pki := newTestPKI(t)
	der, key := pki.leaf(t, certOpts{cn: "wp.test", dns: []string{"wp.test"}})
	var bHits atomic.Int32
	var conns atomic.Int32
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/b" {
			bHits.Add(1)
		}
		w.Write([]byte("ok " + r.Proto))
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, pki.interDER}, PrivateKey: key}}}
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	port := serverPort(t, srv)
	base := "https://wp.test:" + port

	cfg, _ := localCfg(t, "wp.test:"+port, map[string]string{"wp.test": "127.0.0.1"}, pki.pool)
	client := newUpstreamClient(cfg)

	// B alone, without the allowance: refused.
	reqB, _ := http.NewRequestWithContext(withLocalStart(context.Background(), false), http.MethodGet, base+"/b", nil)
	if resp, err := client.Do(reqB); err == nil {
		resp.Body.Close()
		t.Fatal("B alone reached the local target")
	}

	// A with the allowance; while A holds its fresh connection (GotConn),
	// B without the allowance runs.
	var bErr error
	var bStatus int
	var once sync.Once
	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(withLocalStart(context.Background(), false), 3*time.Second)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/b", nil)
			resp, err := client.Do(req)
			bErr = err
			if err == nil {
				bStatus = resp.StatusCode
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		})
	}}
	ctxA := httptrace.WithClientTrace(withLocalStart(context.Background(), true), trace)
	reqA, _ := http.NewRequestWithContext(ctxA, http.MethodGet, base+"/a", nil)
	resp, err := client.Do(reqA)
	if err != nil {
		t.Fatalf("A: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	t.Logf("A: %s %q; B: status=%d err=%v; server connections=%d", resp.Proto, body, bStatus, bErr, conns.Load())
	if bErr == nil || bHits.Load() != 0 {
		t.Errorf("request B without the local allowance reached the local target over A's HTTP/2 connection (B status %d, server saw %d /b requests)", bStatus, bHits.Load())
	}

	// The same without a hook: A and B started together, many times.
	bHits.Store(0)
	const rounds = 200
	for i := 0; i < rounds; i++ {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(withLocalStart(context.Background(), true), http.MethodGet, base+"/a", nil)
			if resp, err := client.Do(req); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i%10) * 100 * time.Microsecond)
			req, _ := http.NewRequestWithContext(withLocalStart(context.Background(), false), http.MethodGet, base+"/b", nil)
			if resp, err := client.Do(req); err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
		wg.Wait()
	}
	if n := bHits.Load(); n != 0 {
		t.Errorf("unhooked concurrency: B without the allowance reached the local target %d times in %d rounds", n, rounds)
	}
}

// --- 11. Pre-check fail-open, then rebinding at dial time -------------------

func TestAttack_PrecheckFailOpenThenLoopback(t *testing.T) {
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	var calls atomic.Int32
	cfg, _ := localCfg(t, "*.ddev.site:"+port, nil, nil)
	cfg.lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		if calls.Add(1) == 1 {
			return nil, &net.DNSError{Err: "timeout", IsTimeout: true}
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
	}
	for name, do := range map[string]func() *httptest.ResponseRecorder{
		"proxy": func() *httptest.ResponseRecorder {
			return doProxy(t, cfg, http.MethodGet, "http://evil.test:"+port+"/", "", nil)
		},
		"inspect": func() *httptest.ResponseRecorder { return doInspect(t, cfg, "http://evil.test:"+port+"/", "&body=1") },
		"page":    func() *httptest.ResponseRecorder { return doPage(t, cfg, "http://evil.test:"+port+"/", "") },
	} {
		calls.Store(0)
		rr := do()
		if strings.Contains(rr.Body.String(), "local ok") {
			t.Errorf("%s: reached loopback after a failed pre-check lookup", name)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("server saw %d requests", hits.Load())
	}

	// Listed name: /page traces with HEAD on loopback, then the final GET's
	// lookup answers with a LAN address. The GET must be refused.
	calls.Store(0)
	cfg, _ = localCfg(t, "wp.test:"+port, nil, nil)
	cfg.lookupIP = func(context.Context, string) ([]net.IPAddr, error) {
		if calls.Add(1) == 1 {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("192.168.1.66")}}, nil
	}
	page := decodePage(t, doPage(t, cfg, "http://wp.test:"+port+"/", ""))
	if page.Error == nil || page.Error.Error != "blocked_target" || page.Error.Reason != reasonNotAllowlisted {
		t.Errorf("/page final GET after rebinding: error=%+v html=%q", page.Error, page.HTML)
	}
}

// --- 12. Parser edges -------------------------------------------------------

func TestAttack_ParseEdges(t *testing.T) {
	mustFail := []string{
		"*.NIP.IO", "*.nip.io.", "*.x.nip.io", "*.X.SSLIP.IO", "*.Home.Arpa.", "*.FRITZ.BOX",
		"*.lan.", "*", "*.", "**.ddev.site", "*.*.ddev.site", "a*.ddev.site",
		"[127.0.0.1]", "::1", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[fd00::5", "fd00::5:8443",
		"10.0.0.0/7", "172.32.0.0/16", "192.0.0.0/16", "[fc00::/47]", "[::/0]", "0.0.0.0/0", "10.0.0.1/8",
		"http://wp.test", "wp.test/path", "wp_test", "-wp.test", "wp..test", "1.2.3.4.5",
		"8.8.8.8", "[2001:4860::8888]", "100.63.0.0/16", "100.64.0.0/9",
	}
	for _, e := range mustFail {
		if _, err := parseAllowLocal([]string{e}, 0); err == nil {
			t.Errorf("entry %q accepted", e)
		}
	}
	// Spec (LOCAL-1): under home-network suffixes only exact names.
	for _, e := range []string{"*.nas.home.arpa", "*.x.fritz.box"} {
		if _, err := parseAllowLocal([]string{e}, 0); err == nil {
			t.Logf("NOTE: wildcard below a home-network suffix accepted: %q (LOCAL-1: \"Unter diesen Endungen nur exakte Namen\")", e)
		}
	}
	// Public suffixes with two labels are accepted as wildcards.
	for _, e := range []string{"*.co.uk", "*.github.io"} {
		if _, err := parseAllowLocal([]string{e}, 0); err == nil {
			t.Logf("NOTE: %q accepted (two-label rule; any registrant below it can point a name at loopback)", e)
		}
	}
	// Names that look numeric but pass validHostName.
	for _, e := range []string{"0x7f000001", "127.0.0.1x"} {
		if _, err := parseAllowLocal([]string{e}, 0); err == nil {
			t.Logf("NOTE: name entry %q accepted", e)
		}
	}
}

// --- 13. Strict origins with --allow-local ------------------------------------

func TestAttack_StrictOrigins(t *testing.T) {
	bad := []string{
		"null", "*", "https://www.jpkc.com/", "https://www.jpkc.com/tools", "https://*.jpkc.com",
		"https://user@www.jpkc.com", "https://www.jpkc.com?x", "https://www.jpkc.com#", "https://www.jpkc.com:",
		"https://www.jpkc.com:0", "https://www.jpkc.com:99999", "http://www.jpkc.com", "http://localhost.",
		"http://localhost.evil.com", "http://127.0.0.1.nip.io", "http://[::1]", "ws://localhost", "https:/www.jpkc.com",
		"https://www.jpkc.com\\@evil.com", "file://", "https://", "chrome-extension://abc",
	}
	for _, o := range bad {
		_, err := validateFlags(startFlags{port: 8765, timeoutSec: 30, maxMB: 50, rawOrigins: o,
			allowLocal: []string{"wp.test"}, allowLocalSet: true})
		if err == nil {
			t.Errorf("--origin %q accepted with --allow-local", o)
		}
	}
	// Positional arguments after --allow-local.
	if _, err := validateFlags(startFlags{port: 8765, timeoutSec: 30, rawOrigins: "https://www.jpkc.com",
		allowLocal: []string{"*.ddev.site"}, allowLocalSet: true, args: []string{"localhost:8888"}}); err == nil {
		t.Error("positional arguments accepted with --allow-local")
	}
	// --allow-local with --allow-any-host.
	if _, err := validateFlags(startFlags{port: 8765, timeoutSec: 30, rawOrigins: "https://www.jpkc.com",
		allowLocal: []string{"wp.test"}, allowLocalSet: true, allowAnyHost: true}); err == nil {
		t.Error("--allow-any-host accepted with --allow-local")
	}
	// Given but empty.
	for _, v := range [][]string{{""}, {" , ,"}, {"", ""}} {
		if _, err := validateFlags(startFlags{port: 8765, timeoutSec: 30, rawOrigins: "https://www.jpkc.com",
			allowLocal: v, allowLocalSet: true}); err == nil {
			t.Errorf("empty --allow-local %q accepted", v)
		}
	}
}

// --- 14. Without --allow-local: no change of the v1.3.0 decisions ------------

func TestAttack_FlagOffUnchanged(t *testing.T) {
	srv, hits := countingServer(t, nil)
	port := serverPort(t, srv)
	for _, target := range []string{
		"http://localhost:" + port + "/", "http://127.0.0.1:" + port + "/", "http://[::ffff:127.0.0.1]:" + port + "/",
		"http://x.localhost:" + port + "/", "http://wp.test:" + port + "/",
	} {
		cfg, _ := localCfg(t, "", map[string]string{"wp.test": "127.0.0.1", "localhost": "127.0.0.1", "x.localhost": "127.0.0.1"}, nil)
		for name, do := range map[string]func() *httptest.ResponseRecorder{
			"proxy":   func() *httptest.ResponseRecorder { return doProxy(t, cfg, http.MethodGet, target, "&follow=1", nil) },
			"inspect": func() *httptest.ResponseRecorder { return doInspect(t, cfg, target, "&body=1") },
			"page":    func() *httptest.ResponseRecorder { return doPage(t, cfg, target, "") },
		} {
			if rr := do(); strings.Contains(rr.Body.String(), "local ok") {
				t.Errorf("flag off: %s reached %s", name, target)
			}
		}
		// Even with a forged context value.
		client := newUpstreamClient(cfg)
		req, _ := http.NewRequestWithContext(withLocalStart(context.Background(), true), http.MethodGet, target, nil)
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
			t.Errorf("flag off, localStart=true: client reached %s", target)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("server saw %d requests with the flag off", hits.Load())
	}
}
