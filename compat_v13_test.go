package main

// Compatibility tests against v1.3.0 (COMPAT-1/2/3 of the v1.4.0 requirements):
// without --allow-local every endpoint, status, error body, header, banner line
// and flag default must be what v1.3.0 produced. The only allowed difference
// on these paths is the additive "reason" field on blocked_target errors (and
// the /page hop field "errorReason"), plus a banner WARNING line for positional
// arguments v1.3.0 ignored silently. With AUTH-* (v1.4.0) two more values
// change on every request, as section 4.1 allows: Access-Control-Allow-Headers
// names X-Target-Authorization and X-Target-Origin (difference 1), and /proxy
// responses add "Vary: X-Target-Authorization" (difference 2).

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

// -----------------------------------------------------------------------
// Banner
// -----------------------------------------------------------------------

// v13Banner is the v1.3.0 banner code from main(), copied verbatim from
// git show v1.3.0:main.go and turned into a function returning the lines
// fmt.Println printed.
func v13Banner(version string, actualPort int, token, dnsLabel string, origins []string, allowAnyHost bool) []string {
	title := fmt.Sprintf("localproxy %s  —  ready", version)
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
	if allowAnyHost {
		hostLine = "  Host     :  ANY (--allow-any-host — not recommended)"
	}
	licenseLine := fmt.Sprintf("  License  :  %s", License)
	authorLine := fmt.Sprintf("  Author   :  %s [%s]", Author, AuthorURL)
	repoLine := fmt.Sprintf("  Repo     :  %s", RepoURL)

	runeWidth := func(s string) int { return utf8.RuneCountInString(s) }
	innerWidth := runeWidth(title)
	for _, line := range []string{addressLine, tokenLine, dnsLine, originsLine, hostLine, licenseLine, authorLine, repoLine} {
		if w := runeWidth(line); w > innerWidth {
			innerWidth = w
		}
	}
	innerWidth += 4

	hBar := strings.Repeat("═", innerWidth)
	pad := func(s string) string {
		gap := innerWidth - runeWidth(s) - 2
		if gap < 0 {
			gap = 0
		}
		return "║  " + s + strings.Repeat(" ", gap) + "║"
	}
	titlePad := (innerWidth - runeWidth(title)) / 2
	titleRight := innerWidth - runeWidth(title) - titlePad
	centeredTitle := "║" + strings.Repeat(" ", titlePad) + title + strings.Repeat(" ", titleRight) + "║"
	thinBar := "╟" + strings.Repeat("─", innerWidth) + "╢"

	return []string{
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
		thinBar,
		pad(licenseLine),
		pad(authorLine),
		pad(repoLine),
		"╚" + hBar + "╝",
		"",
		"  Enter the address and token in your online tool.",
		"  Press Ctrl+C to stop.",
		"",
	}
}

func TestCompat13_BannerUnchangedWithoutNewFlags(t *testing.T) {
	token := strings.Repeat("ab", 24)
	long := "https://a-very-long-origin-name-that-widens-the-box.example.com"
	cases := []struct {
		version  string
		port     int
		dns      string
		origins  []string
		anyHost  bool
		tokenStr string
	}{
		{"dev", 8765, "1.1.1.1:53, 8.8.8.8:53", nil, false, token},
		{"v1.3.0", 1, "system", []string{"https://www.jpkc.com"}, false, token},
		{"v1.4.0", 65535, "9.9.9.9:53", []string{"https://a.example", "http://localhost:8080"}, true, token},
		{"dev", 40000, "1.1.1.1:53", []string{long, long}, true, token},
		{"dev", 0, "", nil, false, ""},
	}
	for i, c := range cases {
		got := bannerLines(bannerInfo{
			version: c.version, port: c.port, token: c.tokenStr, dnsLabel: c.dns,
			origins: c.origins, allowAnyHost: c.anyHost,
		})
		want := v13Banner(c.version, c.port, c.tokenStr, c.dns, c.origins, c.anyHost)
		if !slices.Equal(got, want) {
			t.Errorf("case %d: banner differs from v1.3.0\n got:\n%s\nwant:\n%s", i, strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	}
}

// -----------------------------------------------------------------------
// Flags (COMPAT-2)
// -----------------------------------------------------------------------

// v13Origins is the v1.3.0 origin parsing from main().
func v13Origins(raw string) []string {
	var origins []string
	if raw != "" {
		for _, o := range strings.Split(raw, ",") {
			trimmed := strings.TrimSpace(o)
			if trimmed != "" {
				origins = append(origins, trimmed)
			}
		}
	}
	return origins
}

func TestCompat13_ValidateFlagsWithoutNewFlags(t *testing.T) {
	base := startFlags{port: 0, timeoutSec: 30, maxMB: 50}

	// The v1.3.0 range errors, word for word (main printed them with "fatal: ").
	errCases := []struct {
		mod  func(*startFlags)
		want string
	}{
		{func(f *startFlags) { f.port = -1 }, "--port must be between 0 and 65535, got -1"},
		{func(f *startFlags) { f.port = 65536 }, "--port must be between 0 and 65535, got 65536"},
		{func(f *startFlags) { f.timeoutSec = 0 }, "--timeout must be at least 1 second, got 0"},
		{func(f *startFlags) { f.maxMB = -1 }, "--max-mb must be between 0 and 1048576, got -1"},
		{func(f *startFlags) { f.maxMB = 1024*1024 + 1 }, "--max-mb must be between 0 and 1048576, got 1048577"},
	}
	for _, c := range errCases {
		f := base
		c.mod(&f)
		_, err := validateFlags(f)
		if err == nil || err.Error() != c.want {
			t.Errorf("validateFlags(%+v) = %v, want %q", f, err, c.want)
		}
	}

	// Boundaries v1.3.0 accepted stay accepted.
	for _, mod := range []func(*startFlags){
		func(f *startFlags) { f.port = 65535 },
		func(f *startFlags) { f.timeoutSec = 1 },
		func(f *startFlags) { f.maxMB = 0 },
		func(f *startFlags) { f.maxMB = 1024 * 1024 },
		func(f *startFlags) { f.allowAnyHost = true },
	} {
		f := base
		mod(&f)
		if _, err := validateFlags(f); err != nil {
			t.Errorf("validateFlags(%+v): %v, v1.3.0 accepted it", f, err)
		}
	}

	// --origin is parsed exactly as in v1.3.0 and, without --allow-local, not
	// validated at all: "null", "*", http origins and paths keep working.
	for _, raw := range []string{
		"", ",", " , ", "https://www.jpkc.com", " https://a.example , ,https://b.example ",
		"null", "*", "http://www.example.com", "https://www.example.com/tools/", "https://x.example?y",
	} {
		f := base
		f.rawOrigins = raw
		start, err := validateFlags(f)
		if err != nil {
			t.Errorf("--origin %q: %v, v1.3.0 accepted it", raw, err)
			continue
		}
		if !slices.Equal(start.origins, v13Origins(raw)) {
			t.Errorf("--origin %q parsed to %q, v1.3.0 parsed %q", raw, start.origins, v13Origins(raw))
		}
		if start.allowLocal != nil || len(start.warnings) != 0 {
			t.Errorf("--origin %q: allowLocal %v, warnings %q, want none", raw, start.allowLocal, start.warnings)
		}
	}

	// Positional arguments: v1.3.0 ignored them silently. Now a warning, never
	// a start-up error, whatever else is set.
	for _, args := range [][]string{
		{"stray"},
		{"https://b.example"},
		{"x", "--origin", "https://a.example"},
		// {"--allow-local", "*.ddev.site"} was here (flag after a positional:
		// not parsed, not "set"). Corrected by the builder: that is the
		// PowerShell trap LOCAL-1 makes fatal — the user did give the new
		// flag, and no v1.3.0 command line contains it — so it is checked
		// below as a start-up error instead.
	} {
		f := base
		f.rawOrigins = "https://a.example"
		f.allowAnyHost = true
		f.args = args
		start, err := validateFlags(f)
		if err != nil {
			t.Errorf("args %q without --allow-local: %v, want only a warning (COMPAT-2)", args, err)
			continue
		}
		if len(start.warnings) != 1 || !strings.Contains(start.warnings[0], strconv.Quote(args[0])) {
			t.Errorf("args %q: warnings %q, want one naming the arguments", args, start.warnings)
		}
		if start.allowLocal != nil {
			t.Errorf("args %q: allowLocal %v, want off", args, start.allowLocal)
		}
	}
	f := base
	f.rawOrigins = "https://a.example"
	f.args = []string{"https://b.example", "--allow-local", "*.ddev.site"}
	if _, err := validateFlags(f); err == nil || !strings.Contains(err.Error(), "quote the list") {
		t.Errorf("args %q: %v, want the LOCAL-1 positional-argument error", f.args, err)
	}
}

// TestCompat13_ValidateFlags_WindowsQuoting covers the PowerShell splitting of
// an unquoted comma list (LOCAL-1) at the validateFlags level, as main hands
// it flag.Args().
func TestCompat13_ValidateFlags_WindowsQuoting(t *testing.T) {
	parse := func(argv ...string) (startFlags, error) {
		fs := flag.NewFlagSet("localproxy", flag.ContinueOnError)
		fs.SetOutput(new(strings.Builder))
		port := fs.Int("port", 0, "")
		origins := fs.String("origin", "", "")
		timeout := fs.Int("timeout", 30, "")
		maxMB := fs.Int64("max-mb", 50, "")
		fs.String("dns", "1.1.1.1,8.8.8.8", "")
		anyHost := fs.Bool("allow-any-host", false, "")
		var allow listFlag
		fs.Var(&allow, "allow-local", "")
		if err := fs.Parse(argv); err != nil {
			return startFlags{}, err
		}
		return startFlags{port: *port, timeoutSec: *timeout, maxMB: *maxMB, rawOrigins: *origins,
			allowAnyHost: *anyHost, allowLocal: allow.values, allowLocalSet: allow.set, args: fs.Args()}, nil
	}

	cases := []struct {
		argv    []string
		wantErr string // "" = starts
		local   string // canonical entries when it starts
	}{
		// PowerShell: --allow-local *.ddev.site,localhost:8888 --origin …
		{[]string{"--allow-local", "*.ddev.site", "localhost:8888", "--origin", "https://www.jpkc.com"}, `quote the list`, ""},
		{[]string{"--origin", "https://www.jpkc.com", "--allow-local", "*.ddev.site", "localhost:8888"}, `unexpected arguments ["localhost:8888"]`, ""},
		// Quoted forms.
		{[]string{"--origin", "https://www.jpkc.com", "--allow-local", "*.ddev.site,localhost:8888"}, "", "*.ddev.site,localhost:8888"},
		{[]string{"--origin", "https://www.jpkc.com", "--allow-local", "*.ddev.site, localhost:8888"}, "", "*.ddev.site,localhost:8888"},
		{[]string{"--origin", "https://www.jpkc.com", "--allow-local=*.ddev.site,localhost:8888"}, "", "*.ddev.site,localhost:8888"},
		{[]string{"-origin=https://www.jpkc.com", "-allow-local", "*.ddev.site"}, "", "*.ddev.site"},
		// Repeated flag: merged.
		{[]string{"--origin", "https://www.jpkc.com", "--allow-local", "*.ddev.site", "--allow-local", "localhost:8888"}, "", "*.ddev.site,localhost:8888"},
		// Windows PowerShell 5.1 drops an empty "" argument: --allow-local then
		// swallows the next flag name as its value.
		{[]string{"--allow-local", "--origin", "https://www.jpkc.com"}, "unexpected arguments", ""},
		{[]string{"--origin", "https://www.jpkc.com", "--allow-local", ""}, "is empty", ""},
		{[]string{"--origin", "https://www.jpkc.com", "--allow-local", ",,"}, "is empty", ""},
		// Brackets survive PowerShell; unbracketed IPv6 is refused.
		{[]string{"--origin", "https://www.jpkc.com", "--allow-local", "[fd00::5]:8443"}, "", "[fd00::5]:8443"},
		{[]string{"--origin", "https://www.jpkc.com", "--allow-local", "fd00::5"}, "brackets", ""},
	}
	for _, c := range cases {
		f, err := parse(c.argv...)
		if err != nil {
			t.Errorf("%q: flag parse: %v", c.argv, err)
			continue
		}
		start, err := validateFlags(f)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("%q: err = %v, want one containing %q", c.argv, err, c.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v, want a start", c.argv, err)
			continue
		}
		var got []string
		for _, e := range start.allowLocal {
			got = append(got, e.String())
		}
		if strings.Join(got, ",") != c.local {
			t.Errorf("%q: entries %q, want %q", c.argv, got, c.local)
		}
	}
}

// -----------------------------------------------------------------------
// Pre-check and dialer without --allow-local
// -----------------------------------------------------------------------

// compat13IPs covers every privateRangeCIDRs class plus public addresses and
// IPv4-mapped forms.
var compat13IPs = []string{
	"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700::1111",
	"127.0.0.1", "127.255.255.254", "::1", "10.0.0.1", "172.16.0.1", "172.31.255.255", "172.32.0.1",
	"192.168.1.1", "100.64.0.1", "100.100.100.200", "fc00::1", "fd00:ec2::254", "fd12::5",
	"0.0.0.0", "169.254.169.254", "192.0.0.8", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.5",
	"224.0.0.1", "240.0.0.1", "255.255.255.255", "::", "64:ff9b::a00:1", "100::1", "2001:db8::1",
	"2002:a00:1::", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::ffff:8.8.8.8",
}

func TestCompat13_PrecheckMatchesV13(t *testing.T) {
	cfg := newTestConfig() // no ssrfCheck, no lookupIP, no list: the production path
	cfg.port = 8765
	for _, s := range compat13IPs {
		ip := net.ParseIP(s)
		host := s
		if strings.Contains(s, ":") {
			host = "[" + s + "]"
		}
		for _, port := range []string{"", ":80", ":443", ":8765", ":8080"} {
			for _, scheme := range []string{"http", "https"} {
				u, err := url.Parse(scheme + "://" + host + port + "/")
				if err != nil {
					t.Fatalf("parse: %v", err)
				}
				blocked, reason := cfg.precheck(context.Background(), u, false)
				want := isBlockedIP(ip)
				if blocked != want {
					t.Errorf("%s: blocked = %v, v1.3.0 isBlockedIP = %v", u, blocked, want)
				}
				// v1.3.0 pre-check through isPrivateHost agrees too.
				if old := isPrivateHost(context.Background(), u.Host, nil); old != want {
					t.Errorf("%s: isPrivateHost = %v, want %v", u, old, want)
				}
				switch {
				case !blocked && reason != "":
					t.Errorf("%s: reason %q on an allowed target", u, reason)
				case blocked && reason != reasonPrivate && reason != reasonAlwaysBlocked:
					t.Errorf("%s: reason %q, without --allow-local only private/always_blocked may appear", u, reason)
				}
				// Same verdict also with localStart=true: without a list no
				// request can be local.
				if b2, r2 := cfg.precheck(context.Background(), u, true); b2 != blocked || r2 != reason {
					t.Errorf("%s: localStart=true changed the verdict to %v/%q", u, b2, r2)
				}
				if cfg.allowLocalMatchURL(u) {
					t.Errorf("%s: allowLocalMatchURL true without --allow-local", u)
				}
			}
		}
	}

	// Names: a failing resolver fails open, as in v1.3.0.
	failing := &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("no DNS in this test")
	}}
	cfg.resolver = failing
	for _, h := range []string{"example.com", "wp.ddev.site", "foo.localhost", "nas.lan"} {
		u, _ := url.Parse("http://" + h + "/")
		if blocked, reason := cfg.precheck(context.Background(), u, false); blocked || reason != "" {
			t.Errorf("%s with failing DNS: %v/%q, v1.3.0 failed open", h, blocked, reason)
		}
	}

	// The ssrfCheck test hook keeps its v1.3.0 meaning, reason "private".
	cfg.ssrfCheck = func(h string) bool { return h == "blocked.example" }
	u, _ := url.Parse("https://blocked.example/")
	if b, r := cfg.precheck(context.Background(), u, false); !b || r != reasonPrivate {
		t.Errorf("ssrfCheck hook: %v/%q, want true/private", b, r)
	}
	u, _ = url.Parse("http://127.0.0.1/")
	if b, r := cfg.precheck(context.Background(), u, false); b || r != "" {
		t.Errorf("ssrfCheck hook allowing 127.0.0.1: %v/%q, want false", b, r)
	}
}

// TestCompat13_DialerPathUnchanged: without a list and without the test hook,
// localGuard is the plain dialer: same refusal, same error text, no request.
func TestCompat13_DialerPathUnchanged(t *testing.T) {
	srv, hits := countingServer(t, nil)
	cfg := newTestConfig()
	client := newUpstreamClient(cfg)
	for _, target := range []string{srv.URL + "/", "http://169.254.169.254/latest/"} {
		resp, err := client.Get(target)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("GET %s succeeded, want a dialer block", target)
		}
		if !errors.Is(err, errBlockedTarget) {
			t.Errorf("GET %s: %v does not unwrap to errBlockedTarget", target, err)
		}
		u, _ := url.Parse(target)
		if want := "target address is blocked: " + u.Hostname(); !strings.Contains(err.Error(), want) {
			t.Errorf("GET %s: error %q, want the v1.3.0 text %q", target, err, want)
		}
		if code, msg := classifyUpstreamError(err); code != "blocked_target" || msg != "target resolves to a private or reserved address" {
			t.Errorf("classify: %s / %s", code, msg)
		}
	}
	if hits.Load() != 0 {
		t.Errorf("blocked target got %d requests", hits.Load())
	}
}

// -----------------------------------------------------------------------
// Endpoint bodies and headers
// -----------------------------------------------------------------------

// jsonKeys returns the sorted keys of a JSON object.
func jsonKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("decode: %v — %s", err, raw)
	}
	return slices.Sorted(func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	})
}

func compat13Do(t *testing.T, cfg *config, h func(*config, *http.Client) http.Handler, method, path string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("X-Proxy-Token", cfg.sessionToken)
	req.Header.Set("Origin", "https://test.example.com")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	h(cfg, newUpstreamClient(cfg)).ServeHTTP(rr, req)
	return rr
}

// TestCompat13_PrecheckRejectionBody: the 403 of the start-URL pre-check keeps
// the v1.3.0 body (error, message, status — no type) and only gains reason.
func TestCompat13_PrecheckRejectionBody(t *testing.T) {
	cfg := newTestConfig()
	cfg.port = 8765
	handlers := map[string]func(*config, *http.Client) http.Handler{
		"/proxy": proxyHandler, "/inspect": inspectHandler, "/page": pageHandler,
	}
	targets := map[string]string{
		"http://127.0.0.1:1/":               reasonPrivate,
		"http://10.0.0.1/":                  reasonPrivate,
		"http://[::1]:8080/":                reasonPrivate,
		"http://[fd12::5]/":                 reasonPrivate,
		"http://169.254.169.254/latest/":    reasonAlwaysBlocked,
		"http://0.0.0.0/":                   reasonAlwaysBlocked,
		"http://127.0.0.1:8765/ping":        reasonAlwaysBlocked,
		"http://100.100.100.200/":           reasonAlwaysBlocked,
		"http://[fd00:ec2::254]/":           reasonAlwaysBlocked,
		"http://[::ffff:169.254.169.254]/x": reasonAlwaysBlocked,
	}
	for path, h := range handlers {
		for target, reason := range targets {
			for _, extra := range []string{"", "&diag=1", "&get=1", "&body=1", "&follow=1"} {
				rr := compat13Do(t, cfg, h, http.MethodGet, path+"?url="+url.QueryEscape(target)+extra, nil)
				if rr.Code != http.StatusForbidden {
					t.Errorf("%s %s%s: status %d, want 403", path, target, extra, rr.Code)
					continue
				}
				if keys := jsonKeys(t, rr.Body.Bytes()); !slices.Equal(keys, []string{"error", "message", "reason", "status"}) {
					t.Errorf("%s %s: keys %q, want v1.3.0 keys plus reason", path, target, keys)
				}
				pe := decodeProxyError(t, rr)
				if pe.Error != "blocked_target" || pe.Message != "target resolves to a private or reserved address" ||
					pe.Status != 403 || pe.Type != "" || pe.Reason != reason {
					t.Errorf("%s %s: body %+v, want blocked_target/v1.3.0 message/403/reason %s", path, target, pe, reason)
				}
				if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://test.example.com" {
					t.Errorf("%s %s: Allow-Origin %q", path, target, got)
				}
				if got, want := rr.Header().Values("Vary"), compat14Vary(path); !slices.Equal(got, want) {
					t.Errorf("%s %s: Vary %q, want %q", path, target, got, want)
				}
				if rr.Header().Get("Access-Control-Expose-Headers") != "" {
					t.Errorf("%s %s: Expose-Headers on a pre-check error", path, target)
				}
			}
		}
	}
}

// compat14Vary is the Vary list of a v1.4.0 response without credentials:
// v1.3.0's "Origin", plus "X-Target-Authorization" on /proxy (section 4.1,
// difference 2).
func compat14Vary(path string) []string {
	if path == "/proxy" {
		return []string{"Origin", "X-Target-Authorization"}
	}
	return []string{"Origin"}
}

// TestCompat13_DialerRejectionBody: a dialer block (pre-check disabled by the
// v1.3.0 test hook) keeps the v1.3.0 502 body and only gains reason.
func TestCompat13_DialerRejectionBody(t *testing.T) {
	srv, hits := countingServer(t, nil)
	cfg := newTestConfig()
	cfg.ssrfCheck = func(string) bool { return false }
	target := srv.URL + "/"

	const blockedMsg = "target resolves to a private or reserved address"
	check := func(where string, pe *proxyError, wantStatus int, wantReason string) {
		t.Helper()
		if pe == nil {
			t.Fatalf("%s: no error", where)
		}
		// /page prefixes the code to the message, as v1.3.0 did.
		wantMsg := blockedMsg
		if strings.HasPrefix(where, "/page") {
			wantMsg = "blocked_target: " + blockedMsg
		}
		if pe.Error != "blocked_target" || pe.Message != wantMsg ||
			pe.Status != wantStatus || pe.Type != proxyErrorType("blocked_target", nil) || pe.Reason != wantReason {
			t.Errorf("%s: %+v, want blocked_target/%d/type %q/reason %s", where, *pe, wantStatus, proxyErrorType("blocked_target", nil), wantReason)
		}
	}

	for _, ownPort := range []bool{false, true} {
		wantReason := reasonPrivate
		cfg.port = 0
		if ownPort {
			cfg.port, _ = strconv.Atoi(serverPort(t, srv))
			wantReason = reasonAlwaysBlocked
		}

		for _, extra := range []string{"", "&follow=1"} {
			for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
				rr := compat13Do(t, cfg, proxyHandler, m, "/proxy?url="+url.QueryEscape(target)+extra, nil)
				if rr.Code != http.StatusBadGateway {
					t.Fatalf("/proxy %s%s: status %d, want 502", m, extra, rr.Code)
				}
				if m == http.MethodHead {
					continue
				}
				if keys := jsonKeys(t, rr.Body.Bytes()); !slices.Equal(keys, []string{"error", "message", "reason", "status", "type"}) {
					t.Errorf("/proxy %s: keys %q", m, keys)
				}
				pe := decodeProxyError(t, rr)
				check("/proxy "+m+extra, &pe, 502, wantReason)
			}
		}

		for _, extra := range []string{"", "&get=1", "&body=1"} {
			rr := compat13Do(t, cfg, inspectHandler, http.MethodGet, "/inspect?url="+url.QueryEscape(target)+extra, nil)
			if rr.Code != http.StatusBadGateway {
				t.Fatalf("/inspect%s: status %d, want 502", extra, rr.Code)
			}
			pe := decodeProxyError(t, rr)
			check("/inspect"+extra, &pe, 502, wantReason)
		}

		rr := compat13Do(t, cfg, inspectHandler, http.MethodGet, "/inspect?diag=1&url="+url.QueryEscape(target), nil)
		var ir inspectResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &ir); err != nil {
			t.Fatalf("/inspect diag: %v — %s", err, rr.Body.String())
		}
		check("/inspect diag error", ir.Error, 502, wantReason)

		for _, extra := range []string{"", "&diag=1"} {
			rr := compat13Do(t, cfg, pageHandler, http.MethodGet, "/page?url="+url.QueryEscape(target)+extra, nil)
			var raw map[string]json.RawMessage
			if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
				t.Fatalf("/page: %v", err)
			}
			if _, isTop := raw["redirectChain"]; !isTop {
				pe := decodeProxyError(t, rr)
				check("/page"+extra+" top", &pe, rr.Code, wantReason)
				continue
			}
			var pr pageResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &pr); err != nil {
				t.Fatalf("/page: %v", err)
			}
			check("/page"+extra+" error", pr.Error, pr.Error.Status, wantReason)
			if n := len(pr.RedirectChain); n == 0 || pr.RedirectChain[n-1].ErrorCategory != "blocked_target" ||
				pr.RedirectChain[n-1].ErrorReason != wantReason {
				t.Errorf("/page%s: hops %+v, want a blocked_target hop with errorReason %s", extra, pr.RedirectChain, wantReason)
			}
		}
	}
	if hits.Load() != 0 {
		t.Errorf("blocked target got %d requests", hits.Load())
	}
}

// TestCompat13_NoReasonOnOtherErrors: reason is only for blocked_target. Every
// other error keeps exactly the v1.3.0 keys.
func TestCompat13_NoReasonOnOtherErrors(t *testing.T) {
	cfg := newTestConfig()
	cases := []struct {
		h      func(*config, *http.Client) http.Handler
		method string
		path   string
		hdr    map[string]string
		status int
	}{
		{proxyHandler, http.MethodGet, "/proxy", nil, 400},
		{proxyHandler, http.MethodGet, "/proxy?url=ftp://example.com/", nil, 400},
		{proxyHandler, http.MethodPut, "/proxy?url=https://example.com/", nil, 405},
		{inspectHandler, http.MethodPost, "/inspect?url=https://example.com/", nil, 405},
		{pageHandler, http.MethodHead, "/page?url=https://example.com/", nil, 405},
		{proxyHandler, http.MethodGet, "/proxy?url=https://example.com/", map[string]string{"X-Proxy-Token": "wrong"}, 403},
		{proxyHandler, http.MethodGet, "/proxy?url=https://example.com/", map[string]string{"Origin": "https://evil.example"}, 403},
	}
	for _, c := range cases {
		rr := compat13Do(t, cfg, c.h, c.method, c.path, c.hdr)
		if rr.Code != c.status {
			t.Errorf("%s %s: status %d, want %d", c.method, c.path, rr.Code, c.status)
			continue
		}
		if c.method == http.MethodHead {
			continue
		}
		if !strings.HasPrefix(rr.Header().Get("Content-Type"), "application/json") {
			// Plain-text rejections (rejected origin) stay plain text.
			if strings.Contains(rr.Body.String(), "reason") {
				t.Errorf("%s %s: %q", c.method, c.path, rr.Body.String())
			}
			continue
		}
		if keys := jsonKeys(t, rr.Body.Bytes()); !slices.Equal(keys, []string{"error", "message", "status"}) {
			t.Errorf("%s %s: keys %q, want the v1.3.0 [error message status]", c.method, c.path, keys)
		}
	}

	// An upstream failure that is not a block: dns_error, no reason.
	cfg.ssrfCheck = func(string) bool { return false }
	cfg.lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	cfg.resolver = &net.Resolver{PreferGo: true, Dial: func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.DNSError{Err: "no such host", IsNotFound: true}
	}}
	for _, withHook := range []bool{true, false} {
		if !withHook {
			cfg.lookupIP = nil
		}
		rr := compat13Do(t, cfg, proxyHandler, http.MethodGet, "/proxy?url="+url.QueryEscape("https://nx.example/"), nil)
		pe := decodeProxyError(t, rr)
		if pe.Error != "dns_error" || pe.Reason != "" {
			t.Errorf("hook=%v: %+v, want dns_error without reason", withHook, pe)
		}
		if strings.Contains(rr.Body.String(), `"reason"`) {
			t.Errorf("hook=%v: reason key on a non-block error: %s", withHook, rr.Body.String())
		}
	}
}

// TestCompat13_PreflightHeadersUnchanged pins the v1.3.0 CORS values, apart
// from the two differences of section 4.1 that AUTH-1 and AUTH-10 bring:
// Allow-Headers adds the two credential headers, Vary on /proxy adds
// X-Target-Authorization. Methods, Max-Age and the rest stay.
func TestCompat13_PreflightHeadersUnchanged(t *testing.T) {
	cfg := newTestConfig()
	want := map[string]string{
		"Access-Control-Allow-Origin":          "https://test.example.com",
		"Access-Control-Allow-Methods":         "GET, HEAD, POST, OPTIONS",
		"Access-Control-Allow-Headers":         "Content-Type, X-Proxy-Token, X-Target-Authorization, X-Target-Origin",
		"Access-Control-Allow-Private-Network": "true",
		"Access-Control-Max-Age":               "600",
	}
	for name, h := range map[string]func(*config, *http.Client) http.Handler{
		"/proxy": proxyHandler, "/inspect": inspectHandler, "/page": pageHandler,
	} {
		rr := compat13Do(t, cfg, h, http.MethodOptions, name+"?url=https://example.com/",
			map[string]string{"Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "x-proxy-token"})
		if rr.Code != http.StatusNoContent {
			t.Errorf("%s OPTIONS: %d", name, rr.Code)
		}
		for k, v := range want {
			if got := rr.Header().Get(k); got != v {
				t.Errorf("%s OPTIONS: %s = %q, want %q", name, k, got, v)
			}
		}
		if got, want := rr.Header().Values("Vary"), compat14Vary(name); !slices.Equal(got, want) {
			t.Errorf("%s OPTIONS: Vary %q, want %q", name, got, want)
		}
		if rr.Header().Get("Access-Control-Expose-Headers") != "" {
			t.Errorf("%s OPTIONS: Expose-Headers set", name)
		}
	}
}

// TestCompat13_SuccessPathUnchanged: a successful /proxy through a test
// server — the transport now wraps the dialer in localGuard — keeps the
// v1.3.0 headers and Expose-Headers (test hooks as in the v1.3.0 suite).
func TestCompat13_SuccessPathUnchanged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom", "1")
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	cfg := testCfg(t, nil)
	cfg.allowedOrigins = []string{"https://test.example.com"}
	rr := compat13Do(t, cfg, proxyHandler, http.MethodGet, "/proxy?url="+url.QueryEscape(srv.URL+"/"), nil)
	if rr.Code != 200 || rr.Body.String() != "ok" {
		t.Fatalf("status %d body %q", rr.Code, rr.Body.String())
	}
	if got, want := rr.Header().Values("Vary"), compat14Vary("/proxy"); !slices.Equal(got, want) {
		t.Errorf("Vary %q, want %q", got, want)
	}
	exp := rr.Header().Get("Access-Control-Expose-Headers")
	for _, h := range []string{"X-Custom", "X-Upstream-IP", "X-Upstream-Final-URL"} {
		if !exposed(rr, h) {
			t.Errorf("Expose-Headers %q lacks %s", exp, h)
		}
	}
	for _, h := range []string{"X-Upstream-Auth", "X-Upstream-Cache-Control"} {
		if exposed(rr, h) {
			t.Errorf("Expose-Headers %q has %s, an AUTH-* header", exp, h)
		}
	}
	if ip := rr.Header().Get("X-Upstream-IP"); ip != "127.0.0.1" {
		t.Errorf("X-Upstream-IP %q", ip)
	}
}

// -----------------------------------------------------------------------
// main() in a subprocess: --help, defaults, start-up
// -----------------------------------------------------------------------

const compat13MainEnv = "LOCALPROXY_COMPAT13_MAIN_ARGS"

// TestCompat13_MainHelper is not a test of its own: the subprocess tests
// re-run the test binary with compat13MainEnv set, and this then runs main()
// with those arguments.
func TestCompat13_MainHelper(t *testing.T) {
	raw := os.Getenv(compat13MainEnv)
	if raw == "" {
		t.Skip("helper for the subprocess tests")
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

type compat13Result struct {
	exitCode int  // -1: still running (killed after the banner)
	running  bool // the banner appeared and the server was up
	output   string
}

// compat13RunMain runs main() with args in a subprocess. It returns once the
// process exits, or kills it once the banner is complete.
func compat13RunMain(t *testing.T, args ...string) compat13Result {
	t.Helper()
	enc, _ := json.Marshal(args)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCompat13_MainHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), compat13MainEnv+"="+string(enc))
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = pw, pw
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pw.Close()

	var out strings.Builder
	res := compat13Result{exitCode: -1}
	sc := bufio.NewScanner(pr)
	for sc.Scan() {
		out.WriteString(sc.Text() + "\n")
		if strings.Contains(sc.Text(), "Press Ctrl+C to stop.") {
			res.running = true
			break
		}
	}
	if res.running {
		_ = cmd.Process.Kill()
	}
	pr.Close()
	err = cmd.Wait()
	if !res.running {
		var ee *exec.ExitError
		switch {
		case err == nil:
			res.exitCode = 0
		case errors.As(err, &ee):
			res.exitCode = ee.ExitCode()
		default:
			t.Fatalf("wait: %v", err)
		}
	}
	res.output = out.String()
	return res
}

func TestCompat13_MainHelpAndDefaults(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test")
	}
	res := compat13RunMain(t, "--help")
	if res.exitCode != 0 {
		t.Fatalf("--help exit %d:\n%s", res.exitCode, res.output)
	}
	// v1.3.0 --help lines (flags and defaults, COMPAT-2), verbatim.
	for _, line := range []string{
		"  -allow-any-host\n    \tAccept requests with a non-localhost Host header (not recommended)\n",
		"  -dns string\n    \tComma-separated DNS servers (e.g. \"9.9.9.9,8.8.4.4\"), or \"system\" for OS defaults (default \"1.1.1.1,8.8.8.8\")\n",
		"  -max-mb int\n    \tMaximum upstream response size in megabytes (0 = unlimited) (default 50)\n",
		"  -origin string\n    \tComma-separated list of allowed Origins, e.g. https://mytool.example.com\n",
		"  -port int\n    \tTCP port to listen on (0 = random free port)\n",
		"  -timeout int\n    \tUpstream request timeout in seconds (default 30)\n",
		"  -version\n    \tPrint version information and exit\n",
	} {
		if !strings.Contains(res.output, line) {
			t.Errorf("--help lacks the v1.3.0 entry %q", line)
		}
	}
	// DOC-4: --allow-local explains itself.
	i := strings.Index(res.output, "  -allow-local")
	if i < 0 {
		t.Fatalf("--help has no -allow-local:\n%s", res.output)
	}
	help := res.output[i:]
	if j := strings.Index(help[2:], "\n  -"); j >= 0 {
		help = help[:j+2]
	}
	for _, want := range []string{"requires --origin", "localhost:8888", "ddev.site", "quote", "brackets", "80/443", "Off by default"} {
		if !strings.Contains(help, want) {
			t.Errorf("-allow-local help lacks %q: %s", want, help)
		}
	}
	if strings.Contains(help, "(default ") {
		t.Errorf("-allow-local shows a default: %s", help)
	}
}

func TestCompat13_MainStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test")
	}
	type want struct {
		running  bool
		contains []string
		absent   []string
	}
	cases := []struct {
		args []string
		want want
	}{
		// v1.3.0 command lines: start, no Local line, no WARNING line.
		{nil, want{true, []string{"Origins  :  (all — pass --origin for production)", "Host     :  localhost only"}, []string{"Local", "WARNING"}}},
		{[]string{"--origin", "https://www.jpkc.com,https://tools.example"}, want{true, []string{"Origins  :  https://www.jpkc.com, https://tools.example"}, []string{"Local", "WARNING"}}},
		{[]string{"--origin", "null", "--allow-any-host", "--timeout", "5", "--max-mb", "0", "--dns", "system"}, want{true, []string{"Origins  :  null", "Host     :  ANY", "DNS      :  system"}, []string{"Local", "WARNING"}}},
		// Positional arguments without new flags: start with a warning (COMPAT-2).
		{[]string{"--origin", "https://a.example", "https://b.example"}, want{true, []string{"Origins  :  https://a.example", `WARNING  :  ignored arguments ["https://b.example"]`}, []string{"Local    :"}}},
		{[]string{"stray"}, want{true, []string{`WARNING  :  ignored arguments ["stray"]`}, nil}},
		// PowerShell-split --allow-local: fatal, names the leftovers.
		{[]string{"--allow-local", "*.ddev.site", "localhost:8888", "--origin", "https://www.jpkc.com"}, want{false, []string{"fatal: unexpected arguments", `"localhost:8888"`, `quote the list: --allow-local "a,b"`}, nil}},
		// LOCAL-8.
		{[]string{"--allow-local", "*.ddev.site"}, want{false, []string{"fatal: --allow-local requires --origin"}, nil}},
		{[]string{"--allow-local", "*.ddev.site", "--origin", "https://www.jpkc.com", "--allow-any-host"}, want{false, []string{"fatal: --allow-local cannot be combined with --allow-any-host"}, nil}},
		// Proper start with the new flag: banner lines.
		{[]string{"--origin", "https://www.jpkc.com", "--allow-local", "*.ddev.site,localhost:8888"}, want{true, []string{"Local    :  *.ddev.site, localhost:8888", "WARNING  :  local network access enabled for the allowed origins"}, nil}},
	}
	for _, c := range cases {
		res := compat13RunMain(t, c.args...)
		if res.running != c.want.running {
			t.Errorf("%q: running=%v (exit %d), want running=%v:\n%s", c.args, res.running, res.exitCode, c.want.running, res.output)
			continue
		}
		if !res.running && res.exitCode == 0 {
			t.Errorf("%q: exit 0, want a failure", c.args)
		}
		for _, s := range c.want.contains {
			if !strings.Contains(res.output, s) {
				t.Errorf("%q: output lacks %q:\n%s", c.args, s, res.output)
			}
		}
		for _, s := range c.want.absent {
			if strings.Contains(res.output, s) {
				t.Errorf("%q: output has %q:\n%s", c.args, s, res.output)
			}
		}
	}
}
