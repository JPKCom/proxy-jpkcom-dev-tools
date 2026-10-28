package main

// Tests for CAP-1/CAP-2 (/version with capabilities and proof), TOK-1 (token
// probe) and TOK-2 (--token-file) of the v1.4.0 requirements. The Unix-only
// file checks are in tokenfile_unix_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"
)

// -----------------------------------------------------------------------
// /ping (real handler)
// -----------------------------------------------------------------------

func TestPingHandler(t *testing.T) {
	cfg := newTestConfig()
	h := pingHandler(cfg)

	req := httptest.NewRequest(http.MethodGet, "/ping", nil)
	req.Header.Set("Origin", "https://test.example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || rr.Body.String() != "localproxy ok\n" {
		t.Fatalf("got %d %q", rr.Code, rr.Body.String())
	}
	for name, want := range map[string]string{
		"Content-Type":                "text/plain",
		"X-Content-Type-Options":      "nosniff",
		"Access-Control-Allow-Origin": "https://test.example.com",
		"Vary":                        "Origin",
	} {
		if got := rr.Header().Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	// Preflight.
	req = httptest.NewRequest(http.MethodOptions, "/ping", nil)
	req.Header.Set("Origin", "https://test.example.com")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || rr.Body.Len() != 0 {
		t.Errorf("OPTIONS: got %d %q", rr.Code, rr.Body.String())
	}

	// Without --origin every origin may read it (no Origin header → "*").
	cfg.allowedOrigins = nil
	req = httptest.NewRequest(http.MethodGet, "/ping", nil)
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("without --origin Allow-Origin = %q, want *", got)
	}
}

// -----------------------------------------------------------------------
// /version (CAP-1, CAP-2)
// -----------------------------------------------------------------------

// getVersion calls the real /version handler and returns the raw body.
func getVersion(t *testing.T, cfg *config, rawQuery string) (*httptest.ResponseRecorder, []byte) {
	t.Helper()
	target := "/version"
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Origin", "https://test.example.com")
	rr := httptest.NewRecorder()
	versionHandler(cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("/version%s: status %d", target, rr.Code)
	}
	return rr, rr.Body.Bytes()
}

func TestVersionHandler_Capabilities(t *testing.T) {
	cfg := newTestConfig()
	rr, body := getVersion(t, cfg, "")
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := rr.Header().Get("Cache-Control"); cc != "" {
		t.Errorf("Cache-Control without challenge = %q, want none (v1.3.0 headers)", cc)
	}

	var got map[string]any
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	// The v1.3.0 keys: unchanged, still strings.
	for key, want := range map[string]string{
		"version": Version, "license": License, "author": Author, "url": AuthorURL, "repo": RepoURL,
	} {
		if v, ok := got[key].(string); !ok || v != want {
			t.Errorf("%s = %#v, want string %q", key, got[key], want)
		}
	}
	// capabilities: an array with all ten names, in this order.
	wantCaps := []string{"follow", "diag", "inspect-get", "no-location", "error-type",
		"target-auth", "allow-local", "token-file", "error-reason", "proof"}
	caps, ok := got["capabilities"].([]any)
	if !ok || len(caps) != len(wantCaps) {
		t.Fatalf("capabilities = %#v", got["capabilities"])
	}
	for i, c := range caps {
		if c != wantCaps[i] {
			t.Errorf("capabilities[%d] = %v, want %s", i, c, wantCaps[i])
		}
	}
	if got["localTargets"] != false || got["tokenPersistent"] != false {
		t.Errorf("runtime state without flags: localTargets=%v tokenPersistent=%v", got["localTargets"], got["tokenPersistent"])
	}
	limits, _ := got["limits"].(map[string]any)
	if limits["maxBytes"] != float64(1024*1024) || limits["timeoutSeconds"] != float64(10) {
		t.Errorf("limits = %#v", limits)
	}
	if _, ok := got["proof"]; ok {
		t.Error("proof without challenge")
	}
	if len(got) != 9 {
		t.Errorf("got %d keys, want 9: %v", len(got), got)
	}

	// Runtime state follows the configuration, as booleans only: no
	// --allow-local entry and no token-file path in the body.
	entries, err := parseAllowLocal([]string{"secret-site.ddev.site,10.0.5.0/24"}, 8765)
	if err != nil {
		t.Fatal(err)
	}
	cfg.allowLocal = entries
	cfg.tokenPersistent = true
	cfg.maxResponseBytes = 0
	cfg.requestTimeout = 45 * time.Second
	_, body = getVersion(t, cfg, "")
	got = nil
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatal(err)
	}
	if got["localTargets"] != true || got["tokenPersistent"] != true {
		t.Errorf("runtime state with flags: localTargets=%v tokenPersistent=%v", got["localTargets"], got["tokenPersistent"])
	}
	limits, _ = got["limits"].(map[string]any)
	if limits["maxBytes"] != float64(0) || limits["timeoutSeconds"] != float64(45) {
		t.Errorf("limits = %#v", limits)
	}
	for _, leak := range []string{"secret-site", "ddev.site", "10.0.5"} {
		if strings.Contains(string(body), leak) {
			t.Errorf("body leaks %q: %s", leak, body)
		}
	}
	if strings.Contains(string(body), cfg.sessionToken) {
		t.Error("body contains the session token")
	}
}

func TestVersionHandler_Proof(t *testing.T) {
	// Test vectors computed independently with
	//   printf 'localproxy-proof:%s:%s' "$port" "$challenge" | openssl dgst -sha256 -hmac "$token"
	const token = "0123456789abcdef0123456789abcdef0123456789abcdef"
	const port = 8765
	vectors := []struct {
		token, challenge, proof string
	}{
		{token, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
			"f60566d010925594613c729c59e8181693bfec35c5e3b0add698012663aeb4e4"},
		// Upper case is hex as well; the proof is over the challenge as sent.
		{token, "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
			"4669a14d865f43225739bde88160ae2fa0426a910c42a5db60522f81d62716d4"},
		{"test-token-abc", strings.Repeat("f", 64),
			"8b69450a1a944a61e720659ec9dc91132d1fbf8256cdfcdca1e046591fd4b6ad"},
	}
	for _, v := range vectors {
		if got := versionProof(v.token, port, v.challenge); got != v.proof {
			t.Errorf("versionProof(%s…, %d, %s…) = %s, want %s", v.token[:6], port, v.challenge[:6], got, v.proof)
		}

		cfg := newTestConfig()
		cfg.port = port
		cfg.sessionToken = v.token
		rr, body := getVersion(t, cfg, "challenge="+v.challenge)
		var got map[string]any
		if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if got["proof"] != v.proof {
			t.Errorf("/version?challenge=%s… proof = %v, want %s", v.challenge[:6], got["proof"], v.proof)
		}
		if cc := rr.Header().Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control with proof = %q, want no-store", cc)
		}
		if len(got) != 10 {
			t.Errorf("got %d keys with proof, want 10", len(got))
		}
	}

	// Another token gives another proof.
	if versionProof(token, port, vectors[0].challenge) == versionProof("f"+token[1:], port, vectors[0].challenge) {
		t.Error("proof does not depend on the token")
	}
	// Another port gives another proof (vector for 8766 from openssl as well).
	if got := versionProof(token, 8766, vectors[0].challenge); got != "2a97341902d3381d6b3b7e193f566a5e7df463759b01ed2317c13088cbf5a2a1" {
		t.Errorf("versionProof(port 8766) = %s", got)
	}

	// Invalid challenges: the field is missing and the body is byte for byte
	// the one without a challenge.
	cfg := newTestConfig()
	_, plain := getVersion(t, cfg, "")
	valid := vectors[0].challenge
	for _, q := range []string{
		"challenge=",
		"challenge=" + valid[:63],
		"challenge=" + valid + "0",
		"challenge=" + valid[:63] + "g",
		"challenge=" + strings.Repeat("z", 64),
		"challenge=" + valid + "&challenge=" + valid,
		"challenge=" + url.QueryEscape(" "+valid[1:]),
		"challenge=" + url.QueryEscape(valid[:62]+"é"),
		"Challenge=" + valid,
		"challenge;=" + valid,
	} {
		rr, body := getVersion(t, cfg, q)
		if !bytes.Equal(body, plain) {
			t.Errorf("?%s: body differs from the plain answer:\n%s", q, body)
		}
		if rr.Header().Get("Cache-Control") != "" {
			t.Errorf("?%s: Cache-Control set without a proof", q)
		}
	}

	// Preflight and through the full stack (Host check) like main wires it.
	mux := http.NewServeMux()
	mux.Handle("/version", versionHandler(cfg))
	srv := localhostOnly(cfg, mux)
	req := httptest.NewRequest(http.MethodOptions, "/version?challenge="+valid, nil)
	req.Host = "127.0.0.1:8765"
	req.Header.Set("Origin", "https://test.example.com")
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent || rr.Body.Len() != 0 {
		t.Errorf("OPTIONS /version: %d %q", rr.Code, rr.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/version?challenge="+valid, nil)
	req.Host = "127.0.0.1:8765"
	rr = httptest.NewRecorder()
	srv.ServeHTTP(rr, req)
	if !strings.Contains(rr.Body.String(), `"proof":"`+versionProof(cfg.sessionToken, cfg.port, valid)+`"`) {
		t.Errorf("full stack: no proof in %s", rr.Body.String())
	}
}

// -----------------------------------------------------------------------
// TOK-1: token probe without an upstream request
// -----------------------------------------------------------------------

func TestTokenProbe_Contract(t *testing.T) {
	cfg := newTestConfig()
	// Any upstream activity — pre-check, DNS, dial — fails the test.
	var touched sync.Map
	cfg.ssrfCheck = func(host string) bool { touched.Store("precheck "+host, true); return true }
	cfg.lookupIP = func(_ context.Context, host string) ([]net.IPAddr, error) {
		touched.Store("dns "+host, true)
		return nil, errors.New("no DNS in the token probe")
	}
	cfg.dialControl = func(_, address string, _ syscall.RawConn) error {
		touched.Store("dial "+address, true)
		return errors.New("no dial in the token probe")
	}
	h := inspectHandler(cfg, newUpstreamClient(cfg))

	probe := func(token string, extra http.Header) (int, proxyError) {
		req := httptest.NewRequest(http.MethodGet, "/inspect", nil)
		req.Header.Set("Origin", "https://test.example.com")
		if token != "" {
			req.Header.Set("X-Proxy-Token", token)
		}
		for k, v := range extra {
			req.Header[k] = v
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		var pe proxyError
		if err := json.Unmarshal(rr.Body.Bytes(), &pe); err != nil {
			t.Fatalf("token %q: body %q is not JSON", token, rr.Body.String())
		}
		if rr.Header().Get("Access-Control-Allow-Origin") != "https://test.example.com" {
			t.Errorf("token %q: probe answer without CORS", token)
		}
		return rr.Code, pe
	}

	cases := []struct {
		name   string
		token  string
		extra  http.Header
		status int
		code   string
	}{
		{"valid token", cfg.sessionToken, nil, http.StatusBadRequest, "bad_request"},
		{"wrong token", "wrong-token", nil, http.StatusForbidden, "forbidden"},
		{"no token", "", nil, http.StatusForbidden, "forbidden"},
		// The url check comes before the credential checks (AUTH-2): still
		// bad_request with X-Target-Authorization, even a malformed one.
		{"valid token + credentials", cfg.sessionToken, http.Header{
			"X-Target-Authorization": {"Basic dXNlcjpwYXNz"},
			"X-Target-Origin":        {"https://wp.example"},
		}, http.StatusBadRequest, "bad_request"},
		{"valid token + malformed credentials", cfg.sessionToken, http.Header{
			"X-Target-Authorization": {"nonsense"},
		}, http.StatusBadRequest, "bad_request"},
		{"wrong token + credentials", "wrong-token", http.Header{
			"X-Target-Authorization": {"Basic dXNlcjpwYXNz"},
			"X-Target-Origin":        {"https://wp.example"},
		}, http.StatusForbidden, "forbidden"},
	}
	for _, c := range cases {
		status, pe := probe(c.token, c.extra)
		if status != c.status || pe.Error != c.code || pe.Status != c.status {
			t.Errorf("%s: got %d %+v, want %d %s", c.name, status, pe, c.status, c.code)
		}
		if pe.Reason != "" || pe.Type != "" {
			t.Errorf("%s: probe answer carries reason/type: %+v", c.name, pe)
		}
	}
	touched.Range(func(k, _ any) bool {
		t.Errorf("token probe caused upstream activity: %v", k)
		return true
	})
}

// -----------------------------------------------------------------------
// TOK-2: --token-file
// -----------------------------------------------------------------------

// tokenTempLeftovers lists temporary token files left in dir.
func tokenTempLeftovers(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, ".localproxy-token-*"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTokenFile_RelativePathRefused(t *testing.T) {
	for _, p := range []string{
		"", "token", "./token", "../token", "~/x", "~", `%LOCALAPPDATA%\x`, `%LOCALAPPDATA%/x`,
		"$HOME/x", "${HOME}/x", "/home/$USER/token", "/tmp/%x%/token",
	} {
		_, _, err := loadOrCreateToken(p)
		if err == nil || err.Error() != tokenFileHelp {
			t.Errorf("loadOrCreateToken(%q) = %v, want the absolute-path error", p, err)
		}
		_, err = validateFlags(startFlags{timeoutSec: 30, maxMB: 50, tokenFile: p, tokenFileSet: true})
		if err == nil || err.Error() != tokenFileHelp {
			t.Errorf("validateFlags(--token-file %q) = %v, want the absolute-path error", p, err)
		}
	}
	// The message names a working form for every shell.
	for _, want := range []string{`$env:LOCALAPPDATA\localproxy\token`, `%LOCALAPPDATA%\localproxy\token`,
		`$HOME/.config/localproxy/token`, "no quotes around ~"} {
		if !strings.Contains(tokenFileHelp, want) {
			t.Errorf("help lacks %q", want)
		}
	}
	// Nothing was created in the working directory.
	for _, name := range []string{"token", "~", "%LOCALAPPDATA%", "$HOME"} {
		if _, err := os.Lstat(name); err == nil {
			t.Errorf("relative path created %q", name)
		}
	}
}

func TestTokenFile_CreateThenReuse(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "conf", "localproxy")
	path := filepath.Join(dir, "token")

	token, created, err := loadOrCreateToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if !created || !tokenFormat.MatchString(token) {
		t.Fatalf("first start: created=%t token=%q", created, token)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != token+"\n" {
		t.Fatalf("file content %q, %v", data, err)
	}
	if fi, err := os.Stat(path); err != nil || (isUnix() && fi.Mode().Perm() != 0o600) {
		t.Errorf("file mode %v, %v; want 0600", fi.Mode(), err)
	}
	if fi, err := os.Stat(dir); err != nil || (isUnix() && fi.Mode().Perm() != 0o700) {
		t.Errorf("folder mode %v, %v; want 0700", fi.Mode(), err)
	}

	again, created, err := loadOrCreateToken(path)
	if err != nil || created || again != token {
		t.Fatalf("second start: %q created=%t %v, want the same token", again, created, err)
	}
	// Hand-edited whitespace around a valid token is fine.
	if err := os.WriteFile(path, []byte("\r\n  "+token+" \r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if again, _, err := loadOrCreateToken(path); err != nil || again != token {
		t.Errorf("token with whitespace: %q %v", again, err)
	}
	if left := tokenTempLeftovers(t, dir); len(left) > 0 {
		t.Errorf("temporary files left: %v", left)
	}

	// A new token: delete the file and start again.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	fresh, created, err := loadOrCreateToken(path)
	if err != nil || !created || fresh == token {
		t.Errorf("after delete: %q created=%t %v, want a new token", fresh, created, err)
	}
}

func TestTokenFile_InvalidContent(t *testing.T) {
	dir := t.TempDir()
	valid := strings.Repeat("ab", 24)
	for name, content := range map[string]string{
		"empty":       "",
		"blank":       " \n",
		"47 chars":    valid[:47],
		"49 chars":    valid + "a",
		"upper case":  strings.ToUpper(valid),
		"non-hex":     valid[:47] + "g",
		"two tokens":  valid + "\n" + valid,
		"inner space": valid[:24] + " " + valid[24:],
		"huge":        valid + strings.Repeat(" ", tokenFileMaxBytes),
		"password":    "correct horse battery staple",
	} {
		path := filepath.Join(dir, strings.ReplaceAll(name, " ", "-"))
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _, err := loadOrCreateToken(path)
		if err == nil || !strings.Contains(err.Error(), "does not hold a localproxy token") {
			t.Errorf("%s: %v, want the content error", name, err)
		}
		// The file is left alone.
		if data, _ := os.ReadFile(path); string(data) != content {
			t.Errorf("%s: file was changed", name)
		}
	}
	// A folder at the path is not a token file.
	sub := filepath.Join(dir, "is-a-dir")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := loadOrCreateToken(sub); err == nil {
		t.Error("a folder was accepted as token file")
	}
}

func TestTokenFile_ConcurrentStart(t *testing.T) {
	for round := 0; round < 20; round++ {
		dir := t.TempDir()
		path := filepath.Join(dir, "token")
		const n = 8
		var wg sync.WaitGroup
		tokens := make([]string, n)
		createdBy := make([]bool, n)
		errs := make([]error, n)
		start := make(chan struct{})
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				tokens[i], createdBy[i], errs[i] = loadOrCreateToken(path)
			}(i)
		}
		close(start)
		wg.Wait()

		creators := 0
		for i := 0; i < n; i++ {
			if errs[i] != nil {
				t.Fatalf("round %d, start %d: %v", round, i, errs[i])
			}
			if tokens[i] != tokens[0] {
				t.Fatalf("round %d: different tokens %q / %q", round, tokens[i], tokens[0])
			}
			if createdBy[i] {
				creators++
			}
		}
		if creators != 1 {
			t.Fatalf("round %d: %d starts report creating the file, want exactly 1", round, creators)
		}
		if left := tokenTempLeftovers(t, dir); len(left) > 0 {
			t.Fatalf("round %d: temporary files left: %v", round, left)
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 1 {
			t.Fatalf("round %d: folder holds %d entries, want only the token", round, len(entries))
		}
	}
}

func TestBanner_TokenFileLines(t *testing.T) {
	tok := strings.Repeat("c", 48)
	info := bannerInfo{version: "dev", port: 8765, token: tok, dnsLabel: "1.1.1.1:53",
		origins: []string{"https://www.jpkc.com"}}
	plain := bannerLines(info)
	if len(plain) != 19 {
		t.Fatalf("v1.3.0 banner has 19 lines, got %d", len(plain))
	}
	for _, l := range plain {
		if strings.Contains(l, "token file") || strings.Contains(l, "Tokenfile") {
			t.Errorf("banner without --token-file has %q", l)
		}
	}

	for _, created := range []bool{false, true} {
		info.tokenFile = "/home/user/.config/localproxy/token"
		info.tokenCreated = created
		lines := bannerLines(info)
		if len(lines) != len(plain)+1 {
			t.Fatalf("created=%t: %d lines, want %d", created, len(lines), len(plain)+1)
		}
		suffix := "  (from token file)"
		if created {
			suffix = "  (new, saved to the token file)"
		}
		text := strings.Join(lines, "\n")
		for _, want := range []string{
			"║    Token    :  " + tok + suffix,
			"║    Tokenfile:  /home/user/.config/localproxy/token",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("created=%t: banner lacks %q:\n%s", created, want, text)
			}
		}
		for i, l := range lines {
			if strings.Contains(l, "Token    :") && !strings.Contains(lines[i+1], "Tokenfile:") {
				t.Errorf("Tokenfile line not right after the token: %q", lines[i+1])
			}
		}
		width := -1
		for _, l := range lines {
			if l == "" || !strings.ContainsAny(l[:3], "║╔╟╠╚") {
				continue
			}
			w := utf8.RuneCountInString(l)
			if width == -1 {
				width = w
			} else if w != width {
				t.Errorf("line width %d ≠ %d: %q", w, width, l)
			}
		}
	}

	// validateFlags adds the --port warning only with --token-file.
	f := startFlags{timeoutSec: 30, maxMB: 50, tokenFile: "/home/user/token", tokenFileSet: true}
	start, err := validateFlags(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(start.warnings) != 1 || start.warnings[0] != "--port not set — the address changes on every start" {
		t.Errorf("warnings with --token-file and no --port: %q", start.warnings)
	}
	if start.tokenFile != "/home/user/token" {
		t.Errorf("tokenFile = %q", start.tokenFile)
	}
	f.port = 8765
	if start, err := validateFlags(f); err != nil || len(start.warnings) != 0 {
		t.Errorf("with --port: %q %v", start.warnings, err)
	}
	if start, err := validateFlags(startFlags{timeoutSec: 30, maxMB: 50}); err != nil || len(start.warnings) != 0 || start.tokenFile != "" {
		t.Errorf("without --token-file: %+v %v", start, err)
	}
	info.warnings = []string{"--port not set — the address changes on every start"}
	if text := strings.Join(bannerLines(info), "\n"); !strings.Contains(text, "WARNING  :  --port not set — the address changes on every start") {
		t.Errorf("port warning missing:\n%s", text)
	}
}

func TestValidateFlags_TokenFilePositionalArgs(t *testing.T) {
	// An unquoted path with a space arrives split (PowerShell, cmd).
	f := startFlags{port: 8765, timeoutSec: 30, maxMB: 50, tokenFile: `C:\Users\Jean`, tokenFileSet: true,
		args: []string{`Pierre\AppData\Local\localproxy\token`, "--origin", "https://www.jpkc.com"}}
	if _, err := validateFlags(f); err == nil || !strings.Contains(err.Error(), "quote the path") {
		t.Errorf("split path: %v, want the quoting error", err)
	}
	// --token-file itself among the leftovers.
	for _, args := range [][]string{
		{"https://b.example", "--token-file", "/x/token"},
		{"https://b.example", "-token-file=/x/token"},
	} {
		f := startFlags{port: 8765, timeoutSec: 30, maxMB: 50, rawOrigins: "https://a.example", args: args}
		if _, err := validateFlags(f); err == nil || !strings.Contains(err.Error(), "quote the path") {
			t.Errorf("args %q: %v, want the quoting error", args, err)
		}
	}
	// A value that only mentions it stays a v1.3.0 warning.
	f = startFlags{port: 8765, timeoutSec: 30, maxMB: 50, args: []string{"token-file"}}
	if start, err := validateFlags(f); err != nil || len(start.warnings) != 1 {
		t.Errorf("plain leftover: %v %v", start, err)
	}
}

// TestVersionHandler_ProofBoundToPort is the regression test for review M1:
// a squatter on an old port relays /version?challenge=… to the real proxy on
// its new port. The proof it hands back must not verify for the port the tool
// addressed, and the Host header the relay sends must not change that.
func TestVersionHandler_ProofBoundToPort(t *testing.T) {
	cfg := newTestConfig()
	cfg.sessionToken = "0123456789abcdef0123456789abcdef0123456789abcdef"
	real := httptest.NewServer(versionHandler(cfg))
	defer real.Close()
	_, realPortStr, _ := net.SplitHostPort(real.Listener.Addr().String())
	realPort, _ := strconv.Atoi(realPortStr)

	// The squatter's "port" is a second listener that just relays.
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		req, _ := http.NewRequest(http.MethodGet, real.URL+r.URL.RequestURI(), nil)
		req.Host = r.Host // pretend to be addressed as the squatted port
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}))
	defer relay.Close()
	_, relayPortStr, _ := net.SplitHostPort(relay.Listener.Addr().String())
	relayPort, _ := strconv.Atoi(relayPortStr)

	challenge := strings.Repeat("5c", 32)
	fetch := func(base string) string {
		resp, err := http.Get(base + "/version?challenge=" + challenge)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var v versionResponse
		if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
			t.Fatal(err)
		}
		return v.Proof
	}

	direct := fetch(real.URL)
	if direct != versionProof(cfg.sessionToken, realPort, challenge) {
		t.Errorf("direct proof %s does not use the listening port %d", direct, realPort)
	}
	relayed := fetch(relay.URL)
	// What the tool computes for the address it talked to:
	if relayed == versionProof(cfg.sessionToken, relayPort, challenge) {
		t.Error("relayed proof verifies for the squatted port")
	}
	if relayed != direct {
		t.Errorf("relayed proof %s, want the real proxy's own %s", relayed, direct)
	}
	// cfg.port is only the fallback without a connection address.
	cfg.port = relayPort
	if fetch(real.URL) != direct {
		t.Error("proof follows cfg.port instead of the connection's port")
	}
}

// -----------------------------------------------------------------------
// main() with --token-file and --help (subprocess, like the golden test)
// -----------------------------------------------------------------------

func TestMain_TokenFileAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lp", "token")
	addr1, tok1 := goldenStartMain(t, "-port", "0", "-origin", goldenOrigin, "-dns", "system", "-token-file", path)
	addr2, tok2 := goldenStartMain(t, "-port", "0", "-origin", goldenOrigin, "-dns", "system", "-token-file", path)
	if tok1 != tok2 || !tokenFormat.MatchString(tok1) {
		t.Fatalf("tokens differ across restarts: %q / %q", tok1, tok2)
	}
	data, err := os.ReadFile(path)
	if err != nil || strings.TrimSpace(string(data)) != tok1 {
		t.Fatalf("token file %q, %v", data, err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	for _, addr := range []string{addr1, addr2} {
		resp, err := client.Get("http://" + addr + "/version")
		if err != nil {
			t.Fatal(err)
		}
		var v versionResponse
		err = json.NewDecoder(resp.Body).Decode(&v)
		resp.Body.Close()
		if err != nil || !v.TokenPersistent || v.LocalTargets {
			t.Errorf("%s /version: %+v %v, want tokenPersistent", addr, v, err)
		}
		// The proof matches the token from the file.
		challenge := strings.Repeat("0a", 32)
		resp, err = client.Get("http://" + addr + "/version?challenge=" + challenge)
		if err != nil {
			t.Fatal(err)
		}
		err = json.NewDecoder(resp.Body).Decode(&v)
		resp.Body.Close()
		_, portStr, _ := net.SplitHostPort(addr)
		addrPort, _ := strconv.Atoi(portStr)
		if err != nil || v.Proof != versionProof(tok1, addrPort, challenge) {
			t.Errorf("%s: proof %q does not match the token file", addr, v.Proof)
		}
	}
}

func TestMain_HelpDocumentsNewFlags(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test")
	}
	res := compat13RunMain(t, "--help")
	if res.exitCode != 0 {
		t.Fatalf("--help exit %d:\n%s", res.exitCode, res.output)
	}
	i := strings.Index(res.output, "  -token-file path")
	if i < 0 {
		t.Fatalf("--help has no -token-file:\n%s", res.output)
	}
	help := res.output[i:]
	if j := strings.Index(help[2:], "\n  -"); j >= 0 {
		help = help[:j+2]
	}
	for _, want := range []string{
		"Absolute", `$HOME/.config/localproxy/token`, `$env:LOCALAPPDATA\localproxy\token`,
		`%LOCALAPPDATA%\localproxy\token`, "0600", "Delete the file", "Off by default", "together with --port",
	} {
		if !strings.Contains(help, want) {
			t.Errorf("-token-file help lacks %q: %s", want, help)
		}
	}
	if strings.Contains(help, "(default ") {
		t.Errorf("-token-file shows a default: %s", help)
	}
	if !strings.Contains(res.output, "Any script on an allowed origin that has the token can reach these targets") {
		t.Errorf("-allow-local help lacks the threat sentence:\n%s", res.output)
	}
}

func TestMain_TokenFileStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("subprocess test")
	}
	dir := t.TempDir()
	cases := []struct {
		args     []string
		running  bool
		contains []string
	}{
		{[]string{"--token-file", "token"}, false, []string{"fatal: --token-file needs an absolute path"}},
		{[]string{"--token-file=~/token"}, false, []string{"fatal: --token-file needs an absolute path"}},
		{[]string{"--token-file", ""}, false, []string{"fatal: --token-file needs an absolute path"}},
		{[]string{"--token-file", filepath.Join(dir, "a", "token")}, true, []string{
			"(new, saved to the token file)", "Tokenfile:  " + filepath.Join(dir, "a", "token"),
			"WARNING  :  --port not set — the address changes on every start"}},
		{[]string{"--token-file", filepath.Join(dir, "a", "token")}, true, []string{"(from token file)"}},
	}
	for _, c := range cases {
		res := compat13RunMain(t, c.args...)
		if res.running != c.running {
			t.Errorf("%q: running=%v, want %v:\n%s", c.args, res.running, c.running, res.output)
			continue
		}
		for _, s := range c.contains {
			if !strings.Contains(res.output, s) {
				t.Errorf("%q: output lacks %q:\n%s", c.args, s, res.output)
			}
		}
	}
	// The relative path created nothing in the working directory.
	if _, err := os.Lstat("token"); err == nil {
		t.Error("a relative --token-file created ./token")
	}
}

// isUnix reports whether the Unix file checks apply (tokenfile_unix.go).
func isUnix() bool {
	_, err := os.Stat("/")
	return err == nil && filepath.Separator == '/'
}
