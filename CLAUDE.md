# CLAUDE.md

## Project Overview

**localproxy** is a secure, localhost-only HTTP proxy written in Go. It allows browser-based online tools to fetch external URLs by bypassing CORS restrictions. The proxy binds exclusively to `127.0.0.1` and authenticates requests via a per-session cryptographic token.

This proxy is the **"Expertenmodus"** companion for the **JPKCom Tools** project (`/home/jpk/ddev/jpkcom-tools/`). It does **not** replace the existing PHP-based proxy system (`p.php` + `proxy.php`), but offers an optional, high-performance alternative that users can install locally on their machine.

## Repository

- **GitHub:** https://github.com/JPKCom/proxy-jpkcom-dev-tools
- **Author:** Jean Pierre Kolb ([https://www.jpkc.com/](https://www.jpkc.com/))
- **License:** GPL-2.0-or-later

## Language & Stack

- **Language:** Go (no external dependencies — stdlib only)
- **Entry point:** `main.go` (contains all logic). Since v1.4.0 two small platform files hold the OS-specific part of `--token-file`: `tokenfile_unix.go` (`//go:build unix`: `O_NOFOLLOW`, owner/mode checks) and `tokenfile_other.go` (`//go:build !unix`, in practice Windows: no permission check, banner warning outside the user profile)
- **Go version:** 1.27 series — `go.mod` declares `go 1.27.3`; CI pin is `go-version: "1.27"` (auto-resolves to latest 1.27.x patch). Release builds since v1.2.4 use 1.27.3+ (security release, `crypto/x509` distrust). Building with 1.27 raises the macOS floor for the darwin binaries to **macOS 13 Ventura**.
- **Module:** `github.com/jpk/localproxy` (`go.mod`)

## Build & Run

```bash
# Build for current platform
go build -o localproxy .

# Cross-compile examples
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o localproxy-linux-amd64 .
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o localproxy-macos-apple-silicon .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o localproxy-windows-amd64.exe .

# Run
./localproxy [--port 8765] [--origin https://example.com] [--timeout 30] [--max-mb 50] [--dns "1.1.1.1,8.8.8.8"] [--allow-any-host] \
             [--allow-local "mysite.ddev.site,localhost:8888"] [--token-file "$HOME/.config/localproxy/token"]
```

All nine release targets locally (what the `build` job does; `-X main.Version=<tag>`):

```bash
for t in linux/amd64/linux-amd64 linux/arm64/linux-arm64 darwin/amd64/macos-intel darwin/arm64/macos-apple-silicon \
         windows/amd64/windows-amd64.exe freebsd/amd64/freebsd-amd64 freebsd/arm64/freebsd-arm64 \
         openbsd/amd64/openbsd-amd64 netbsd/amd64/netbsd-amd64; do
  os=${t%%/*}; r=${t#*/}; arch=${r%%/*}; suf=${r#*/}
  GOOS=$os GOARCH=$arch CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=dev" -trimpath -o dist/localproxy-$suf .
done
(cd dist && sha256sum localproxy-* > SHA256SUMS && sha256sum -c SHA256SUMS)
```

## CI/CD

- **GitHub Actions workflow:** `.github/workflows/build.yml`
- Three jobs: `verify` → `build` → `release`
- `verify` runs on **every push to main and every PR**, plus on tags: `gofmt`, `go vet`, `staticcheck`, `govulncheck`, `go test -race`
- `build` only runs on tags / `workflow_dispatch`; cross-compiles for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, freebsd/amd64, freebsd/arm64, openbsd/amd64, netbsd/amd64
- `release` (since v1.4.0) writes `SHA256SUMS` for the nine binaries (fails unless exactly nine are present, then `sha256sum -c`), takes `.github/release-notes/<tag>.md` as release text when it exists (GitHub's generated notes are appended), and creates a **draft** GitHub Release with all files via `softprops/action-gh-release@v2`. The draft is published by hand after the JPKCom Tools deploy
- `GITHUB_TOKEN` is read-only at workflow level; only `release` gets `contents: write`
- Injects version via `-ldflags "-X main.Version=$TAG"` into `var Version` in `main.go`

## Architecture

Single-file proxy with these components (all in `main.go`):

- **config struct** — runtime configuration (port, allowed origins, session token, `tokenPersistent`, timeouts, response cap, DNS resolver, `allowAnyHost`, `allowLocal` (parsed `--allow-local` entries), plus the test-only hooks `ssrfCheck`, `dialControl`, `rootCAs` and `lookupIP` — `main` never sets them). Methods: `precheck` / `precheckHost` (SSRF pre-check with block reason; replaces the old `blocksHost`), `resolveHost` (the **one** resolution hook: `lookupIP` in tests, else `resolver` — used by the pre-check, `localGuard` and, when `lookupIP` is set, the base dial path), `tokenValid` (constant-time), `pageBudget` (overall `/page` deadline), `dialControlOrDefault` (falls back to `safeDialControl`, so production code can never dial without it), `allowLocalActive` / `allowLocalMatch` / `allowLocalMatchURL` (syntactic list match, no DNS), `localVerdict` / `blockReason` (one decision for pre-check, dialer and TLS probe)
- **authorizeRequest(w, r, cfg, endpoint, methods…)** — shared handler preamble, fixed order: CORS preflight, origin, method, token, target URL parse, `checkTargetAuth` (credential rules; also strips userinfo from the target), `localStart := allowLocalMatchURL(target)`, SSRF pre-check (`blocked_target` + `reason`), then `insecure_scheme` (header credentials over http to a non-listed target). Returns `*authorizedRequest{target, localStart, creds}`; writes its own error response and returns `false` when the caller must stop. Used by all three authenticated endpoints (answers their OPTIONS preflights too). The token is checked before the `url`, so `GET /inspect` with a token and without `url` is the token probe (TOK-1: 400 valid / 403 invalid, nothing contacted)
- **Target credentials (since v1.4.0)** — `checkTargetAuth` (AUTH-2…13: form, `X-Target-Origin`, endpoint, GET/HEAD, override guard, userinfo; `reason` constants `reason*`, messages in `authRefused`), `writesViaOverride` / `phpURLDecode` (rebuilds how PHP fills `$_GET` — splits at `&` and `;`, `.`/space → `_`, `[`, NUL; the value is compared with `asciiUpper` like PHP 8's `strtoupper`, never the Unicode `strings.ToUpper`, which maps `OPTıONS` to `OPTIONS`), `originOf` (scheme + host + effective port). Credentials travel on the request **context** (`withTargetAuth` / `targetAuthFrom`), and `attachTargetAuth` — called last in `doTraced` (after the tweak) and in `probeContentEncoding`, both of which build their request with `newUpstreamRequest` (strips userinfo, picks the header copier) — is the **only** place that sets `Authorization`: only to the credentials' origin and only for a URL that passes the override guard; otherwise it marks `withheld`. With credentials `copyAllowedRequestHeaders` (allowlist) replaces `copyRequestHeaders`. `/proxy` ends a `follow=1` chain before another origin (`withheld-cross-origin`) or a writing override (`withheld-method-override`), sets `X-Upstream-Auth`, `no-store` + `X-Upstream-Cache-Control` (drops `ETag`/`Expires`); `varyTargetAuthWriter` adds `Vary: X-Target-Authorization` to every `/proxy` response. Nothing of the value is ever logged or echoed (LOG-1)
- **Local targets (`--allow-local`, since v1.4.0)** — `parseAllowLocal` / `parseAllowEntry` (syntax, wildcards, dangerous ports, ranges), `validateFlags` (needs `--origin` with strict https origins, not with `--allow-any-host`, leftover positional args fatal). Enforcement: `localGuard` is the transport's `DialContext`; it resolves itself (via `resolveHost`), runs `localVerdict` per IP and dials the IP **literal** through `exactAddressControl` (admits exactly that `ip:port`, everything else goes to `dialControlOrDefault`). Context values: `localStart` (`withLocalStart` / `localStartFrom`; missing = false, fail closed) and `authOverHTTP` (`withAuthOverHTTP`; then only loopback, else `errInsecureAuth` → `auth_refused`/`insecure_scheme`, via `loopbackOnlyControl`). `localSplitTransport` keeps local and public requests in separate pools. **Security dependency:** both context values are only correct because every connection serves exactly one request — `DisableKeepAlives: true` (commented at the line, test `TestAllowLocal_NoConnectionReuse`). `refineBlocked` turns dialer errors into `blockedError{reason}` (`Unwrap() → errBlockedTarget`). Redirect hops: `redirect_into_local` when a non-local start redirects to a listed target. The TLS probe uses the same allowance
- **pingHandler / versionHandler (since v1.4.0 out of `main`)** — `/ping` unchanged. `/version` = `versionResponse` (old five string keys first, then `capabilities`, `localTargets`, `tokenPersistent`, `limits`, optional `proof`). `capabilities` is a package var (the list only grows). `?challenge=<64 hex>` → `proof = hex(HMAC-SHA256(key = token as 48 ASCII chars, "localproxy-proof:" + port + ":" + challenge))` (`versionProof`; `port` = local port of the connection via `http.LocalAddrContextKey`, `cfg.port` only as fallback, never the Host header — stops a relay from a squatted old port) plus `Cache-Control: no-store`; an invalid or repeated challenge is ignored
- **Token file (since v1.4.0)** — `checkTokenFilePath` (absolute, no `%`/`$`/leading `~`), `loadOrCreateToken(path) (token, created, err)`: `MkdirAll(0700)`, `checkTokenDir`, `readTokenFile` (platform `openTokenFile` + `checkTokenFileInfo`, content `^[0-9a-f]{48}$` after `TrimSpace`); missing → temp file `0600` + `Sync` + `os.Link` (EEXIST → read the winner's file), temp file always removed. Flag type `optionalFlag` (knows "given but empty")
- **Flags and banner** — `validateFlags(startFlags) (*startConfig, error)` (all start-up checks, testable), `bannerLines(bannerInfo) []string`. New lines appear only with the new flags (`Local`, `Tokenfile`, `WARNING`), so the v1.3.0 banner is unchanged
- **localhostOnly** — middleware wrapping the whole mux; rejects requests whose `Host` header is not loopback (DNS-rebinding defense). Bypass via `--allow-any-host`
- **safeDialControl / newUpstreamClient** — `net.Dialer.Control` hook that is the authoritative SSRF boundary; runs post-resolution, pre-connect. The DNS resolver deliberately uses a separate dialer *without* the hook, because `--dns system` may point at a loopback resolver (systemd-resolved on 127.0.0.53). The client never follows redirects (`http.ErrUseLastResponse`) and never sets `InsecureSkipVerify` (test-enforced); `rootCAs` replaces the trust store in tests only
- **doTraced / isHeadRefused / probeContentEncoding** — `doTraced` runs one upstream request with a `connTrace` of its own, so timing and IP describe exactly that request. `isHeadRefused` (405/501) triggers the HEAD→GET fallback in `/inspect` and the `/page` tracer (GET body closed unread). `probeContentEncoding` is the **untraced** HEAD with the browser's full `Accept-Encoding` that `/inspect?body=1` and `/page` use to learn the true `Content-Encoding`
- **newDecompressor** — `Content-Encoding` decoder; sniffs the zlib header so `deflate` handles both RFC 1950 and RFC 1951. Returns `(nil, nil)` for everything else (identity, br, zstd, unknown tokens); `readDecodedBody` decides what happens to those bytes
- **readCapped / trimPartialUTF8 / readDecodedBody** — body reading for `/inspect?body=1` and `/page`: cap on the wire bytes and again on the decoded text (reads one byte past the cap to set `truncated`), cut on a UTF-8 boundary. `readDecodedBody` returns a `cappedBody{data, rawSize, truncated, decodeError}`; a corrupt stream gives `decodeError` and only decoded text — never raw compressed bytes. Encoding classes (`contentCodings` splits the field, drops `identity`): single `gzip`/`x-gzip`/`deflate` → decoded; a token in `knownContentCodings` that Go cannot decode (IANA registry: br, zstd, compress, x-compress, dcb, dcz, aes128gcm, exi, pack200-gzip) or any stack of several tokens (`gzip, br`) → empty + `decodeError`; any other token (`none`, `UTF-8`, `text/html`, `binary` — real misconfigured servers) → raw bytes passed through if `utf8.Valid` (v1.2.4 behaviour, cut at the cap via `trimPartialUTF8` first), else empty + `decodeError`
- **lastLocation / resolveRedirect** — the last `Location` value, resolved against the URL that returned it (RFC 3986, `url.ResolveReference`), userinfo dropped, http/https only (`errUnsupportedRedirectScheme` otherwise). Used by all three endpoints
- **altSvcAdvertisesHTTP3 / splitAltSvcValues** — parses the target's `Alt-Svc` field (RFC 7838) into the `http3` boolean on `/inspect` and `/page`. Only the final ALPN token `h3` (RFC 9114) counts; drafts (`h3-29`, `h3-Q050`) are ignored because current browsers no longer negotiate them. The splitter respects quotes so a comma inside the alt-authority is not mistaken for the separator
- **connTrace** — connection-level metadata capture via `net/http/httptrace` (DNS, TCP, TLS timing, remote IP, TTFB from request start). `ConnectDone` only counts a successful connect — with Happy Eyeballs a losing dial's late callback would otherwise overwrite the winner's IP
- **proxyHandler** — main HTTP handler: validates origin, checks token, parses target URL, forwards request upstream with connection tracing, streams response back with CORS headers and upstream metadata headers (`X-Upstream-Protocol`, `X-Upstream-IP`, `X-Upstream-Timing`, `X-Upstream-Content-Encoding`, `X-Upstream-Content-Length`, `X-Upstream-Truncated`). `Location` is never forwarded (it would carry the token to the target); a 3xx gets `X-Upstream-Location` instead. With `follow=1` (GET/HEAD; ignored for POST) it follows up to `maxProxyRedirects` (5) redirects (`isFollowableRedirect`: 301/302/303/307/308), each target SSRF-pre-checked (403 `blocked_target` with `type`), a loop or unusable `Location` returns the 3xx, and adds `X-Upstream-Final-URL` / `X-Upstream-Redirects`. All hops share one `--timeout`
- **inspectHandler** — metadata endpoint (`/inspect`): HEAD (GET fallback on 405/501, `method` says which); `get=1` (without `body=1`) sends a GET right away and closes its body unread — what PHP `fetchUrl(headersOnly)` puts on the wire (cURL `CUSTOMREQUEST GET` + `NOBODY` is a GET, **not** a HEAD); needed for security headers, `www.google.com` sends HSTS only on GET. JSON with the certificate report, timing, IP, protocol, headers, `location` (resolved 3xx target), and with `body=1` the decoded body (`probeContentEncoding` first, then a traced GET with `Accept-Encoding: gzip, deflate`; `truncated`, `maxBodySize`, `decodeError`). The HEAD-detected `Content-Encoding` is restored in the header map. With `diag=1` an upstream failure is HTTP 200 + `error`, and a `tls_error` runs `diagnoseRequestTLS`; without `diag` the 502/504 contract is unchanged (plus `type`)
- **Certificate report** (PHP `proxy.php` 2.8.0 parity) — `buildSSLInfo` assembles `sslInfo` (the original twelve Go-named fields plus `protocol`, `cipher`, `cipherSuite`, `bits`, `verified`/`valid`, `error`/`errorType`, `hostMatch`, `selfSigned`, `issues`, `certSource`, `probeError`). `extractSSLInfo(state, host)` wraps it for a verified connection (empty host → `hostMatch` null). Helpers: `buildCertificateChain` (max. 10, labels, `signatureValid` per link), `describeCertificate` (`chainLink`: DN, orgs, dates, serial, fingerprints, PEM, key), `signatureValid` (pure signature check, MD5 fallback; not `CheckSignatureFrom`), `certMatchesHost` (RFC 6125; nil for empty/non-ASCII host), `certificateIssues` (port of the dns-ssl `certificateIssues()`, plus `ecdsa-with-SHA1` as weak), `formatDN`, `firstAttr`, `describePublicKey`, `colonHex`, `daysUntil` (floor on integer Unix seconds — `time.Duration` would saturate at ~292 years, i.e. for `NotAfter` 9999-12-31), `isSelfIssued`/`isSelfSigned`, `servedChainReachesRoot`, and the OpenSSL name tables `tlsProtocolName`, `openSSLCipherName` (`openSSLCiphers`, test-checked complete), `openSSLSigAlgName`
- **TLS verdict and probe** — `classifyTLSFailure(err, certs, now)` maps a failed connection to the PHP `error.type` text and the OpenSSL verify-result text; the content connection's error is authoritative, `certs` only sub-classify an unknown authority. `Untrusted root certificate in the chain` only when `servedChainReachesRoot` walks from the leaf (subject/issuer match + signature) through the served certificates to a self-signed one — a root the leaf cannot reach (intermediate missing or wrong) is `Incomplete chain or unknown issuer`, like OpenSSL's error 20 vs. 19. `probeTLS` is the **handshake-only** diagnostic connection (`InsecureSkipVerify`, TLS 1.0+, all Go cipher suites incl. insecure ones, no SNI for IPs/non-ASCII hosts, 10 s cap, dialled via `dialControlOrDefault` to the IP the failed request had connected to, no application data). `diagnoseTLSFailure` builds the report from the probe (`certSource: "probe"`) or the `CertificateVerificationError`'s unverified chain (`"verify-error"`), else nil; `diagnoseRequestTLS` gives it a 10 s budget derived from `r.Context()`
- **JSON error responses** — `proxyError` struct (`error`, `message`, `status`, `type`), `writeJSONError` (request-validation 4xx, no `type`), `writeUpstreamError`, `upstreamFailure(ctx, err)` (complete error object: code, message, 502/504, `type`; an expired ctx deadline wins), `classifyUpstreamError` (blocked → timeout → DNS → x509 → TLS → connection → upstream), `isTimeout`, `proxyErrorType` (code → PHP `error.type` text), `leafError`
- **CORS helpers** — `writeCORSHeaders` (base CORS headers), `isOriginAllowed`. `Access-Control-Expose-Headers` is set dynamically per endpoint: `proxyHandler` enumerates the forwarded upstream response headers + the nine `X-Upstream-*` metadata headers, sorted (wildcard `*` only works with `Allow-Origin: *`, not with specific origins per Fetch spec)
- **pageHandler** — full page analysis endpoint (`/page`): traces the redirect chain (`traceRedirectChain`), then fetches the final page via GET with body decompression and HEAD pre-check for true `Content-Encoding`. Returns a single JSON response with redirect chain, HTML body (`readDecodedBody`: `truncated`, `maxBodySize`, `decodeError`), SSL info for the final host, timing, transfer size, and content encoding. On a chain failure the final GET is skipped and `error` carries the hop's real code; with `diag=1` a `tls_error` (chain or final GET) gets `ssl` via `diagnoseRequestTLS`, and `finalUrl` names the failing URL. Designed as 1:1 replacement for PHP proxy's `handlePageAction`
- **traceRedirectChain** — HEAD per hop (GET fallback on 405/501), own per-hop timeout under the `/page` budget, returns `(hops, finalURL, *hopFailure)`. Each hop: `method`, `location`, `rawHeaders` (`rawHeaderBlock` = `statusLine` + sorted `formatRawHeaders`), cert summary (`setHopCert`: first CN only via `firstAttr` — not `Subject.CommonName`, which keeps the last —, `YYYY-MM-DD`, floored days). Every stop sets `errorCategory` (`chainStop` builds the top-level error): `timeout` (budget or per-hop), `redirect_loop`, `too_many_redirects` (stops when `i > maxHops`: 20 redirects followed and the 21st request redirected again; hop 22 is an error hop, never requested), `blocked_target` (pre-check or non-http(s) scheme), `bad_request` (unparseable URL/`Location`), or the transport code; `errorType` only for `tls_error`
- **SSRF protection** — two layers. `safeDialControl` in the dialer is the security boundary (immune to DNS rebinding, covers every code path including the TLS probe; with `--allow-local` `localGuard` sits in front of it). `cfg.precheck` is a fast-fail pre-check only and is deliberately fail-open on lookup errors; it also runs on every redirect target (`/proxy?follow=1`, `/page`), and skips DNS for a listed start URL (the dialer decides per IP)
- **Header forwarding** — `copyRequestHeaders` / `copyResponseHeaders` strip hop-by-hop headers, `Connection`-listed headers (RFC 9110 §7.6.1), proxy-internal headers (`X-Proxy-Token`, `X-Target-Authorization`, `X-Target-Origin`), and — on requests — `sensitiveRequestHeaders` (`Cookie`, `Authorization`, `Origin`, `Referer`, `Sec-Fetch-*`). Names are compared via `normHeader` (lower case, `_` → `-`), so `Sec_Fetch_Site` counts as `Sec-Fetch-Site`. With credentials `copyAllowedRequestHeaders` forwards only `Accept`, `Accept-Language`, `Accept-Encoding`, `User-Agent`, `Cache-Control`, `Pragma`. `forwardsResponseHeader` is the single rule for responses: also drops upstream `access-control-*`, **`Location`** and every **`x-upstream-*`**, also in underscore spelling via `normHeader` (AUTH-14); `X-Target-*`/`X-Proxy-Token` from a target fall under hop-by-hop (difference 6 in the changelog)
- **Endpoints:** `/proxy` (streaming proxy, `follow=1`, target credentials), `/inspect` (metadata + SSL inspection, `body=1`, `get=1`, `diag=1`), `/page` (full page analysis with redirect chain, `diag=1`), `/ping` (health check, no auth, with CORS for browser access), `/version` (version, capabilities, runtime state, `proof`; no auth, with CORS)

## Security Design

- Binds only to `127.0.0.1` (never `0.0.0.0`)
- Host-header check: `127.0.0.0/8`, `localhost` or `[::1]` only — DNS-rebinding defense against the proxy itself; `--allow-any-host` opts out
- Per-session 48-char hex token required via `X-Proxy-Token` header, compared with `crypto/subtle`
- Origin allowlist (configurable via `--origin`)
- Method allowlist: only GET, HEAD, POST allowed on `/proxy` (405 for all others)
- Configurable DNS resolution: defaults to Cloudflare (1.1.1.1) + Google (8.8.8.8); custom servers via `--dns`, system DNS via `--dns system`
- SSRF protection enforced in `net.Dialer.Control` (post-resolution, pre-connect). Blocked ranges: RFC 1918, RFC 6598 CGNAT, RFC 1122, loopback, link-local, IETF/benchmark/documentation space, multicast, reserved, plus IPv4-mapped, NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) IPv6 forms. CIDRs pre-parsed at startup
- Sensitive request headers never reach the target: `Cookie`, `Cookie2`, `Authorization`, `Proxy-Authorization`, `Origin`, `Referer`, `Sec-Fetch-*`
- Structured JSON error responses **with CORS headers** for all failures except a rejected origin (see [Error Response Format](#error-response-format))
- Error details are logged server-side but not leaked to the client
- TLS verification enabled for every connection that carries HTTP data — `newUpstreamClient` never sets `InsecureSkipVerify` (test `TestUpstreamClient_NeverSkipsVerification`). **Single, precise exception:** the handshake-only diagnostic probe `probeTLS`. It runs only with `diag=1` after a classified `tls_error`, dials through `dialControlOrDefault` (= `safeDialControl` in production) to the IP the failed request had already connected to (no second DNS lookup, no rebinding window), is capped at 10 s, writes and reads nothing after the handshake and is never handed to an `http.Transport` (test `TestProbeTLS_NoApplicationData`). The trust verdict (`verified`, `error`, `errorType`) always comes from the verified connection; the probe only supplies chain, protocol and cipher
- The HTTP client never follows redirects itself (`http.ErrUseLastResponse`). `/proxy` never forwards `Location` to the browser — `fetch()` would follow it straight to the target with `X-Proxy-Token` attached — and reports `X-Upstream-Location` instead. Redirects are followed only by the proxy's own loops: `/proxy?follow=1` (max. 5, GET/HEAD) and `/page` (max. 20); every target must be http/https (userinfo dropped) and passes the SSRF pre-check before it is requested
- Response body capped (default 50 MB), applied to the decompressed stream too; truncation drops `Content-Length` and sets `X-Upstream-Truncated: 1`. On `/proxy` that marker works for bodies with `Content-Length` and for compressed chunked bodies (buffered via `readCapped` before `WriteHeader`); a chunked body **without** `Content-Encoding` is streamed and cut silently (known limitation)
- Every upstream request derives from the client's request context; `/page` has an overall budget of `3 × --timeout`
- Flags validated at startup (`--port`, `--timeout`, `--max-mb`, `--allow-local`, `--token-file`); leftover positional arguments are fatal with the new flags, a banner warning without them
- **Target credentials (v1.4.0):** only via `X-Target-Authorization` + `X-Target-Origin`, only `/proxy`, only GET/HEAD, no method override on any hop, only the exact origin (cross-origin redirect ends the chain), only HTTPS except `--allow-local` on a loopback address, header allowlist, `no-store`, never logged. Userinfo in the `url` is implicit Basic credentials and is stripped from every URL. "Read only" = no writing methods and overrides; side effects of GET routes are the tool's business
- **Local targets (v1.4.0):** off by default; names reach loopback only, LAN only through IP/CIDR entries; fixed blocks (metadata, link-local, reserved, own port) always win; needs `--origin` (https), not with `--allow-any-host`; no redirect from a public start into a local target; entries only in the banner, never in a response
- **Token file (v1.4.0):** absolute path; Unix: `O_NOFOLLOW`, regular file of the user, no group/other bits, folder and every folder above it (also link targets) owned by user/root and not group/world-writable (sticky allowed) — ssh `StrictModes`; atomic creation via hard link. `/version` shows only `tokenPersistent`
- **Proof (v1.4.0):** `/version?challenge=` lets a tool verify the proxy holds its token before sending it (port squatting)

## Error Response Format

When an upstream request fails, the proxy returns a **JSON error response** with CORS headers so browser-based tools can identify the failure type and react accordingly (e.g. show a meaningful message to the user).

**Response structure:**
```json
{
  "error": "dns_error",
  "message": "could not resolve hostname",
  "status": 502,
  "type": "Could not resolve host"
}
```

`/proxy` and `/inspect` (without `diag`) send this as the body with HTTP status = `status`. `/inspect?diag=1` and `/page` embed it as the `error` field of an HTTP 200 response (`status` still 502/504).

**Error codes:**

| Code | HTTP Status | Meaning |
|---|---|---|
| `bad_request` | 400 | `url` parameter missing or not a valid http/https URL |
| `forbidden` | 403 | Invalid or missing `X-Proxy-Token` |
| `auth_refused` | 400 | Since v1.4.0: credentials (`X-Target-Authorization` or userinfo) used in a way the proxy refuses; always with `reason`, never with `type` or `X-Upstream-Protocol`; nothing contacted |
| `blocked_target` | 403 / 502 | Target resolves to a private or reserved address. 403 for the pre-check (start URL; a `/proxy?follow=1` hop with `type`); 502 with `type` `Blocked target` when the dialer blocks after DNS resolution (rebinding, or the fail-open pre-check) on `/proxy`/`/inspect` — `upstreamFailure` maps every non-timeout code to 502, unchanged since v1.2.x; on `/page` inline with `status` 502 (also for a non-http(s) redirect scheme) |
| `method_not_allowed` | 405 | HTTP method not accepted on this endpoint |
| `dns_error` | 502 | Hostname could not be resolved |
| `tls_error` | 502 | Any TLS error — certificate (expired, hostname mismatch, unknown CA) or handshake (protocol version, cipher suite, peer alert, non-TLS target) |
| `connection_error` | 502 | TCP connection failed (refused, unreachable, etc.) |
| `upstream_error` | 502 | Any other upstream failure |
| `redirect_loop` | 502 | `/page` only (inline): redirect chain returned to a visited URL |
| `too_many_redirects` | 502 | `/page` only (inline): more than 20 redirects — exactly 20 are fine (Fetch standard), the 21st redirect stops the chain |
| `timeout` | 504 | Upstream request timed out — request deadline, `/page` budget, or a dial/TLS-handshake/response-header timeout of the transport |

`bad_request` also appears inline on `/page` for an unparseable `Location` (`status` 502).

**`reason` (since v1.4.0, `proxyError.Reason`, `omitempty`):** machine-readable sub-code on `auth_refused` (`invalid_value`, `endpoint`, `method`, `method_override`, `userinfo`, `origin_mismatch`, `insecure_scheme`) and `blocked_target` (`private`, `not_allowlisted`, `always_blocked`, `redirect_into_local`, `unsupported_scheme`). JSON paths: top-level `reason` on `/proxy` and every rejection in `authorizeRequest` (`writeJSONErrorReason`); `error.reason` on `/inspect?diag=1` and `/page`; hop field `errorReason` on `/page`. Order of the credential checks: `invalid_value` → `endpoint` → `method` → `method_override` → `userinfo` → `origin_mismatch` → SSRF pre-check → `insecure_scheme` (pre-stage) → `insecure_scheme` at dial time.

**`type` (since v1.3.0):** human-readable class with the PHP proxy's `error.type` texts — `tls_error` → `classifyTLSFailure` (`Certificate expired`, `Certificate not yet valid`, `Host name does not match the certificate`, `Self-signed certificate`, `Untrusted root certificate in the chain`, `Incomplete chain or unknown issuer`, `TLS protocol not supported`, `TLS/SSL error`); `dns_error` → `Could not resolve host`; `connection_error` → `Could not connect to host`; `timeout` → `Connection timeout`; `blocked_target` → `Blocked target`; `redirect_loop` → `Redirect loop detected`; `too_many_redirects` → `Too many redirects`; `bad_request` (`/page` chain) → `Invalid URL`; otherwise `Upstream error`. Set on every upstream failure, every `/page` chain stop and the `/proxy` 403 for a blocked redirect target; **not** on the request-validation 4xx from `authorizeRequest` (`omitempty`).

**Key implementation details:**
- Classification uses Go's `errors.As` to inspect the error chain (`*net.DNSError`, `x509.*` errors, `*tls.CertificateVerificationError`, `tls.RecordHeaderError`, `*net.OpError`)
- `errors.Is(err, errBlockedTarget)` is checked **first** — the dialer's block arrives wrapped in a `*net.OpError` and would otherwise be misreported as `connection_error`
- **Timeout detection second** (`isTimeout`): `errors.Is(err, context.DeadlineExceeded)` or a `net.Error` with `Timeout()` → `timeout`, before DNS (a timed-out lookup counts as timeout, like cURL errno 28). `upstreamFailure(ctx, err)` additionally treats an expired request ctx as timeout whatever shape the transport gave the error, and picks 504. Up to v1.2.4 only an expired request context was recognised; dial timeouts became `connection_error`, TLS-handshake and response-header timeouts `upstream_error` (502)
- **x509 before the wrapper:** `x509.UnknownAuthorityError` / `CertificateInvalidError` / `HostnameError` are tested **before** `*tls.CertificateVerificationError` — crypto/tls wraps them in it, so the old order made their messages unreachable (up to v1.2.4 every certificate rejection read "TLS certificate verification failed")
- **https:// to a plain-HTTP server:** `http.Client` reports it as `http.ErrSchemeMismatch`, not `tls.RecordHeaderError` → both map to `tls_error` / `TLS protocol not supported` (up to v1.2.4 wrongly `upstream_error`)
- **Non-certificate TLS failures** need two extra steps, because `errors.As` alone cannot see them:
  - `crypto/tls` reports peer alerts (protocol version, cipher suite, `certificate_required`, …) as a `*net.OpError` with `Op` `"remote error"` / `"local error"` wrapping the **unexported** `tls.alert` type. `tls.AlertError` does *not* match these — the `Op` field is the only usable marker. Without the check they fall into `connection_error`
  - Failures the client rejects locally are bare `fmt.Errorf` values with no type at all (261 of them in Go 1.27), e.g. `tls: server selected unsupported protocol version 301` from a TLS-1.0-only server. The only marker is the package-wide `tls: ` message prefix, read via `leafError` off the **innermost** error — never off the flattened chain, since the wrapping `*url.Error` carries the caller-supplied URL and a query string could otherwise forge the verdict
- The `message` field is safe for display — it never contains internal error details
- **Ab v1.1.0** tragen auch 4xx-Antworten CORS-Header und einen JSON-Body. Einzige Ausnahme: abgelehnter Origin → Plaintext 403 ohne CORS (bewusst nicht für den abgewiesenen Origin lesbar)
- Full error details are logged server-side via `log.Printf` for debugging in the terminal
- CORS headers are included on error responses so JavaScript can read the JSON body
- Request-validation errors (bad request, forbidden, method not allowed, blocked URL) are JSON with CORS too (since v1.1.0), but carry no `type`

## Testing

```bash
go test -v ./...
go test -race ./...    # needs CGO_ENABLED=1 and a C compiler
```

Tests in `main_test.go` cover: token generation and constant-time comparison (`tokenValid`), origin validation, the Host-header check (`isLocalHostname`, `localhostOnly`, `--allow-any-host`), SSRF blocking at both layers — pre-check (`isPrivateHost`, literal IPs without DNS) and dialer (`isBlockedIP` incl. NAT64/6to4/IPv4-mapped, `safeDialControl`, and an end-to-end test proving the dialer blocks loopback even with the pre-check disabled) — request-header filtering (`copyRequestHeaders` strips `Cookie`/`Authorization`/`Origin`/`Referer`/`Sec-Fetch-*` while keeping `Accept`/`User-Agent`/custom `X-*`; `Connection`-listed headers dropped), CORS preflight (including dynamic `Access-Control-Expose-Headers`), CORS + JSON on all 4xx and the deliberate absence of CORS for a rejected origin, `Vary: Origin`, deflate/zlib decompression (`newDecompressor`), response truncation (`Content-Length` dropped + `X-Upstream-Truncated`), successful upstream forwarding with metadata headers, the `/inspect` endpoint (auth, missing URL, with/without body, multi-value `Set-Cookie`), the `/page` endpoint (auth, missing URL, method restriction, no-redirect, 301→200 chain, `formatRawHeaders`, `pageBudget`), SSL extraction (`extractSSLInfo` incl. IP SANs, `tlsVersionName`), error classification (`classifyUpstreamError`: DNS, certificate errors, and — against **real** failing handshakes via `httptest` — peer alerts, protocol-version and cipher-suite mismatches, a non-TLS target, plus guards that genuine socket errors stay `connection_error` and that a `tls: ` substring in the URL cannot forge a TLS verdict), connection tracing, `/ping` and `/version`.

**Since v1.3.0** (no network needed; real `httptest` TLS servers against a test PKI):

- **Test helpers:** `certOpts` / `newCert` / `testKey` (rsa2048, rsa1024, p256, p384, ed25519; cached per slot), `newTestPKI` (root + intermediate, `leaf()` for localhost/127.0.0.1), `tlsServerWith` (serves exactly the given chain), `allowAllDial`, `testCfg` (SSRF pre-check off, `dialControl = allowAllDial`, `rootCAs` = test pool), `doInspect` / `decodeInspect`, `doPage` / `decodePage`, `closedPortURL`, `doProxy`, `exposed`, an MD5-signed PEM fixture (Go can no longer create MD5 certificates)
- **Certificate report (pure):** `TestTLSProtocolName`, `TestOpenSSLCipherName` (table covers every `tls.CipherSuites()` + `InsecureCipherSuites()` ID), `TestOpenSSLSigAlgName`, `TestFormatDN`, `TestDaysUntil` (floor, 9999-12-31 without `time.Duration` saturation), `TestSetHopCert_FirstCN`, `TestDescribeCertificate`, `TestBuildCertificateChain` (labels, signature checks, cross-signed root, wrong order, self-signed leaf, 10-cert cap), `TestSignatureValid_LegacyAlgorithms` (SHA-1, MD5 fallback, tampered), `TestCertMatchesHost`, `TestCertificateIssues`
- **Classification:** `TestClassifyUpstreamError_Timeout`, `TestClassifyUpstreamError_UnwrapsCertificateVerificationError`, `TestUpstreamFailure`, `TestClassifyTLSFailure_RealHandshakes` (expired, not yet valid, hostname, self-signed, untrusted root (also out of order), incomplete chain, root sent but intermediate missing or wrong → incomplete chain, TLS 1.0-only server, plain HTTP — each from a real handshake), `TestConnTrace_IgnoresFailedConnect`
- **Probe & client:** `TestProbeTLS_NoApplicationData`, `TestProbeTLS_SNI`, `TestProbeTLS_DefaultDialControlBlocksLoopback`, `TestProbeTLS_LegacyCiphers` (TLS 1.0 RSA-kex, TLS 1.1 3DES, TLS 1.2 RC4), `TestUpstreamClient_NeverSkipsVerification`
- **`/inspect`:** `TestInspect_TLSFailure_NoDiag_ContractUnchanged`, `TestInspect_TLSFailure_Diag`, `TestInspect_Diag_ProbeFails_FallsBackToVerifyError`, `TestInspect_Diag_LegacyTLS10Server`, `TestInspect_Diag_NonTLSFailure`, `TestInspect_Timeout`, `TestInspect_Success_NewFields` (all old keys still present), `TestInspect_HeadFallback` (405/501/404), `TestInspect_HeadersViaGET` (`get=1`: one GET, no HEAD, body unread; without `get=1` HEAD; `body=1` wins), `TestInspect_Location`, `TestInspect_BodyTruncated`, `TestInspect_BodyUndecodableEncoding`, `TestInspect_BodyTimingIsTheGET`
- **`/page`:** `TestPage_ChainHeadFallback`, `TestPage_TLSFailure` (with/without diag), `TestPage_TooManyRedirects` (21st redirect stops), `TestPage_TwentyRedirectsSucceed`, `TestPage_ChainStopCategories` (loop, blocked, `javascript:`, connection refused, hop timeout), `TestPage_FinalGETTimeout`, `TestPage_Truncated` (multi-byte char at the cap), `TestPage_CorruptGzipNeverRaw` (corrupt gzip, br, valid gzip), `TestPage_UnknownContentEncoding` (`none`/`UTF-8` plain HTML passes, br and binary behind `x-custom` → empty + `decodeError`, `/inspect` too), `TestPage_HopCertSummary`, `TestPage_RawHeadersStatusLine`, `TestStatusLine`, `TestFormatRawHeaders_SortedAndKeepsValueOrder`
- **`/proxy`:** `TestProxy_LocationNotForwarded` (relative `../x`, two Location values, Location on 201), `TestProxy_Follow` (relative 301, no redirect, HEAD, blocked hop, loop, >5 hops, `javascript:`, POST), `TestProxy_FollowDialerBlock` (pre-check passes, dialer blocks the hop → 502 `blocked_target` with `type`), `TestProxy_TruncatedCompressedChunked` (gzip, chunked: over/under/exactly the cap)
- **Helpers:** `TestResolveRedirect` (all RFC 3986 §5.4.1/§5.4.2 examples, userinfo, schemes), `TestReadCapped`, `TestTrimPartialUTF8`, `TestReadDecodedBody` (incl. unknown tokens with UTF-8/binary bodies, every undecodable registered coding, stacked codings, `identity` spellings)

Not covered: the `diag` path for a `tls_error` that only hits the final `/page` GET (HEAD succeeds, GET fails TLS — hard to stage with `httptest`); the chain-failure path is tested.

**Since v1.4.0** (test files next to `main_test.go`):

- **`compat_golden_test.go` — `TestCompat_Golden`:** fixed request matrix (call patterns of the 7 tools, error paths, preflights, size limit, underscore headers, method overrides without credentials, `main()` with `--origin` and with **no flags at all**) against `httptest` targets; every response compared byte for byte with `testdata/golden/*.golden` (only `Date`, timings, `daysLeft` and ports normalised). The files were recorded on **v1.3.0 code** (commit `92f51d6`; later cases by copying the harness into an export of that commit and running `-update` there). Only the differences of spec section 4.1 may appear. `-update` only on purpose, review every diff line, golden changes in a commit of their own
- **`compat_v13_test.go`:** v1.3.0 behaviour of flags, help, banner and start-up (subprocess via `compat13RunMain`)
- **`target_auth_test.go`:** AUTH-1…14 and LOG-1 (incl. redirect host/port/scheme changes, underscore and case variants, CR/LF/NUL, `_method` in query/hop/header/body, encoded and empty userinfo, nothing in logs/headers/bodies)
- **`local_attack_test.go`** + LOCAL tests in `main_test.go`: `--allow-local` parser, matching, rebinding, fixed blocks, own port, redirects into local, all endpoints, `reason`, no connection reuse
- **`cap_tok_test.go`:** `TestPingHandler`, `TestVersionHandler_Capabilities`, `TestVersionHandler_Proof` (openssl-computed vectors with port, invalid challenges, full stack), `TestVersionHandler_ProofBoundToPort` (relay from another port does not verify), `TestTokenProbe_Contract` (no pre-check/DNS/dial), `TestTokenFile_*` (relative paths, create/reuse, content, 20 rounds of 8 concurrent starts), `TestBanner_TokenFileLines`, subprocess tests for `--token-file` across restarts and `--help`
- **`tokenfile_unix_test.go`** (`//go:build unix`): file and folder permissions, whole folder chain incl. link targets (`TestTokenFile_FolderChain`), sticky folder, symlinks (also dangling), FIFO
- **`workflow_test.go`:** the release workflow has no `${{ … }}` inside `run:` scripts (tag names → `env:`) and every checkout uses `persist-credentials: false`

## Linting

The project is linted with [staticcheck](https://staticcheck.dev/). CI runs `staticcheck ./...` on linux/amd64 before the release build; any finding blocks the release.

```bash
# One-time install — NOT a plain `go install ...@v0.8.1`: Go 1.27.2 writes
# export data version 5, staticcheck v0.8.1 pins golang.org/x/tools v0.44,
# which only reads up to version 4. Build it in a throwaway module with
# x/tools v0.51.0 (same recipe as CI):
d=$(mktemp -d) && cd "$d" && go mod init staticcheck-build \
  && go get honnef.co/go/tools/cmd/staticcheck@v0.8.1 golang.org/x/tools@v0.51.0 \
  && go install honnef.co/go/tools/cmd/staticcheck && cd - && rm -rf "$d"

# Run locally (requires $(go env GOPATH)/bin in $PATH)
staticcheck ./...
```

`staticcheck` is a dev tool only — it is not added to `go.mod` and never ships with the binary. The stdlib-only rule applies to runtime dependencies, not to build/lint tooling.

## Conventions

- Documentation language: English (README.md, code comments, identifiers)
- Integration documentation: German (CLAUDE.md, JPKCom Tools section)
- stdlib only — no external dependencies

---

## Integration with JPKCom Tools

`localproxy` ist der **optionale Expertenmodus** für die JPKCom Tools — kein
Ersatz für den bestehenden PHP-Proxy (`p.php`), sondern ein additiver Pfad
mit automatischem Fallback. Die PHP-Seite bleibt unverändert — einzige Ausnahme
seit v1.3.0 ist der kleine CAA-Modus `p.php?caa=on` im DNS-SSL-Tool, weil die
CAA-Abfrage (DNS) auch im Expertenmodus beim Server bleibt.

### Two-Proxy-Architektur

| | PHP-Proxy (Standard, immer aktiv) | localproxy (Expertenmodus, opt-in) |
|---|---|---|
| Wo läuft er | Server (DDEV / Production) | User-Rechner (`127.0.0.1:PORT`) |
| Auth | Token V2 (SHA-256) | Per-Session 48-char hex via `X-Proxy-Token` Header |
| Aufruf | `p.php?purl=...&token=...&t=...` | `/proxy`, `/inspect`, `/page` + Header |
| Vorteil | Keine Installation | Keine Server-Last, kein Rate-Limit, größere Responses |
| Redirects | serverseitig (`fetchUrl` max. 5, Redirect-Tracer max. 10) | `/proxy?follow=1` max. 5 (GET/HEAD), `/page` max. 20, `/inspect` liefert `location` |
| Zertifikat bei TLS-Fehler | Volle Details (cURL/OpenSSL) | Ab v1.3.0 mit `diag=1` (handshake-only Probe), sonst nur Fehler |
| Nur-Header-Abfrage | `fetchUrl(headersOnly)` = cURL `CUSTOMREQUEST GET` + `NOBODY` → auf der Leitung ein **GET** (Body ungelesen); nur `fetchProxyHeaders('HEAD')` (Redirect-Tracer) ist ein echter HEAD | `/inspect` ohne Parameter = HEAD (GET bei 405/501); ab v1.3.0 `get=1` = GET mit ungelesenem Body wie PHP. `/page`-Hops = HEAD wie `fetchProxyHeaders` |

### Frontend-Integration

Die Client-Seite (Fetch-Patterns, localStorage-Layout, Error-Handling, Status-
Tabelle pro Tool) ist im JPKCom-Tools-Repo dokumentiert:

→ **[/home/jpk/ddev/jpkcom-tools/.claude/docs/INTEGRATION.md](file:///home/jpk/ddev/jpkcom-tools/.claude/docs/INTEGRATION.md)**

Stand v1.3.0: SEO, DNS-SSL-Redirect, Source (Load-Button; der Header-Report
bleibt auf PHP), WYSIWYG, MD, llms und robots-sitemap ✅ integriert — alle mit
`follow=1` bzw. `headCheck` für Redirects und mit Feature-Detection. Mit
älteren Proxys laufen sie wie bisher; Redirects zu anderen Sites folgen sie
aber erst ab v1.3.0 (mit älteren Proxys scheitern diese wie zuvor am
CORS-Preflight → „Failed to fetch“).

Ab v1.4.0 kommt ein achtes Tool dazu: der **WP REST API Explorer** (`wp-api`).
Er läuft **nur** über den lokalen Proxy (kein PHP-Pfad). Zugangsdaten
(`X-Target-Authorization` + `X-Target-Origin`) und lokale Ziele
(`--allow-local`) gibt es erst ab v1.4.0; er erkennt sie an `capabilities` in
`/version` und prüft vorher `proof`. Mit v1.3.0 oder einem `dev`-Build ohne
`capabilities` läuft er nur im Grundumfang (öffentliche Seiten). Die 7 anderen
Tools brauchen v1.4.0 nicht; `MIN_VERSION` bleibt `v1.3.0`. Anforderungen:
`/home/jpk/ddev/jpkcom-tools/.claude/knowledge/projects/localproxy-v1.4.0.md`.
Release nur gemeinsam mit dem Explorer: Tag bauen, Entwurf prüfen, erst
`jpkcom-tools` deployen, dann den Entwurf veröffentlichen.

### Empfohlene Startup-Konfiguration

User startet `localproxy` mit dem Origin der jeweiligen Umgebung:

```bash
# Produktion
./localproxy --origin https://www.jpkc.com --port 8765

# DDEV Entwicklung
./localproxy --origin https://jpkcom-tools.ddev.site --port 8765

# Beide Origins zugleich (Empfehlung für Entwickler)
./localproxy --origin "https://www.jpkc.com,https://jpkcom-tools.ddev.site" --port 8765

# Mit eigenem DNS-Server (z.B. Quad9)
./localproxy --origin https://www.jpkc.com --dns "9.9.9.9,1.1.1.1"

# System-DNS verwenden statt Cloudflare/Google
./localproxy --origin https://www.jpkc.com --dns system

# Ab v1.4.0: lokales DDEV-Projekt für den WP REST API Explorer freigeben
# (genau die Seite; "*.ddev.site" gibt JEDES lokale DDEV-Projekt frei)
./localproxy --origin "https://www.jpkc.com" --port 8765 --allow-local "mysite.ddev.site"

# Ab v1.4.0: Token übersteht Neustarts (immer mit --port, absoluter Pfad)
./localproxy --origin "https://www.jpkc.com" --port 8765 --token-file "$HOME/.config/localproxy/token"

# Lab des Explorers (WSL, DDEV-Origin der Tools)
./localproxy --origin https://jpkcom-tools.ddev.site --port 18765 \
  --allow-local "*.ddev.site" --token-file /home/jpk/tmp/wp-api-explorer/proxy.token
```

Werte immer quoten (bash/zsh globben `*` und `[…]`, PowerShell zerlegt Kommalisten).

### Wichtige Architektur-Punkte

- **`/page`-Endpoint** verfolgt Redirect-Chains serverseitig und liefert die komplette `redirectChain` mit Timing/IP/Status/Headers pro Hop (ab v1.3.0 zusätzlich `method`, `location`, `errorCategory`, `errorType`, `certCN`/`certExpiry`/`certDaysLeft`, `rawHeaders` mit Statuszeile) — 1:1-Ersatz für `p.php?action=page`. Tools, die nur den Body brauchen (Source, WYSIWYG, MD, llms, robots-sitemap, SEO-Nebenabrufe), nutzen `/proxy?follow=1`: der **Proxy** folgt den Redirects (max. 5) und meldet `X-Upstream-Final-URL` / `X-Upstream-Redirects`. Den Browser den 3xx selbst auflösen zu lassen klappte nur bei CORS-offenen Zielen (sonst CORS-Fehler bzw. proxy-lokaler 404) und trug dabei den `X-Proxy-Token` ans Ziel — deshalb leitet `/proxy` ab v1.3.0 `Location` nicht mehr weiter, sondern liefert `X-Upstream-Location`. Link-Checks laufen über `LocalProxy.headCheck()` (auf `/inspect`, Client-Schleife über `data.location`, max. 5).
- **Header-Format ab v1.0.3:** `/inspect` und `/page` liefern `headers` als `map[string][]string` (Array pro Key). Frontend-Konsumenten brauchen `Array.isArray()`-Guards oder `headers["X"][0]`-Zugriff — siehe INTEGRATION.md.
- **Verhaltensänderungen ab v1.1.0** (alle rückwärtskompatibel, im Tools-Repo war nichts anzupassen): 4xx-Antworten liefern jetzt CORS + JSON statt Plaintext ohne CORS — dadurch unterscheidet das Frontend „falscher Token" von „Proxy läuft nicht"; `Origin`/`Referer` werden nicht mehr an Zielserver weitergereicht (kein Tool verlässt sich darauf, `Accept: text/markdown` aus `seo.js` bleibt unberührt); der Host-Header muss Loopback sein (`127.0.0.0/8`, `localhost`, `[::1]` — deckt alles ab, was User realistisch eintippen).
- **`MIN_VERSION` im Frontend** (`tools/assets/js/tools/localproxy.js`) steht auf **`v1.3.0`** (bleibt so mit v1.4.0; der Explorer prüft `capabilities` statt der Version). Rein beratend: `isEnabled()` ignoriert die Version, ein älterer Proxy funktioniert weiter (Badge + „outdated"-Toast höchstens einmal pro Browser-Session und Version). `localproxy.js` wird im Footer mit `?v=<filemtime>` geladen; neue API-Funktionen (`headCheck`, `readUpstreamMeta`, `buildProxyError`) nutzen die Tools nur hinter `typeof LocalProxy.x === 'function'`.
- **Release-Reihenfolge ab v1.3.0: erst die Tools deployen, dann localproxy v1.3.0 veröffentlichen.** Das neue JS läuft auch mit alten Proxys (unbekannte Query-Parameter wie `diag`/`follow` werden ignoriert, neue Felder feature-detected). Umgekehrt verliert altes Produktions-JS mit dem neuen Proxy die Fälle, in denen der Browser `Location` direkt zu einem CORS-offenen Ziel folgte — es bekäme einen nackten 3xx.
- **PHP-Parität ab v1.3.0 (`proxy.php` 2.8.0):** `/inspect` und `/page` liefern `ssl` mit voller Chain (Label, `signatureValid`, DN, Orgs, Serial, OpenSSL-Signaturname, Key, SANs, SHA-256/SHA-1, PEM), `protocol`/`cipher` in OpenSSL-Notation, `cipherSuite` (IANA), `bits`, `verified`/`valid`, `error` (OpenSSL-Verify-Text, Feld für SEO) / `errorType` (Feld für DNS-SSL), `hostMatch`, `selfSigned`, `issues`, `certSource`. Fehler-JSON trägt `type` mit den PHP-Texten. `daysLeft` wird gefloort (wie DNS-SSL und die Lib; das SEO-PHP rundet — keine SEO-Parität behaupten).
- **`diag=1` (opt-in, `/inspect` + `/page`):** Upstream-Fehler kommen inline (HTTP 200 + `error`), bei `tls_error` füllt die handshake-only Probe `ssl` mit `valid:false`. Bewusst opt-in: altes `seo.js` rechnet `valid = daysLeft > 0` und würde ein kaputtes Zertifikat sonst als gültig anzeigen; altes DNS-SSL-JS wirft bei `!resp.ok`. Ohne `diag` bleibt der 502/504-Vertrag (plus `type`).
- **IDN:** Go hat ohne externe Pakete kein IDNA. Die Tools normalisieren URLs vor `/inspect` und `/page` mit `new URL(u).href` (Punycode); für einen Nicht-ASCII-Host liefert der Proxy `hostMatch: null` und die Probe sendet kein SNI.
- **localproxy ist stärker als der PHP-Proxy in:** SSRF-Schutz (Dialer-Level nach DNS-Auflösung, immun gegen DNS-Rebinding, statt URL-Prefix-Blocklist; gilt auch für jeden Redirect-Hop und die TLS-Probe), Connection-Timing (`httptrace` für DNS/TCP/TLS/TTFB einzeln), SSL-Cert-Details (ab v1.3.0 inhaltlich gleichauf mit PHP; Hostname-Match auch für IP-SANs semantisch, `ecdsa-with-SHA1` wird als schwach erkannt), Concurrent Requests (Goroutine pro Request mit fresh connections), Response-Limit (50 MB statt 950 KB), DNS-Server-Wahl (Default Cloudflare+Google statt System).
- **HTTP/3:** Der Proxy *spricht* kein h3, *erkennt* es aber. `/inspect` und `/page` liefern ab v1.1.0 ein `http3`-Boolean aus dem `Alt-Svc`-Header des Ziels. Das ist keine Notlösung: HTTP/3 wird per Spezifikation über TCP entdeckt (RFC 7838 `Alt-Svc` oder DNS-HTTPS-RR), es gibt also keine Seite, die nur über QUIC erreichbar wäre. Ein QUIC-Transport (`quic-go`) würde dagegen externe Dependencies bringen, `httptrace` außer Kraft setzen (Timing-Aufschlüsselung wäre leer) und `resp.TLS` nicht wie gewohnt füllen (Zertifikatsdetails weg) — bei nahezu null Nutzen, weil `DisableKeepAlives` ohnehin jede Verbindung frisch aufbaut. Ausführlich im README-Abschnitt „HTTP/3 detection".
- **Wichtig für Frontend:** `http3` ≠ `protocol`/`httpVersion`. Ersteres ist die Fähigkeit des Ziels, Letzteres das tatsächlich verwendete Protokoll (bleibt `HTTP/2.0`).
