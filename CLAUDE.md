# CLAUDE.md

## Project Overview

**localproxy** is a secure, localhost-only HTTP proxy written in Go. It allows browser-based online tools to fetch external URLs by bypassing CORS restrictions. The proxy binds exclusively to `127.0.0.1` and authenticates requests via a per-session cryptographic token.

This proxy is the **"Expertenmodus"** companion for the **JPKCom Tools** project (`/home/jpk/ddev/jpkcom-tools/`). It does **not** replace the existing PHP-based proxy system (`p.php` + `proxy.php`), but offers an optional, high-performance alternative that users can install locally on their machine.

## Repository

- **GitHub:** https://github.com/JPKCom/proxy-jpkcom-dev-tools
- **Author:** Jean Pierre Kolb ([https://www.jpkc.com/](https://www.jpkc.com/))
- **License:** GPL-2.0-or-later

## Language & Stack

- **Language:** Go (single-file, no external dependencies — stdlib only)
- **Entry point:** `main.go` (contains all logic)
- **Go version:** 1.26 series — `go.mod` declares `go 1.26.5`; CI pin is `go-version: "1.26"` (auto-resolves to latest 1.26.x patch). Release builds since v1.1.0 use 1.26.5+.
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
./localproxy [--port 8765] [--origin https://example.com] [--timeout 30] [--max-mb 50] [--dns "1.1.1.1,8.8.8.8"] [--allow-any-host]
```

## CI/CD

- **GitHub Actions workflow:** `.github/workflows/build.yml`
- Three jobs: `verify` → `build` → `release`
- `verify` runs on **every push to main and every PR**, plus on tags: `gofmt`, `go vet`, `staticcheck`, `govulncheck`, `go test -race`
- `build` only runs on tags / `workflow_dispatch`; cross-compiles for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, freebsd/amd64, freebsd/arm64, openbsd/amd64, netbsd/amd64
- `release` creates a GitHub Release with all binaries via `softprops/action-gh-release@v2`
- `GITHUB_TOKEN` is read-only at workflow level; only `release` gets `contents: write`
- Injects version via `-ldflags "-X main.Version=$TAG"` into `var Version` in `main.go`

## Architecture

Single-file proxy with these components (all in `main.go`):

- **config struct** — runtime configuration (port, allowed origins, session token, timeouts, response cap, DNS resolver, `allowAnyHost`). Methods: `blocksHost` (SSRF pre-check), `tokenValid` (constant-time), `pageBudget` (overall `/page` deadline)
- **authorizeRequest** — shared handler preamble: CORS preflight, origin, method, token, target URL parse, SSRF pre-check. Writes its own error response and returns `(target, false)` when the caller must stop. Used by all three authenticated endpoints
- **localhostOnly** — middleware wrapping the whole mux; rejects requests whose `Host` header is not loopback (DNS-rebinding defense). Bypass via `--allow-any-host`
- **safeDialControl / newUpstreamClient** — `net.Dialer.Control` hook that is the authoritative SSRF boundary; runs post-resolution, pre-connect. The DNS resolver deliberately uses a separate dialer *without* the hook, because `--dns system` may point at a loopback resolver (systemd-resolved on 127.0.0.53)
- **newDecompressor** — `Content-Encoding` decoder; sniffs the zlib header so `deflate` handles both RFC 1950 and RFC 1951. Returns `(nil, nil)` for encodings the stdlib cannot decode (br, zstd) so they pass through verbatim
- **altSvcAdvertisesHTTP3 / splitAltSvcValues** — parses the target's `Alt-Svc` field (RFC 7838) into the `http3` boolean on `/inspect` and `/page`. Only the final ALPN token `h3` (RFC 9114) counts; drafts (`h3-29`, `h3-Q050`) are ignored because current browsers no longer negotiate them. The splitter respects quotes so a comma inside the alt-authority is not mistaken for the separator
- **connTrace** — connection-level metadata capture via `net/http/httptrace` (DNS, TCP, TLS timing, remote IP, TTFB)
- **proxyHandler** — main HTTP handler: validates origin, checks token, parses target URL, forwards request upstream with connection tracing, streams response back with CORS headers and upstream metadata headers (`X-Upstream-Protocol`, `X-Upstream-IP`, `X-Upstream-Timing`, `X-Upstream-Content-Encoding`, `X-Upstream-Content-Length`)
- **inspectHandler** — metadata-only endpoint (`/inspect`): performs upstream request and returns JSON with SSL certificate details, connection timing, resolved IP, HTTP protocol version, response headers, and optionally the body. When `body=1`, sends a HEAD pre-check with the browser's full `Accept-Encoding` to detect the server's true preferred encoding (e.g. zstd, br), then a GET with `Accept-Encoding: gzip, deflate` for the body, decompressed manually via `compress/gzip` / `compress/flate`. The HEAD-detected `Content-Encoding` is restored in the header map for accurate reporting
- **SSL extraction** — `extractSSLInfo` builds structured certificate data from `resp.TLS.PeerCertificates` (subject, issuer, validity, SANs, chain, algorithms, TLS version)
- **JSON error responses** — `proxyError` struct, `writeJSONError`, `classifyUpstreamError` (categorizes DNS, TLS, connection, timeout errors)
- **CORS helpers** — `writeCORSHeaders` (base CORS headers), `isOriginAllowed`. `Access-Control-Expose-Headers` is set dynamically per endpoint: `proxyHandler` enumerates all upstream response headers + `X-Upstream-*` metadata headers (wildcard `*` only works with `Allow-Origin: *`, not with specific origins per Fetch spec)
- **pageHandler** — full page analysis endpoint (`/page`): traces the redirect chain via HEAD requests (`traceRedirectChain`), then fetches the final page via GET with body decompression and HEAD pre-check for true `Content-Encoding`. Returns a single JSON response with redirect chain (per-hop timing, IP, status, headers), HTML body, SSL info, timing, transfer size, and content encoding. Designed as 1:1 replacement for PHP proxy's `handlePageAction`
- **SSRF protection** — two layers. `safeDialControl` in the dialer is the security boundary (immune to DNS rebinding, covers every code path). `isPrivateHost` / `cfg.blocksHost` is a fast-fail pre-check only and is deliberately fail-open on lookup errors
- **Header forwarding** — `copyRequestHeaders` / `copyResponseHeaders` strip hop-by-hop headers, `Connection`-listed headers (RFC 9110 §7.6.1), proxy-internal headers, and — on requests — `sensitiveRequestHeaders` (`Cookie`, `Authorization`, `Origin`, `Referer`, `Sec-Fetch-*`)
- **Endpoints:** `/proxy` (streaming proxy), `/inspect` (metadata + SSL inspection), `/page` (full page analysis with redirect chain), `/ping` (health check, no auth, with CORS for browser access), `/version` (version info as JSON, no auth, with CORS)

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
- TLS verification enabled (no `InsecureSkipVerify`)
- Redirects not followed automatically (`http.ErrUseLastResponse`)
- Response body capped (default 50 MB), applied to the decompressed stream too; truncation drops `Content-Length` and sets `X-Upstream-Truncated: 1`
- Every upstream request derives from the client's request context; `/page` has an overall budget of `3 × --timeout`
- Flags validated at startup (`--port`, `--timeout`, `--max-mb`)

## Error Response Format

When an upstream request fails, the proxy returns a **JSON error response** with CORS headers so browser-based tools can identify the failure type and react accordingly (e.g. show a meaningful message to the user).

**Response structure:**
```json
{
  "error": "dns_error",
  "message": "could not resolve hostname",
  "status": 502
}
```

**Error codes:**

| Code | HTTP Status | Meaning |
|---|---|---|
| `bad_request` | 400 | `url` parameter missing or not a valid http/https URL |
| `forbidden` | 403 | Invalid or missing `X-Proxy-Token` |
| `blocked_target` | 403 | Target resolves to a private or reserved address (pre-check or dialer) |
| `method_not_allowed` | 405 | HTTP method not accepted on this endpoint |
| `dns_error` | 502 | Hostname could not be resolved |
| `tls_error` | 502 | TLS/SSL error (certificate expired, hostname mismatch, unknown CA, etc.) |
| `connection_error` | 502 | TCP connection failed (refused, unreachable, etc.) |
| `upstream_error` | 502 | Any other upstream failure |
| `timeout` | 504 | Upstream request timed out |

**Key implementation details:**
- Classification uses Go's `errors.As` to inspect the error chain (`*net.DNSError`, `*tls.CertificateVerificationError`, `x509.*` errors, `*net.OpError`)
- `errors.Is(err, errBlockedTarget)` is checked **first** — the dialer's block arrives wrapped in a `*net.OpError` and would otherwise be misreported as `connection_error`
- The `message` field is safe for display — it never contains internal error details
- **Ab v1.1.0** tragen auch 4xx-Antworten CORS-Header und einen JSON-Body. Einzige Ausnahme: abgelehnter Origin → Plaintext 403 ohne CORS (bewusst nicht für den abgewiesenen Origin lesbar)
- Full error details are logged server-side via `log.Printf` for debugging in the terminal
- CORS headers are included on error responses so JavaScript can read the JSON body
- Non-upstream errors (bad request, forbidden, method not allowed) remain plain text

## Testing

```bash
go test -v ./...
go test -race ./...    # needs CGO_ENABLED=1 and a C compiler
```

Tests in `main_test.go` cover: token generation and constant-time comparison (`tokenValid`), origin validation, the Host-header check (`isLocalHostname`, `localhostOnly`, `--allow-any-host`), SSRF blocking at both layers — pre-check (`isPrivateHost`, literal IPs without DNS) and dialer (`isBlockedIP` incl. NAT64/6to4/IPv4-mapped, `safeDialControl`, and an end-to-end test proving the dialer blocks loopback even with the pre-check disabled) — request-header filtering (`copyRequestHeaders` strips `Cookie`/`Authorization`/`Origin`/`Referer`/`Sec-Fetch-*` while keeping `Accept`/`User-Agent`/custom `X-*`; `Connection`-listed headers dropped), CORS preflight (including dynamic `Access-Control-Expose-Headers`), CORS + JSON on all 4xx and the deliberate absence of CORS for a rejected origin, `Vary: Origin`, deflate/zlib decompression (`newDecompressor`), response truncation (`Content-Length` dropped + `X-Upstream-Truncated`), successful upstream forwarding with metadata headers, the `/inspect` endpoint (auth, missing URL, with/without body, multi-value `Set-Cookie`), the `/page` endpoint (auth, missing URL, method restriction, no-redirect, 301→200 chain, `formatRawHeaders`, `pageBudget`), SSL extraction (`extractSSLInfo` incl. IP SANs, `tlsVersionName`), connection tracing, `/ping` and `/version`.

## Linting

The project is linted with [staticcheck](https://staticcheck.dev/). CI runs `staticcheck ./...` on linux/amd64 before the release build; any finding blocks the release.

```bash
# One-time install
go install honnef.co/go/tools/cmd/staticcheck@latest

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
mit automatischem Fallback. Bestehender Code bleibt 100% unverändert.

### Two-Proxy-Architektur

| | PHP-Proxy (Standard, immer aktiv) | localproxy (Expertenmodus, opt-in) |
|---|---|---|
| Wo läuft er | Server (DDEV / Production) | User-Rechner (`127.0.0.1:PORT`) |
| Auth | Token V2 (SHA-256) | Per-Session 48-char hex via `X-Proxy-Token` Header |
| Aufruf | `p.php?purl=...&token=...&t=...` | `/proxy`, `/inspect`, `/page` + Header |
| Vorteil | Keine Installation | Keine Server-Last, kein Rate-Limit, größere Responses |

### Frontend-Integration

Die Client-Seite (Fetch-Patterns, localStorage-Layout, Error-Handling, Status-
Tabelle pro Tool) ist im JPKCom-Tools-Repo dokumentiert:

→ **[/home/jpk/ddev/jpkcom-tools/.claude/docs/INTEGRATION.md](file:///home/jpk/ddev/jpkcom-tools/.claude/docs/INTEGRATION.md)**

Stand: SEO + DNS-SSL-Redirect ✅ integriert, Source + WYSIWYG ⏳ noch offen.

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
```

### Wichtige Architektur-Punkte

- **`/page`-Endpoint** verfolgt Redirect-Chains serverseitig und liefert die komplette `redirectChain` mit Timing/IP/Status/Headers pro Hop — 1:1-Ersatz für `p.php?action=page`. Tools, die nur den Body brauchen (Source, WYSIWYG), nutzen weiterhin `/proxy` und lassen den Browser den 3xx selbst auflösen.
- **Header-Format ab v1.0.3:** `/inspect` und `/page` liefern `headers` als `map[string][]string` (Array pro Key). Frontend-Konsumenten brauchen `Array.isArray()`-Guards oder `headers["X"][0]`-Zugriff — siehe INTEGRATION.md.
- **Verhaltensänderungen ab v1.1.0** (alle rückwärtskompatibel, im Tools-Repo war nichts anzupassen): 4xx-Antworten liefern jetzt CORS + JSON statt Plaintext ohne CORS — dadurch unterscheidet das Frontend „falscher Token" von „Proxy läuft nicht"; `Origin`/`Referer` werden nicht mehr an Zielserver weitergereicht (kein Tool verlässt sich darauf, `Accept: text/markdown` aus `seo.js` bleibt unberührt); der Host-Header muss Loopback sein (`127.0.0.0/8`, `localhost`, `[::1]` — deckt alles ab, was User realistisch eintippen).
- **`MIN_VERSION` im Frontend** (`tools/assets/js/tools/localproxy.js`) steht auf `v1.0.1`. Hochziehen, falls die Tools die gehärtete Version erzwingen sollen.
- **localproxy ist stärker als der PHP-Proxy in:** SSRF-Schutz (Dialer-Level nach DNS-Auflösung, immun gegen DNS-Rebinding, statt URL-Prefix-Blocklist), Connection-Timing (`httptrace` für DNS/TCP/TLS/TTFB einzeln), SSL-Cert-Details (`/inspect` liefert Chain/SANs/Algorithms), Concurrent Requests (Goroutine pro Request mit fresh connections), Response-Limit (50 MB statt 950 KB), DNS-Server-Wahl (Default Cloudflare+Google statt System).
- **HTTP/3:** Der Proxy *spricht* kein h3, *erkennt* es aber. `/inspect` und `/page` liefern ab v1.1.0 ein `http3`-Boolean aus dem `Alt-Svc`-Header des Ziels. Das ist keine Notlösung: HTTP/3 wird per Spezifikation über TCP entdeckt (RFC 7838 `Alt-Svc` oder DNS-HTTPS-RR), es gibt also keine Seite, die nur über QUIC erreichbar wäre. Ein QUIC-Transport (`quic-go`) würde dagegen externe Dependencies bringen, `httptrace` außer Kraft setzen (Timing-Aufschlüsselung wäre leer) und `resp.TLS` nicht wie gewohnt füllen (Zertifikatsdetails weg) — bei nahezu null Nutzen, weil `DisableKeepAlives` ohnehin jede Verbindung frisch aufbaut. Ausführlich im README-Abschnitt „HTTP/3 detection".
- **Wichtig für Frontend:** `http3` ≠ `protocol`/`httpVersion`. Ersteres ist die Fähigkeit des Ziels, Letzteres das tatsächlich verwendete Protokoll (bleibt `HTTP/2.0`).
