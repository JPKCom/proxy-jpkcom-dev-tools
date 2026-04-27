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
- **Go version:** 1.26 series — `go.mod` declares `go 1.26.0`; CI pin is `go-version: "1.26"` (auto-resolves to latest 1.26.x patch). Release builds since v1.0.2 use 1.26.2+.
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
./localproxy [--port 8765] [--origin https://example.com] [--timeout 30] [--max-mb 50] [--dns "1.1.1.1,8.8.8.8"]
```

## CI/CD

- **GitHub Actions workflow:** `.github/workflows/build.yml`
- Triggers on version tags (`v*`) and `workflow_dispatch`
- Cross-compiles for: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, freebsd/amd64, freebsd/arm64, openbsd/amd64, netbsd/amd64
- Creates a GitHub Release with all binaries via `softprops/action-gh-release@v2`
- Injects version via `-ldflags "-X main.Version=$TAG"` into `var Version` in `main.go`

## Architecture

Single-file proxy with these components (all in `main.go`):

- **config struct** — runtime configuration (port, allowed origins, session token, timeouts, response cap, DNS resolver)
- **connTrace** — connection-level metadata capture via `net/http/httptrace` (DNS, TCP, TLS timing, remote IP, TTFB)
- **proxyHandler** — main HTTP handler: validates origin, checks token, parses target URL, forwards request upstream with connection tracing, streams response back with CORS headers and upstream metadata headers (`X-Upstream-Protocol`, `X-Upstream-IP`, `X-Upstream-Timing`, `X-Upstream-Content-Encoding`, `X-Upstream-Content-Length`)
- **inspectHandler** — metadata-only endpoint (`/inspect`): performs upstream request and returns JSON with SSL certificate details, connection timing, resolved IP, HTTP protocol version, response headers, and optionally the body. When `body=1`, sends a HEAD pre-check with the browser's full `Accept-Encoding` to detect the server's true preferred encoding (e.g. zstd, br), then a GET with `Accept-Encoding: gzip, deflate` for the body, decompressed manually via `compress/gzip` / `compress/flate`. The HEAD-detected `Content-Encoding` is restored in the header map for accurate reporting
- **SSL extraction** — `extractSSLInfo` builds structured certificate data from `resp.TLS.PeerCertificates` (subject, issuer, validity, SANs, chain, algorithms, TLS version)
- **JSON error responses** — `proxyError` struct, `writeJSONError`, `classifyUpstreamError` (categorizes DNS, TLS, connection, timeout errors)
- **CORS helpers** — `writeCORSHeaders` (base CORS headers), `isOriginAllowed`. `Access-Control-Expose-Headers` is set dynamically per endpoint: `proxyHandler` enumerates all upstream response headers + `X-Upstream-*` metadata headers (wildcard `*` only works with `Allow-Origin: *`, not with specific origins per Fetch spec)
- **pageHandler** — full page analysis endpoint (`/page`): traces the redirect chain via HEAD requests (`traceRedirectChain`), then fetches the final page via GET with body decompression and HEAD pre-check for true `Content-Encoding`. Returns a single JSON response with redirect chain (per-hop timing, IP, status, headers), HTML body, SSL info, timing, transfer size, and content encoding. Designed as 1:1 replacement for PHP proxy's `handlePageAction`
- **SSRF protection** — `isPrivateHost` blocks requests to private/loopback IP ranges; also checked on each redirect target in `traceRedirectChain`
- **Header forwarding** — `copyRequestHeaders` / `copyResponseHeaders` strip hop-by-hop and proxy-internal headers
- **Endpoints:** `/proxy` (streaming proxy), `/inspect` (metadata + SSL inspection), `/page` (full page analysis with redirect chain), `/ping` (health check, no auth, with CORS for browser access), `/version` (version info as JSON, no auth, with CORS)

## Security Design

- Binds only to `127.0.0.1` (never `0.0.0.0`)
- Per-session 48-char hex token required via `X-Proxy-Token` header
- Origin allowlist (configurable via `--origin`)
- Method allowlist: only GET, HEAD, POST allowed on `/proxy` (405 for all others)
- Configurable DNS resolution: defaults to Cloudflare (1.1.1.1) + Google (8.8.8.8); custom servers via `--dns`, system DNS via `--dns system`
- SSRF protection: target hostname DNS resolution checked against RFC 1918, RFC 6598 (CGNAT), RFC 1122 ("this network"), and loopback ranges (CIDR blocks pre-parsed at startup); uses the configured DNS resolver
- Structured JSON error responses for upstream failures (see [Error Response Format](#error-response-format))
- Error details are logged server-side but not leaked to the client
- TLS verification enabled (no `InsecureSkipVerify`)
- Redirects not followed automatically (`http.ErrUseLastResponse`)
- Response body capped (default 50 MB)

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
| `timeout` | 504 | Upstream request timed out |
| `dns_error` | 502 | Hostname could not be resolved |
| `tls_error` | 502 | TLS/SSL error (certificate expired, hostname mismatch, unknown CA, etc.) |
| `connection_error` | 502 | TCP connection failed (refused, unreachable, etc.) |
| `upstream_error` | 502 | Any other upstream failure |

**Key implementation details:**
- Classification uses Go's `errors.As` to inspect the error chain (`*net.DNSError`, `*tls.CertificateVerificationError`, `x509.*` errors, `*net.OpError`)
- The `message` field is safe for display — it never contains internal error details
- Full error details are logged server-side via `log.Printf` for debugging in the terminal
- CORS headers are included on error responses so JavaScript can read the JSON body
- Non-upstream errors (bad request, forbidden, method not allowed) remain plain text

## Testing

```bash
go test -v ./...
```

Tests in `main_test.go` cover: token generation, origin validation, SSRF blocking, CORS preflight (including dynamic `Access-Control-Expose-Headers`), handler error paths (missing token, wrong origin, missing/invalid URL), successful upstream forwarding with metadata headers (`X-Upstream-Protocol`, `X-Upstream-Timing`, `X-Upstream-Content-Encoding`, `X-Upstream-Content-Length`), the `/inspect` endpoint (auth, missing URL, successful with/without body), the `/page` endpoint (auth, missing URL, method restriction, successful no-redirect, redirect chain with 301→200, `formatRawHeaders`), SSL extraction (`extractSSLInfo`, `tlsVersionName`), connection tracing (`connTrace` timing header, remote IP), the `/ping` endpoint, and the `/version` endpoint (JSON response, CORS preflight).

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
- **localproxy ist stärker als der PHP-Proxy in:** SSRF-Schutz (DNS-basiert + CIDR statt URL-Prefix), Connection-Timing (`httptrace` für DNS/TCP/TLS/TTFB einzeln), SSL-Cert-Details (`/inspect` liefert Chain/SANs/Algorithms), Concurrent Requests (Goroutine pro Request mit fresh connections), Response-Limit (50 MB statt 950 KB), DNS-Server-Wahl (Default Cloudflare+Google statt System).
- **Bewusste Limitation:** kein HTTP/3 (Go-stdlib-only-Prinzip — `quic-go` wäre externe Dependency). Upstream fällt automatisch auf HTTP/2 zurück.
