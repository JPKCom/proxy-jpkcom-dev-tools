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
- **Go version:** 1.26.0 (as specified in `go.mod` and GitHub Actions workflow)
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

## Conventions

- Documentation language: English (README.md, code comments, identifiers)
- Integration documentation: German (CLAUDE.md, JPKCom Tools section)
- stdlib only — no external dependencies

---

## Integration with JPKCom Tools

### Context: The Two-Proxy Architecture

The JPKCom Tools project has **two proxy layers** that coexist:

| | PHP-Proxy (bestehend) | Go-Proxy / localproxy (neu) |
|---|---|---|
| **Wo läuft er?** | Auf dem Server (DDEV lokal / Production) | Auf dem Rechner des Users |
| **Dateien** | `tools/{tool}/p.php` + `tools/.lib/proxy.php` | Standalone Binary (`localproxy`) |
| **Auth** | Token V2 (SHA-256, User-Agent + IP + Timestamp + Secrets) | Per-Session random Token (`X-Proxy-Token` Header) |
| **Aufruf** | `p.php?purl=...&token=...&t=...` | `/proxy?url=...`, `/inspect?url=...`, `/page?url=...` + `X-Proxy-Token` Header |
| **Wann genutzt?** | Standard-Modus (immer) | Expertenmodus (optional, vom User aktiviert) |
| **Vorteil** | Keine Installation nötig, funktioniert sofort | Keine Server-Last, kein Rate-Limit, unbegrenzte Crawls |
| **Limitierung** | Server-Ressourcen, Timeout ~15-30s, Rate-Limits | User muss Binary herunterladen und starten |

### JPKCom Tools URLs

- **DDEV (lokal):** `https://jpkcom-tools.ddev.site/tools/`
- **Produktion:** `https://www.jpkc.com/tools/`
- **Tool-URL-Schema:** `{baseUrl}{toolName}/` (z.B. `https://www.jpkc.com/tools/seo/`)

### Tools die aktuell den PHP-Proxy nutzen

Diese Tools haben `p.php`-Endpunkte und sind Kandidaten für die localproxy-Integration:

| Tool | Verzeichnis | p.php Funktionen | Expertenmodus-Nutzen |
|---|---|---|---|
| **SEO Analyzer** | `tools/seo/` | `action=page` (Full HTML + Headers + SSL + Redirects + Timing), `action=robots` (robots.txt), `action=check-url` (HEAD mit Rate-Limit 2s) | Unbegrenzter Crawl ohne Rate-Limit, schnellere Analyse |
| **DNS/SSL/Redirect** | `tools/dns-ssl-redirect-url/` | `?ssl=on` (SSL-Cert + Security-Headers), `?redirect=on` (Redirect-Chain hop-by-hop) | Schnellere Batch-Checks, keine Server-Last |
| **Source Viewer** | `tools/source/` | Full HTML fetch + Meta-Analyse + Link/Image-Extraction + Keyword-Density | Größere Seiten laden, kein 950 KB Limit |
| **WYSIWYG Editor** | `tools/wysiwyg/` | HTML-Seiten laden für TinyMCE "Insert from URL" | Größere Seiten, schnelleres Laden |

### Expertenmodus — Konzept

Der Expertenmodus ist ein **optionaler Zusatz**, der in die JPKCom Tools integriert wird. Er ändert nichts am bestehenden Verhalten der Tools.

**Aktivierungs-Flow (im Browser):**

1. User klickt auf "Expertenmodus" (Toggle/Button in der Tool-UI)
2. Es öffnet sich ein **Optionsdialog (Bootstrap Modal)** mit:
   - Anleitung zum Download des passenden Binaries (Link zu GitHub Releases)
   - Anleitung zum Starten (`./localproxy --origin https://www.jpkc.com`)
   - Eingabefelder für **Proxy-Adresse** (`http://127.0.0.1:PORT`) und **Token**
   - "Verbindung testen"-Button (ruft `/ping` auf)
   - "Speichern"-Button (speichert in `localStorage`)
3. Nach erfolgreicher Verbindung erscheint ein **visueller Indikator** (z.B. Badge "Expert Mode") im Tool
4. Das Tool nutzt nun localproxy statt p.php für Requests

**localStorage-Struktur:**
```javascript
// Key: "localproxy"
{
    "enabled": true,
    "address": "http://127.0.0.1:54321",
    "token": "a3f8c2..."
}
```

### Wie Tools localproxy ansprechen (JavaScript)

```javascript
// Prüfen ob Expertenmodus aktiv
function isExpertMode() {
    try {
        const config = JSON.parse(localStorage.getItem('localproxy') || '{}');
        return config.enabled === true && config.address && config.token;
    } catch { return false; }
}

// Config auslesen
function getLocalProxyConfig() {
    return JSON.parse(localStorage.getItem('localproxy') || '{}');
}

// Fetch über localproxy (Expertenmodus)
// Bei Upstream-Fehlern (502/504) liefert der Proxy kategorisierte JSON-Errors:
//   { "error": "dns_error|tls_error|connection_error|timeout|upstream_error",
//     "message": "...", "status": 502|504 }
async function fetchViaLocalProxy(targetUrl) {
    const config = getLocalProxyConfig();
    const response = await fetch(
        `${config.address}/proxy?url=${encodeURIComponent(targetUrl)}`,
        {
            headers: { "X-Proxy-Token": config.token }
        }
    );
    if (!response.ok) {
        // Versuche JSON-Error zu parsen (502/504 Upstream-Fehler)
        const contentType = response.headers.get('Content-Type') || '';
        if (contentType.includes('application/json')) {
            const errData = await response.json();
            const err = new Error(errData.message);
            err.code = errData.error;   // z.B. "dns_error", "tls_error", "timeout"
            err.status = errData.status;
            throw err;
        }
        throw new Error(`Proxy error: ${response.status}`);
    }
    return response;
}

// Inspect über localproxy — SSL, Timing, IP, Protocol, Headers als JSON
// Optional mit body=1 um auch den Response-Body zu erhalten
async function inspectViaLocalProxy(targetUrl, includeBody = false) {
    const config = getLocalProxyConfig();
    let inspectUrl = `${config.address}/inspect?url=${encodeURIComponent(targetUrl)}`;
    if (includeBody) inspectUrl += '&body=1';
    const response = await fetch(inspectUrl, {
        headers: { "X-Proxy-Token": config.token }
    });
    if (!response.ok) {
        const contentType = response.headers.get('Content-Type') || '';
        if (contentType.includes('application/json')) {
            const errData = await response.json();
            const err = new Error(errData.message);
            err.code = errData.error;
            err.status = errData.status;
            throw err;
        }
        throw new Error(`Proxy error: ${response.status}`);
    }
    return response.json();
    // Returns: { status, headers, ssl, timing, ip, protocol, body? }
}

// Full Page Analysis über localproxy — Redirect-Chain + Body + SSL + Timing
// Ersetzt die Kombination aus /proxy + /inspect + manueller Redirect-Verfolgung
async function pageFetchViaLocalProxy(targetUrl) {
    const config = getLocalProxyConfig();
    const response = await fetch(
        `${config.address}/page?url=${encodeURIComponent(targetUrl)}`,
        {
            headers: { "X-Proxy-Token": config.token }
        }
    );
    if (!response.ok) {
        throw new Error(`Proxy error: ${response.status}`);
    }
    return response.json();
    // Returns: { url, finalUrl, status, httpVersion, headers, rawHeaders, html,
    //            redirectChain, ssl, timing, ip, size, transferSize, contentEncoding, error }
}

// Fetch über p.php (Standard-Modus) — bestehender Code bleibt unverändert
async function fetchViaPhpProxy(toolPath, targetUrl, token, timestamp) {
    // ... existierender p.php-Aufruf ...
}

// Universelle Fetch-Funktion mit automatischem Fallback
async function proxyFetch(targetUrl, phpProxyOptions) {
    if (isExpertMode()) {
        try {
            return await fetchViaLocalProxy(targetUrl);
        } catch (e) {
            console.warn('localproxy failed, falling back to p.php:', e);
            // Fallback auf PHP-Proxy
        }
    }
    return await fetchViaPhpProxy(
        phpProxyOptions.toolPath,
        targetUrl,
        phpProxyOptions.token,
        phpProxyOptions.timestamp
    );
}
```

### Verbindungstest (Ping)

```javascript
async function testLocalProxy(address) {
    try {
        const response = await fetch(`${address}/ping`, { mode: 'cors' });
        const text = await response.text();
        return response.ok && text.includes('ok');
    } catch { return false; }
}
```

### Feature-Kompatibilität: Was localproxy unterstützt

| Feature | PHP-Proxy | localproxy | Status |
|---|---|---|---|
| GET Requests | ✅ | ✅ | Kompatibel |
| POST Requests | ✅ | ✅ | Kompatibel |
| HEAD Requests | ✅ | ✅ | Kompatibel |
| CORS Headers | Nicht nötig (same-origin) | ✅ (dynamische `Expose-Headers`-Liste aus tatsächlichen upstream Response-Headern + `X-Upstream-*`) | Kompatibel — JS kann alle Response-Headers lesen |
| SSRF-Schutz | ✅ (URL-Prefix-Blocklist) | ✅ (DNS-Resolution + CIDR) | Go ist stärker (DNS-basiert) |
| TLS-Verifikation | ✅ | ✅ | Kompatibel |
| SSL-Zertifikat-Details | ✅ (CURLOPT_CERTINFO + openssl) | ✅ (`/inspect` Endpoint, `resp.TLS.PeerCertificates`) | Kompatibel — Subject, Issuer, SANs, Chain, Validity, Algorithmen, TLS-Version |
| Connection Timing | ✅ (curl_getinfo) | ✅ (`httptrace`: DNS, TCP, SSL, TTFB, Total) | Kompatibel — via `X-Upstream-Timing` Header und `/inspect` JSON |
| Resolved IP | ✅ (gethostbyname) | ✅ (`httptrace.ConnectDone`) | Kompatibel — via `X-Upstream-IP` Header und `/inspect` JSON |
| HTTP-Version | ✅ (CURLINFO_HTTP_VERSION) | ✅ (`resp.Proto`, HTTP/2 via `ForceAttemptHTTP2`) | Kompatibel — via `X-Upstream-Protocol` Header und `/inspect` JSON |
| Content-Encoding Info | ✅ (curl_getinfo) | ✅ (`X-Upstream-Content-Encoding`, `X-Upstream-Content-Length`) | Kompatibel |
| Response-Size-Limit | ✅ (950 KB - 1 MB) | ✅ (50 MB default, konfigurierbar) | Kompatibel (Go erlaubt größere Responses) |
| Timeout | ✅ (10-30s) | ✅ (30s default, konfigurierbar) | Kompatibel |
| Redirect-Verfolgung | ✅ (CURLOPT_FOLLOWLOCATION) | ✅ (`/page` verfolgt Redirect-Chain serverseitig mit Timing/IP pro Hop; `/proxy` gibt 3xx zurück — Browser entscheidet selbst) | Kompatibel — `/page` liefert vollständige Redirect-Chain wie PHP-Proxy |
| User-Agent | Chrome UA hardcoded | Forwarded from browser | Kompatibel (Browser UA wird durchgereicht) |
| IDN/Punycode | ✅ (idn_to_ascii) | ✅ (Go's net/http handhabt IDN nativ) | Kompatibel |
| HTTP Header Forwarding | Teilweise (eigene Header gesetzt) | ✅ (alle safe Headers) | Kompatibel |
| Response Header Forwarding | Nein (nur Body) | ✅ (alle safe Headers + Upstream-Metadata-Headers) | Go gibt **mehr** Infos zurück |
| Concurrent Requests | ❌ (single-threaded pro PHP-Prozess) | ✅ (Goroutine pro Request, fresh connections via `DisableKeepAlives`) | Verbesserung — parallele Crawls möglich, jeder Request mit akkuratem Timing |
| Private Network Access | Nicht nötig (same-origin) | ✅ (`Access-Control-Allow-Private-Network: true`) | Kompatibel — Chrome PNA-Preflight wird korrekt beantwortet |
| Mixed Content (HTTPS→HTTP) | Nicht nötig (same-origin) | ✅ (kein Problem — `127.0.0.1` ist "potentially trustworthy origin") | Kompatibel |
| Brotli/zstd-Kompression | ✅ (CURLOPT_ENCODING) | ✅ (`/proxy`: transparent — Browser-Header wird durchgereicht, Browser dekomprimiert. `/inspect?body=1`: HEAD-Pre-Check mit vollem `Accept-Encoding` erkennt Server-Präferenz (zstd, br, gzip), GET mit `gzip, deflate` für dekomprimierbaren Body, HEAD-Encoding wird in Header-Map restauriert) | Kompatibel |
| HTTP/3 (QUIC) | ❌ | ❌ (Go stdlib nur HTTP/1.1 + HTTP/2) | **Kein Problem**: Upstream fällt automatisch auf HTTP/2 zurück, kein spürbarer Unterschied. HTTP/3 bräuchte externe Library (`quic-go`), widerspricht dem stdlib-only-Prinzip |
| DNS-Server-Wahl | ❌ (System-DNS) | ✅ (konfigurierbar, Default: Cloudflare + Google) | Verbesserung — konsistente Ergebnisse unabhängig vom System |
| Graceful Shutdown | Nein | ✅ (SIGTERM/SIGINT) | Verbesserung |

### Wichtig für die Integration in JPKCom Tools

Folgende Punkte müssen beachtet werden, wenn der Expertenmodus in `/home/jpk/ddev/jpkcom-tools/` implementiert wird:

1. **Bestehender Code bleibt 100% unverändert** — der Expertenmodus ist rein additiv
2. **Fallback auf p.php** — wenn localproxy nicht erreichbar ist, wird automatisch p.php genutzt
3. **localStorage für Konfiguration** — Proxy-Adresse und Token werden pro Browser gespeichert
4. **Kein Server-Side-Code nötig** — die gesamte Expertenmodus-Logik ist clientseitig (JavaScript)
5. **Origin muss konfiguriert sein** — User muss `--origin https://www.jpkc.com` (oder `https://jpkcom-tools.ddev.site` für DDEV) beim Start angeben
6. **SEO-Tool ist der primäre Kandidat** — hat den größten Nutzen (unbegrenzte Crawls, kein 2s Rate-Limit)
7. **Redirect-Handling** — der `/page`-Endpoint verfolgt Redirect-Chains serverseitig und liefert eine vollständige `redirectChain` mit Timing, IP, Status und Headers pro Hop. Für Tools die nur den Body brauchen (Source Viewer, WYSIWYG), gibt `/proxy` weiterhin 3xx zurück — der Browser entscheidet selbst.

### Empfohlene Startup-Konfiguration für JPKCom Tools

```bash
# Produktion
./localproxy --origin https://www.jpkc.com --port 8765

# DDEV Entwicklung
./localproxy --origin https://jpkcom-tools.ddev.site --port 8765

# Mehrere Origins erlauben (Entwicklung + Produktion gleichzeitig)
./localproxy --origin "https://www.jpkc.com,https://jpkcom-tools.ddev.site" --port 8765

# Mit eigenem DNS-Server (z.B. Quad9)
./localproxy --origin https://www.jpkc.com --port 8765 --dns "9.9.9.9,1.1.1.1"

# System-DNS verwenden statt Cloudflare/Google
./localproxy --origin https://www.jpkc.com --port 8765 --dns system
```

### Dateien die in JPKCom Tools erstellt/geändert werden müssen (später, separat)

| Datei | Änderung |
|---|---|
| `tools/assets/js/tools/localproxy.js` | **Neu:** Globales JS-Modul für localproxy-Integration (Config, Ping, Fetch, UI-Helpers) |
| `tools/.tpl/footer.php` | Script-Tag für `localproxy.js` hinzufügen |
| `tools/.tpl/header.php` oder `nav.php` | Optionaler "Expert Mode"-Badge/Indicator |
| `tools/seo/assets/seo.js` | `proxyFetch()` statt direktem `p.php`-Aufruf (mit Fallback) |
| `tools/dns-ssl-redirect-url/assets/dns-ssl-redirect-url.js` | Ditto |
| `tools/source/assets/source.js` | Ditto |
| `tools/wysiwyg/assets/wysiwyg.js` | Ditto |

Keine PHP-Änderungen nötig. Alle p.php-Dateien bleiben unverändert.
