# localproxy

A lightweight, secure local HTTP proxy for browser-based online tools.
It binds exclusively to `127.0.0.1` and allows your web applications to fetch external URLs — bypassing browser CORS restrictions safely.

---

## How It Works

```
Browser (your online tool)
    ↕  HTTP → localhost:PORT  (with X-Proxy-Token header)
localproxy
    ↕  HTTP/HTTPS
External websites
```

1. User downloads the binary
2. Starts it in the terminal
3. Enters **address + token** in the online tool
4. The tool sends requests to `http://127.0.0.1:PORT/proxy?url=https://...`

---

## Download

Pre-built binaries for all platforms are available under **Releases** in this repository.

| Platform | File |
|---|---|
| Linux x64 | `localproxy-linux-amd64` |
| Linux ARM64 | `localproxy-linux-arm64` |
| macOS Intel | `localproxy-macos-intel` |
| macOS Apple Silicon | `localproxy-macos-apple-silicon` |
| Windows x64 | `localproxy-windows-amd64.exe` |
| FreeBSD x64 | `localproxy-freebsd-amd64` |
| FreeBSD ARM64 | `localproxy-freebsd-arm64` |
| OpenBSD x64 | `localproxy-openbsd-amd64` |
| NetBSD x64 | `localproxy-netbsd-amd64` |

### macOS / Linux: Make the binary executable

```bash
chmod +x ./localproxy-macos-apple-silicon
# macOS: bypass Gatekeeper warning (unsigned binary):
xattr -dr com.apple.quarantine ./localproxy-macos-apple-silicon
```

---

## Usage

### Start (minimal configuration)

```bash
./localproxy
```

Output:
```
╔══════════════════════════════════════════════════════════════════╗
║              localproxy v1.1.1  —  ready                         ║
╠══════════════════════════════════════════════════════════════════╣
║  Address  :  http://127.0.0.1:54321                              ║
║  Token    :  a3f8c2...                                           ║
╟──────────────────────────────────────────────────────────────────╢
║  DNS      :  1.1.1.1:53, 8.8.8.8:53                              ║
║  Origins  :  (all — pass --origin for production)                ║
║  Host     :  localhost only                                      ║
╟──────────────────────────────────────────────────────────────────╢
║  License  :  GPL-2.0-or-later                                    ║
║  Author   :  Jean Pierre Kolb [https://www.jpkc.com/]            ║
║  Repo     :  https://github.com/JPKCom/proxy-jpkcom-dev-tools    ║
╚══════════════════════════════════════════════════════════════════╝
```

### Production: Restrict allowed origins

```bash
./localproxy --origin https://yourtool.example.com
```

### Custom DNS servers

```bash
# Use Quad9 + Cloudflare
./localproxy --dns "9.9.9.9,1.1.1.1"

# Use the operating system's DNS resolver
./localproxy --dns system
```

By default, localproxy uses **Cloudflare (1.1.1.1)** and **Google (8.8.8.8)** for DNS resolution — independent of the host system's DNS configuration. This ensures consistent results across machines. Use `--dns system` to fall back to the OS resolver (e.g. `/etc/resolv.conf`).

> **Note:** The `--dns` flag accepts addresses with or without port. If no port is specified, `:53` (standard DNS port) is appended automatically. So `--dns "1.1.1.1,8.8.8.8"` and `--dns "1.1.1.1:53,8.8.8.8:53"` are equivalent. The startup banner always shows the normalized form with port.

### All options

```
--port            int     TCP port to listen on (0 = random free port)        [default: 0]
--origin          string  Allowed origins, comma-separated
--timeout         int     Upstream request timeout in seconds                  [default: 30]
--max-mb          int64   Maximum upstream response size in MB (0 = unlimited) [default: 50]
--dns             string  DNS servers, comma-separated, or "system" for OS defaults [default: "1.1.1.1,8.8.8.8"]
--allow-any-host          Accept a non-localhost Host header (not recommended)
--version                 Print version information and exit
```

`--port`, `--timeout` and `--max-mb` are validated at startup; an out-of-range
value aborts with a message instead of failing later in a confusing way.

### `--allow-any-host`

By default localproxy only answers requests whose `Host` header names the
loopback interface (`127.0.0.0/8`, `localhost` or `[::1]`, with any port). This
blocks DNS rebinding: without it, a web page can point a hostname it controls at
`127.0.0.1` and address the proxy from your browser.

You only need `--allow-any-host` if you reach the proxy under some other local
name (for example through a container alias). Prefer `--origin` over disabling
the check.

---

## Endpoints

| Endpoint | Auth required | Description |
|---|---|---|
| `GET /proxy?url=...` | Yes (`X-Proxy-Token`) | Forward request to the target URL |
| `POST /proxy?url=...` | Yes (`X-Proxy-Token`) | Forward POST request with body to the target URL |
| `HEAD /proxy?url=...` | Yes (`X-Proxy-Token`) | Forward HEAD request to the target URL |
| `GET /inspect?url=...` | Yes (`X-Proxy-Token`) | Return connection metadata as JSON (SSL, timing, IP, headers) |
| `GET /inspect?url=...&body=1` | Yes (`X-Proxy-Token`) | Same as above, but includes the response body |
| `GET /page?url=...` | Yes (`X-Proxy-Token`) | Full page analysis: redirect chain + body + SSL + timing (single JSON) |
| `OPTIONS /proxy`, `OPTIONS /inspect`, `OPTIONS /page` | No | CORS preflight (returns 204 with CORS + PNA headers) |
| `GET /ping` | No | Health check (returns `localproxy ok`) |
| `GET /version` | No | Version info as JSON (version, license, author, repo) |

---

## Response Metadata Headers

Every `/proxy` response includes upstream connection metadata as custom headers:

| Header | Example | Description |
|---|---|---|
| `X-Upstream-Protocol` | `HTTP/2.0` | HTTP protocol version used by the upstream server |
| `X-Upstream-IP` | `93.184.216.34` | Resolved IP address of the upstream server |
| `X-Upstream-Timing` | `dns=12;tcp=45;ssl=23;ttfb=156;total=234` | Connection timing breakdown in milliseconds |
| `X-Upstream-Content-Encoding` | `gzip` | Original `Content-Encoding` from upstream |
| `X-Upstream-Content-Length` | `34567` | Transfer size in bytes (from `Content-Length` or counted for chunked responses) |
| `X-Upstream-Truncated` | `1` | Present only when the body exceeded `--max-mb` and was cut short |

All upstream response headers are readable by JavaScript — `Access-Control-Expose-Headers` is dynamically built from the actual upstream response headers plus the `X-Upstream-*` metadata headers.

**Timing values:** `dns` = DNS lookup, `tcp` = TCP connect, `ssl` = TLS handshake, `ttfb` = time to first byte, `total` = total request time. Every request uses a fresh connection, so all timing phases are always populated.

---

## `/inspect` Endpoint

The `/inspect` endpoint returns detailed connection metadata as JSON — including SSL certificate information that browsers cannot access through the Fetch API.

### Request

```
GET http://127.0.0.1:{PORT}/inspect?url={ENCODED_TARGET_URL}
GET http://127.0.0.1:{PORT}/inspect?url={ENCODED_TARGET_URL}&body=1
Header: X-Proxy-Token: {TOKEN}
```

Without `body=1`, the proxy sends a HEAD request upstream (faster, no body download). With `body=1`, it sends a GET request, decompresses the body if needed (gzip/deflate), and includes the plain-text body in the JSON. The original `Content-Encoding` header is preserved in the `headers` map.

### Response

```json
{
  "status": 200,
  "headers": {
    "Content-Type": "text/html; charset=utf-8",
    "Server": "nginx",
    "Strict-Transport-Security": "max-age=31536000"
  },
  "ssl": {
    "version": "TLS 1.3",
    "subject": "example.com",
    "issuer": "R3",
    "issuerOrg": "Let's Encrypt",
    "organization": "",
    "validFrom": "2024-01-23T10:23:23Z",
    "validTo": "2024-04-21T10:23:22Z",
    "daysLeft": 87,
    "sans": ["example.com", "www.example.com"],
    "chain": [
      { "subject": "example.com", "issuer": "R3" },
      { "subject": "R3", "issuer": "ISRG Root X1" }
    ],
    "signatureAlgorithm": "SHA256-RSA",
    "publicKeyAlgorithm": "RSA"
  },
  "timing": {
    "dnsLookup": 12.3,
    "tcpConnect": 45.6,
    "sslHandshake": 23.4,
    "ttfb": 156.7,
    "total": 234.5
  },
  "ip": "93.184.216.34",
  "protocol": "HTTP/2.0",
  "http3": true,
  "body": "<html>..."
}
```

| Field | Type | Description |
|---|---|---|
| `status` | int | Upstream HTTP status code |
| `headers` | object | All upstream response headers |
| `ssl` | object / null | TLS certificate details (`null` for HTTP targets) |
| `timing` | object | Connection timing in milliseconds (1 decimal precision) |
| `ip` | string | Resolved IP address of the upstream server |
| `protocol` | string | HTTP protocol version actually used for this request (e.g. `HTTP/1.1`, `HTTP/2.0`) |
| `http3` | bool | Whether the target **advertises** HTTP/3 — see [HTTP/3 detection](#http3-detection) |
| `body` | string | Response body (only present when `body=1` is requested) |

---

## `/page` Endpoint

The `/page` endpoint performs a complete page analysis in a single request — redirect chain tracing, body download, SSL inspection, and timing — returning everything as one JSON response. This replaces the need for multiple `/proxy` + `/inspect` calls.

### Request

```
GET http://127.0.0.1:{PORT}/page?url={ENCODED_TARGET_URL}
Header: X-Proxy-Token: {TOKEN}
```

### Response

```json
{
  "url": "http://example.com",
  "finalUrl": "https://www.example.com/",
  "status": 200,
  "httpVersion": "HTTP/2.0",
  "http3": true,
  "headers": {
    "Content-Type": "text/html; charset=utf-8",
    "Strict-Transport-Security": "max-age=31536000",
    "Server": "Apache/2.4.66 (Unix)"
  },
  "rawHeaders": "Content-Type: text/html; charset=utf-8\nServer: Apache/2.4.66 (Unix)\n...",
  "html": "<!DOCTYPE html>...",
  "redirectChain": [
    {
      "hop": 1,
      "url": "http://example.com",
      "status": 301,
      "timing": 45.2,
      "ssl": false,
      "ip": "93.184.216.34",
      "server": "Apache/2.4.66 (Unix)",
      "rawHeaders": "Location: https://example.com/\n..."
    },
    {
      "hop": 2,
      "url": "https://www.example.com/",
      "status": 200,
      "timing": 112.3,
      "ssl": true,
      "ip": "93.184.216.34",
      "server": "Apache/2.4.66 (Unix)",
      "rawHeaders": "Content-Type: text/html; charset=utf-8\n..."
    }
  ],
  "ssl": { "version": "TLS 1.3", "subject": "www.example.com", "..." : "..." },
  "timing": {
    "dnsLookup": 12.1,
    "tcpConnect": 23.4,
    "sslHandshake": 45.2,
    "ttfb": 156.0,
    "total": 234.5,
    "downloadSize": 48230,
    "speed": 0
  },
  "ip": "93.184.216.34",
  "size": 48230,
  "transferSize": 12450,
  "contentEncoding": "gzip",
  "error": null
}
```

| Field | Type | Description |
|---|---|---|
| `url` | string | Original input URL |
| `finalUrl` | string | Final URL after following all redirects |
| `status` | int | HTTP status code of the final page |
| `httpVersion` | string | HTTP protocol version actually used for this request (e.g. `HTTP/2.0`) |
| `http3` | bool | Whether the final page **advertises** HTTP/3 — see [HTTP/3 detection](#http3-detection) |
| `headers` | object | Response headers of the final page |
| `rawHeaders` | string | Raw headers as multi-line string |
| `html` | string | Decompressed response body |
| `redirectChain` | array | Each hop with status, timing, IP, server, headers |
| `ssl` | object / null | TLS certificate details of the final page |
| `timing` | object | Connection timing of the final GET request (ms) |
| `ip` | string | Resolved IP of the final server |
| `size` | int | Decompressed body size in bytes |
| `transferSize` | int | Compressed transfer size in bytes |
| `contentEncoding` | string | Server's preferred compression (from HEAD probe) |
| `error` | object / null | Error details if the request failed |

### How it works

1. **Phase 1 — Redirect chain:** HEAD requests trace each redirect hop (up to 20), recording timing, IP, status, and headers per hop. SSRF checks run on each redirect target.
2. **Phase 2 — Encoding probe:** A HEAD request with the browser's full `Accept-Encoding` detects the server's true preferred compression (e.g. `zstd`, `br`).
3. **Phase 3 — Page fetch:** A GET request with `Accept-Encoding: gzip, deflate` downloads the body, which is decompressed via stdlib. The HEAD-detected encoding is reported in `contentEncoding` and the `headers` map.

---

## Integration

### Request format

```
GET http://127.0.0.1:{PORT}/proxy?url={ENCODED_TARGET_URL}
Header: X-Proxy-Token: {TOKEN}
```

### Error responses

Every error carries a JSON body and CORS headers, so the calling page can read
it and react. The one exception is a rejected `Origin`: that response is plain
text and deliberately carries no CORS headers, because it is not meant to be
readable by the origin that was just turned away.

```json
{ "error": "dns_error", "message": "could not resolve hostname", "status": 502 }
```

| Code | HTTP | Meaning |
|---|---|---|
| `bad_request` | 400 | `url` parameter missing or not a valid http/https URL |
| `forbidden` | 403 | Invalid or missing `X-Proxy-Token` |
| `blocked_target` | 403 | Target resolves to a private or reserved address |
| `method_not_allowed` | 405 | HTTP method not accepted on this endpoint |
| `dns_error` | 502 | Hostname could not be resolved |
| `tls_error` | 502 | Certificate expired, hostname mismatch, unknown CA, … |
| `connection_error` | 502 | TCP connection failed |
| `upstream_error` | 502 | Any other upstream failure |
| `timeout` | 504 | Upstream request timed out |

`message` is safe to display; full error details are logged to the proxy's
terminal only.

### JavaScript example

```javascript
const PROXY_BASE = "http://127.0.0.1:8765"; // entered by user
const PROXY_TOKEN = "a3f8c2...";             // entered by user

// Fetch content via /proxy (body streaming, with metadata headers)
async function fetchViaProxy(targetUrl) {
  const response = await fetch(
    `${PROXY_BASE}/proxy?url=${encodeURIComponent(targetUrl)}`,
    { headers: { "X-Proxy-Token": PROXY_TOKEN } }
  );

  if (!response.ok) {
    throw new Error(`Proxy error: ${response.status} ${response.statusText}`);
  }

  // Read upstream metadata from custom headers
  const protocol = response.headers.get("X-Upstream-Protocol"); // "HTTP/2.0"
  const ip       = response.headers.get("X-Upstream-IP");       // "93.184.216.34"
  const timing   = response.headers.get("X-Upstream-Timing");   // "dns=12;tcp=45;..."

  return response; // .text(), .json(), .arrayBuffer(), etc.
}

// Inspect a URL (SSL cert, timing, headers, IP — no body download)
async function inspectUrl(targetUrl) {
  const response = await fetch(
    `${PROXY_BASE}/inspect?url=${encodeURIComponent(targetUrl)}`,
    { headers: { "X-Proxy-Token": PROXY_TOKEN } }
  );
  return response.json();
  // { status, headers, ssl, timing, ip, protocol }
}

// Full page analysis via /page (redirect chain + body + SSL + timing)
async function analyzePage(targetUrl) {
  const response = await fetch(
    `${PROXY_BASE}/page?url=${encodeURIComponent(targetUrl)}`,
    { headers: { "X-Proxy-Token": PROXY_TOKEN } }
  );
  return response.json();
  // { url, finalUrl, status, httpVersion, headers, html, redirectChain, ssl, timing, ... }
}

// Test connection
async function testProxy(base) {
  const r = await fetch(`${base}/ping`);
  return r.ok && (await r.text()).includes("ok");
}
```

### Recommended setup flow

1. User enters address (`http://127.0.0.1:PORT`) and token
2. Tool calls `/ping` to verify the connection
3. All subsequent requests go through `/proxy?url=...`

---

## Security

| Measure | Details |
|---|---|
| **Localhost-only** | Binds exclusively to `127.0.0.1`, never to `0.0.0.0` |
| **Host check** | Requests must address the proxy as `127.0.0.0/8`, `localhost` or `[::1]` — blocks DNS rebinding against the proxy itself |
| **Session token** | 48-character cryptographic random token, regenerated on each start; compared in constant time |
| **Origin check** | Only configured origins are allowed to send requests |
| **SSRF protection** | Enforced in the dialer, after DNS resolution and before connect — see below |
| **Credential isolation** | `Cookie`, `Authorization`, `Origin`, `Referer` and `Sec-Fetch-*` are never forwarded to the target |
| **Configurable DNS** | Uses Cloudflare + Google DNS by default; custom servers or system DNS via `--dns` |
| **TLS verification** | Upstream certificates are always verified |
| **Redirect control** | Redirects are not followed automatically — the client decides |
| **Response cap** | Maximum response size is configurable (default: 50 MB), enforced on the decompressed stream too |
| **Bounded work** | Every upstream request hangs off the client's request context; `/page` has an overall time budget |
| **Hop-by-hop filter** | Proxy-internal, hop-by-hop and `Connection`-listed headers are stripped |
| **Private Network Access** | Responds with `Access-Control-Allow-Private-Network: true` for Chrome PNA preflights |

### SSRF protection

The check runs in the dialer's `Control` hook, which fires **after** DNS
resolution and **before** the socket connects — so it sees the address the
connection will actually reach.

This matters because the obvious design is unsafe. Resolving the hostname up
front and then handing the *name* to the HTTP client means the name is resolved
twice, and an attacker-controlled zone with a short TTL can answer with a public
address for the check and a loopback address for the connection. Checking at
dial time leaves only one resolution to attack. It also covers every code path
without extra plumbing: redirect hops, encoding probes and the final request all
dial through the same transport.

A hostname pre-check still runs first, purely so obvious cases fail fast with a
clear message. It is deliberately fail-open on lookup errors; the dialer is what
enforces the rule.

Blocked ranges cover loopback, RFC 1918 private, CGNAT, link-local (including
cloud metadata at `169.254.169.254`), multicast and reserved space, plus the
IPv6 forms that embed an IPv4 address — IPv4-mapped (`::ffff:127.0.0.1`), NAT64
(`64:ff9b::/96`) and 6to4 (`2002::/16`).

### HTTPS pages calling HTTP localhost

Browsers treat `http://127.0.0.1` as a **"potentially trustworthy origin"** (W3C Secure Contexts spec). Requests from an HTTPS page to the local proxy are **not blocked** as mixed content. Chrome's Private Network Access preflight is handled automatically.

---

## Concurrency

The proxy handles **multiple requests concurrently**. Go's `net/http` server spawns a goroutine per incoming connection. Each upstream request uses a fresh connection (`DisableKeepAlives`) so that `httptrace` captures accurate DNS, TCP, TLS timing and the resolved IP on every request. HTTP/2 is negotiated automatically via TLS ALPN when supported by the upstream server.

---

## Compression

**`/proxy`:** Brotli, gzip, and deflate are supported **transparently**. The proxy forwards the browser's `Accept-Encoding` header to the upstream server and streams the compressed response bytes back. The browser handles decompression.

**`/inspect?body=1`:** The proxy first sends a HEAD request with the browser's full `Accept-Encoding` to detect the server's preferred compression (e.g. `zstd`, `br`), then a GET with `Accept-Encoding: gzip, deflate` to obtain a body that can be decompressed with Go's stdlib. The body is decompressed before embedding it in the JSON response. The `Content-Encoding` header in the `headers` map reflects the server's true preferred encoding from the HEAD probe, so consumers accurately detect compression support.

**`deflate` handling:** RFC 7230 defines the `deflate` token as zlib
(RFC 1950), but a large share of servers actually send raw DEFLATE (RFC 1951).
The proxy sniffs the two-byte zlib header and picks the matching decoder, so
both forms decode correctly.

**Decompression limits:** the size cap from `--max-mb` is applied to the
decompressed stream as well as the raw one, so a small compressed body cannot
expand into gigabytes of memory.

---

## HTTP/3 detection

`/inspect` and `/page` report an `http3` boolean. It answers *"does this target
support HTTP/3?"* — **not** *"was this request made over HTTP/3?"*. The latter is
`protocol` / `httpVersion`, which will read `HTTP/2.0`.

```json
{ "protocol": "HTTP/2.0", "http3": true }
```

No QUIC stack is involved. HTTP/3 is discovered over TCP by design: a server
advertises it with an `Alt-Svc` field on its HTTP/1.1 or HTTP/2 response
(RFC 7838), or via a DNS HTTPS/SVCB record. There is therefore no site reachable
only over HTTP/3, and the capability signal is already present in the responses
this proxy receives.

Only the final ALPN token `h3` (RFC 9114) counts. Draft tokens such as `h3-29`
or `h3-Q050` are ignored — current browsers no longer negotiate them, so
counting them would overstate what a real visitor gets. `Alt-Svc: clear` yields
`false`.

The raw `Alt-Svc` field remains available in the `headers` map if you need the
advertised authority or `ma` (max-age) value.

### Why not speak HTTP/3 upstream?

Deliberate. Adding a QUIC transport (`quic-go`) would mean:

- an external dependency in a project whose premise is stdlib-only, in binaries
  users run on their own machines
- `net/http/httptrace` does not hook the HTTP/3 transport — the DNS / TCP / TLS /
  TTFB breakdown would go blank
- `http.Response.TLS` is not populated the same way, so certificate details
  would be lost
- UDP optimisations are documented for Linux, Windows and macOS only, while the
  release matrix also covers FreeBSD, OpenBSD and NetBSD

Meanwhile the benefit is small here: every request uses a fresh connection
(`DisableKeepAlives`, for accurate timing), so QUIC's 0-RTT resumption and
stream multiplexing have nothing to work with. The gain would be roughly one
round-trip per request, at the cost of the certificate and timing data that are
the point of these endpoints.

---

## Build from source

Requires [Go 1.26+](https://go.dev/dl/). If Go is not yet installed:

```bash
# Linux (amd64)
wget https://go.dev/dl/go1.26.6.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.26.6.linux-amd64.tar.gz
rm go1.26.6.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc  # or ~/.zshrc
source ~/.bashrc

# macOS (Apple Silicon)
wget https://go.dev/dl/go1.26.6.darwin-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.26.6.darwin-arm64.tar.gz
rm go1.26.6.darwin-arm64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
source ~/.zshrc

# Windows: download the installer from https://go.dev/dl/

# Verify
go version
```

```bash
git clone https://github.com/JPKCom/proxy-jpkcom-dev-tools.git
cd proxy-jpkcom-dev-tools

# Build for current platform
go build -o localproxy .

# Cross-compile examples
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o localproxy-macos-arm64 .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o localproxy.exe .
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o localproxy-linux .
```

### Automated builds

Push the GitHub Actions workflow (`.github/workflows/build.yml`) and create a tag to trigger a release:

```bash
git tag v1.1.1
git push origin v1.1.1
```

This cross-compiles binaries for all platforms and creates a GitHub Release automatically.

---

## Testing

```bash
go test -v ./...              # all tests, verbose
go test -race ./...           # with race detector (recommended)
go test -cover ./...          # with coverage report
```

Tests in `main_test.go` cover token generation and constant-time comparison,
origin validation, the Host-header check, SSRF blocking at both the pre-check
and the dialer (including NAT64/6to4/IPv4-mapped addresses), request-header
filtering, CORS preflight and CORS on error responses, deflate/zlib
decompression, response truncation, all endpoints (`/proxy`, `/inspect`,
`/page`, `/ping`, `/version`), upstream metadata headers, SSL extraction, and
connection tracing.

CI runs `gofmt`, `go vet`, `staticcheck`, `govulncheck` and `go test -race` on
every push and pull request — not only before a release build (see
`.github/workflows/build.yml`).

```bash
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...             # known vulnerabilities in toolchain & stdlib
```

### Linting

The project is linted with [staticcheck](https://staticcheck.dev/) — a Go
linter that catches deprecated APIs, unused code, and bug patterns that
`go vet` misses. CI blocks the release build if `staticcheck` reports any
finding.

To run the same check locally:

```bash
# One-time install (binary lands in $(go env GOPATH)/bin)
go install honnef.co/go/tools/cmd/staticcheck@latest

# Run on the project
staticcheck ./...
```

Make sure `$(go env GOPATH)/bin` is on your `$PATH`. `staticcheck` is a
dev tool only — it is not part of the runtime dependencies and never
ships with the binary.

---

## Changelog

### v1.1.1

Toolchain-only release: no code changes, no behaviour changes, no client-side
adjustments needed. Built with **Go 1.26.6** (2026-08-13), which carries ten
security fixes. Four of them touch code paths this proxy actually executes:

- **`encoding/asn1` — CVE-2026-33818.** `Unmarshal` had no recursion limit, so
  a deeply nested structure could exhaust the stack. `/inspect` and `/page`
  parse the certificate chain of whatever host the caller names, so a hostile
  TLS server was a plausible route to crashing the proxy.
- **`net` (vendored `dns/dnsmessage`) — CVE-2026-46600.** Parsing a malformed
  SVCB or HTTPS record with an overflowing parameter value could panic. The
  proxy uses the pure-Go resolver (`PreferGo: true`) against the servers given
  via `--dns`, and the parser walks every record in a reply — not just the A/AAAA
  answers it asked for.
- **`net/url` — CVE-2026-56860.** `resolvePath` was quadratic in the number of
  `..` segments. `/page` resolves each `Location` header against its base URL
  while tracing the redirect chain, so a target server could bill the proxy for
  the CPU time. The 20-hop limit bounded the number of resolutions but not the
  cost of one.
- **`net/http` — CVE-2026-56853.** `ReadHeaderTimeout` was not applied while the
  server sniffed for an HTTP/2 preface on a new cleartext connection. The proxy
  sets `ReadHeaderTimeout: 10s` and serves cleartext HTTP, so the gap was real —
  though only reachable from the local machine, since the listener binds to
  `127.0.0.1` and the Host header must be loopback.

The remaining six do not apply: `encoding/xml` and `html/template` are not
imported; `x/net/idna` (CVE-2026-39821) affects hostname normalisation, but the
SSRF boundary sits in the dialer after resolution and cannot be steered by a
label-parsing quirk; `crypto/tls` KeyUpdate flooding (CVE-2026-56862) targets
TLS *servers* and the proxy is a client; the two `x/mod/sumdb` transparency-log
issues (CVE-2026-56864, CVE-2026-56865) affect the `go` command at build time,
not the shipped binary — relevant to CI, which now runs on the fixed toolchain.

**Build & CI**

- `go.mod` toolchain directive bumped from `go 1.26.5` to `go 1.26.6`
- `govulncheck` reports no findings on the 1.26.6 toolchain
- CI pin stays `go-version: "1.26"` and resolves to 1.26.6 automatically

### v1.1.0

Security-focused release. No changes are required in client code — existing
fields keep their meaning and only additive fields were introduced.

**New**

- `/inspect` and `/page` report an `http3` boolean derived from the target's
  `Alt-Svc` field (RFC 7838, ALPN token `h3` per RFC 9114). This answers
  "does this site support HTTP/3?" without a QUIC stack — see
  [HTTP/3 detection](#http3-detection). Draft tokens like `h3-29` are ignored.

**Security**

- **SSRF is now enforced in the dialer**, after DNS resolution and before
  connect. The previous hostname pre-check resolved the name separately from
  the HTTP client, so an attacker-controlled zone with a short TTL could answer
  with a public address for the check and a loopback address for the connection.
  The pre-check remains as a fast-fail path only.
- **Blocked ranges extended**: reserved and special-purpose IPv4 space
  (`0/8`, `192.0.0.0/24`, `198.18/15`, multicast, `240/4`) plus the IPv6 forms
  that embed an IPv4 address — IPv4-mapped, NAT64 (`64:ff9b::/96`) and 6to4
  (`2002::/16`). `64:ff9b::7f00:1` reaches `127.0.0.1` on a NAT64 network and
  was previously invisible to a v4-only check.
- **Host-header check**: requests must address the proxy as `127.0.0.0/8`,
  `localhost` or `[::1]`, blocking DNS rebinding against the proxy itself.
  Override with `--allow-any-host`.
- **Credential and identity headers are no longer forwarded** to targets:
  `Cookie`, `Cookie2`, `Authorization`, `Proxy-Authorization`, `Origin`,
  `Referer` and `Sec-Fetch-*`. Headers the caller sets deliberately — `Accept`,
  `User-Agent`, `Accept-Language`, custom `X-*` — still pass through.
- **Bounded work per request**: `/page` derives one overall time budget from the
  client's request context. Redirect hops and encoding probes previously used
  `context.Background()`, so a client disconnect stopped nothing and 20 slow
  redirects could keep a handler alive for minutes.
- **DNS lookups in the SSRF pre-check are now bounded** (5 s) instead of able to
  hang indefinitely against a black-holed resolver.
- **Constant-time token comparison** via `crypto/subtle`.
- **Truncated bodies no longer break the response**: when a body exceeds
  `--max-mb`, the upstream `Content-Length` is dropped (it would promise more
  bytes than are delivered, aborting the connection) and `X-Upstream-Truncated: 1`
  is set instead.
- **Error responses are now readable by the caller**: all 4xx responses carry
  CORS headers and a JSON body with a machine-readable code
  (`bad_request`, `forbidden`, `blocked_target`, `method_not_allowed`). A wrong
  token used to be indistinguishable from an unreachable proxy. Rejected origins
  still get a bare 403 with no CORS headers, by design.
- `X-Content-Type-Options: nosniff` on all proxy-generated responses.

**Fixes & quality**

- `Content-Encoding: deflate` now decodes both zlib-wrapped (RFC 1950) and raw
  DEFLATE (RFC 1951). Only raw was handled, so zlib-wrapped bodies — which a
  large share of servers send — came back empty or corrupt.
- Headers named in a `Connection` header are treated as hop-by-hop (RFC 9110 §7.6.1).
- `Vary: Origin` is now always set, not only when a CORS origin was echoed.
- SSL info includes IP SANs, not just DNS names.
- `--port`, `--timeout` and `--max-mb` are validated at startup; `--timeout 0`
  previously produced an already-expired context and failed every request.
- Upstream `Content-Length` is sanity-checked before being reported as
  `transferSize`.
- Shared handler preamble replaces the duplicated method/origin/token/URL/SSRF
  blocks across the three endpoints.
- JSON encoding errors are logged rather than silently discarded.

**Build & CI**

- Built with Go 1.26.5 — security fixes in `crypto/tls` (GO-2026-5856 /
  CVE-2026-42505, ECH handshake de-anonymisation) and `os`
- `go.mod` toolchain directive bumped from `go 1.26.4` to `go 1.26.5`
- CI now runs on every push and pull request, not only on tags — a broken test
  no longer surfaces first at release time
- `govulncheck` and a `gofmt` check added to CI
- `GITHUB_TOKEN` scoped to read-only by default; only the release job gets write

### v1.0.5

- Built with Go 1.26.4 — picks up upstream stdlib fixes for `crypto/tls`, `crypto/x509`, `net/http`, and the runtime
- `go.mod` toolchain directive bumped from `go 1.26.3` to `go 1.26.4`

### v1.0.4

- Built with Go 1.26.3 — picks up upstream stdlib fixes for `crypto/tls`, `crypto/x509`, `net/http`, and the runtime
- `go.mod` toolchain directive bumped from `go 1.26.0` to `go 1.26.3`

### v1.0.3

- Hardened `/inspect` and `/page` body decompression: the decompressed stream is now also capped at `--max-mb`, preventing zip-bomb-style payloads where a small compressed body would expand to gigabytes of memory
- **Breaking (JSON shape):** `/inspect` and `/page` now return `headers` as `map[string][]string` (JSON arrays of values) instead of `map[string]string` (joined with `", "`). This fixes RFC 6265 §3 — multiple `Set-Cookie` headers used to be joined with `", "`, producing an unparseable string because cookie expiry dates contain literal commas (e.g. `expires=Sun, 27 Apr 2025 14:03:58 GMT`). Browser-side consumers should access values via `headers["X"][0]` for single-value or `headers["X"].join(", ")` for display. A `Array.isArray()` guard makes code compatible with both old and new format.
- CI now runs `staticcheck ./...` on linux/amd64 before producing release binaries; any finding blocks the release
- Code formatted with `gofmt -w` (struct alignment cleanup)

### v1.0.2

- Built with Go 1.26.2 — includes upstream security fixes for `crypto/tls`, `crypto/x509`, `net/url`, and `net/http`
- CI now runs `go test -race -v ./...` on linux/amd64 before producing release binaries; failed tests block the release
- Expanded README testing section with `-race` and `-cover` examples and a summary of what `main_test.go` covers

### v1.0.1

- Added `--version` CLI flag to print version information
- Added `/version` endpoint returning version, license, author, and repo as JSON
- Added GPL-2.0-or-later license
- Startup banner now shows version, license, author, and repository URL
- Startup banner groups Address/Token, DNS/Origins, and License/Author/Repo into visually separated sections
- Fixed resource safety: response body in redirect chain tracing is now closed immediately after receiving the response
- Added FreeBSD (amd64, arm64), OpenBSD (amd64), and NetBSD (amd64) release binaries

### v1.0.0

- Initial release
- Streaming proxy (`/proxy`), metadata inspection (`/inspect`), full page analysis (`/page`)
- Per-session cryptographic token authentication
- Origin allowlist, SSRF protection, configurable DNS resolver
- CORS with Private Network Access support
- Cross-platform binaries via GitHub Actions

---

## License

GPL-2.0-or-later — see [LICENSE](LICENSE) for the full text.
