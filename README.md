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
╔═══════════════════════════════════════════════════════╗
║              localproxy  —  ready                     ║
╠═══════════════════════════════════════════════════════╣
║  Address  :  http://127.0.0.1:54321                   ║
║  Token    :  a3f8c2...                                ║
║  DNS      :  1.1.1.1:53, 8.8.8.8:53                   ║
║  Origins  :  (all — pass --origin for production)     ║
╚═══════════════════════════════════════════════════════╝
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

### All options

```
--port      int     TCP port to listen on (0 = random free port)        [default: 0]
--origin    string  Allowed origins, comma-separated
--timeout   int     Upstream request timeout in seconds                  [default: 30]
--max-mb    int64   Maximum upstream response size in MB (0 = unlimited) [default: 50]
--dns       string  DNS servers, comma-separated, or "system" for OS defaults [default: "1.1.1.1,8.8.8.8"]
```

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
| `protocol` | string | HTTP protocol version (e.g. `HTTP/1.1`, `HTTP/2.0`) |
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
| `httpVersion` | string | HTTP protocol version (e.g. `HTTP/2.0`) |
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
| **Session token** | 48-character cryptographic random token, regenerated on each start |
| **Origin check** | Only configured origins are allowed to send requests |
| **SSRF protection** | Target hostnames are resolved via DNS and checked against private/loopback CIDR ranges |
| **Configurable DNS** | Uses Cloudflare + Google DNS by default; custom servers or system DNS via `--dns` |
| **TLS verification** | Upstream certificates are always verified |
| **Redirect control** | Redirects are not followed automatically — the client decides |
| **Response cap** | Maximum response size is configurable (default: 50 MB) |
| **Hop-by-hop filter** | Proxy-internal and hop-by-hop headers are stripped |
| **Private Network Access** | Responds with `Access-Control-Allow-Private-Network: true` for Chrome PNA preflights |

### HTTPS pages calling HTTP localhost

Browsers treat `http://127.0.0.1` as a **"potentially trustworthy origin"** (W3C Secure Contexts spec). Requests from an HTTPS page to the local proxy are **not blocked** as mixed content. Chrome's Private Network Access preflight is handled automatically.

---

## Concurrency

The proxy handles **multiple requests concurrently**. Go's `net/http` server spawns a goroutine per incoming connection. Each upstream request uses a fresh connection (`DisableKeepAlives`) so that `httptrace` captures accurate DNS, TCP, TLS timing and the resolved IP on every request. HTTP/2 is negotiated automatically via TLS ALPN when supported by the upstream server.

---

## Compression

**`/proxy`:** Brotli, gzip, and deflate are supported **transparently**. The proxy forwards the browser's `Accept-Encoding` header to the upstream server and streams the compressed response bytes back. The browser handles decompression.

**`/inspect?body=1`:** The proxy first sends a HEAD request with the browser's full `Accept-Encoding` to detect the server's preferred compression (e.g. `zstd`, `br`), then a GET with `Accept-Encoding: gzip, deflate` to obtain a body that can be decompressed with Go's stdlib. The body is decompressed before embedding it in the JSON response. The `Content-Encoding` header in the `headers` map reflects the server's true preferred encoding from the HEAD probe, so consumers accurately detect compression support.

---

## Build from source

Requires [Go 1.26+](https://go.dev/dl/). If Go is not yet installed:

```bash
# Linux (amd64)
wget https://go.dev/dl/go1.26.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.26.0.linux-amd64.tar.gz
rm go1.26.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc  # or ~/.zshrc
source ~/.bashrc

# macOS (Apple Silicon)
wget https://go.dev/dl/go1.26.0.darwin-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.26.0.darwin-arm64.tar.gz
rm go1.26.0.darwin-arm64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.zshrc
source ~/.zshrc

# Windows: download the installer from https://go.dev/dl/

# Verify
go version
```

```bash
git clone https://github.com/YOUR-USER/localproxy.git
cd localproxy

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
git tag v1.0.0
git push origin v1.0.0
```

This cross-compiles binaries for all platforms and creates a GitHub Release automatically.

---

## Testing

```bash
go test -v ./...
```

---

## License

MIT
