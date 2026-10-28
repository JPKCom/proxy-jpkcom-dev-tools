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

Since v1.2.0 the binaries are built with Go 1.27, which requires **macOS 13
Ventura or later**. On macOS 12 Monterey and older, stay on
[v1.1.1](https://github.com/JPKCom/proxy-jpkcom-dev-tools/releases/tag/v1.1.1) —
it is functionally identical and built with Go 1.26.6.

### Verify the download (SHA256SUMS)

Since v1.4.0 every release has a `SHA256SUMS` file with the SHA-256 checksum of
all nine binaries. Download it next to the binary and compare:

```bash
# Linux / WSL
grep localproxy-linux-amd64 SHA256SUMS | sha256sum -c

# macOS
grep localproxy-macos-apple-silicon SHA256SUMS | shasum -a 256 -c
```

```powershell
# Windows PowerShell: compare the printed hash with the line in SHA256SUMS
(Get-FileHash -Algorithm SHA256 .\localproxy-windows-amd64.exe).Hash.ToLower()
Select-String localproxy-windows-amd64.exe .\SHA256SUMS
```

The binaries are not signed; the checksums show that the file is the one the
release build produced.

### Windows: first start

1. Open PowerShell in the download folder (in Explorer: right-click the folder →
   "Open in Terminal").
2. Start the proxy with the origin of your tool and a fixed port:

   ```powershell
   .\localproxy-windows-amd64.exe --origin "https://www.jpkc.com" --port 8765
   ```

3. SmartScreen may say "Windows protected your PC", because the binary is not
   signed. Click "More info" → "Run anyway".
4. A firewall prompt normally does not appear: the proxy listens on
   `127.0.0.1` only.

A double-click starts the proxy **without flags** — every origin allowed, a
random port. For a repeatable start, put the command into a `.cmd` file next to
the binary:

```bat
@echo off
"%~dp0localproxy-windows-amd64.exe" --origin "https://www.jpkc.com" --port 8765
pause
```

### macOS / Linux: Make the binary executable

```bash
chmod +x ./localproxy-macos-apple-silicon
# macOS: bypass Gatekeeper warning (unsigned binary):
xattr -dr com.apple.quarantine ./localproxy-macos-apple-silicon
```

On macOS you can also start it once, then allow it under **System Settings →
Privacy & Security → Open Anyway**. macOS 13 Ventura or later is required (see
above).

---

## Usage

### Start (minimal configuration)

```bash
./localproxy
```

Output:
```
╔══════════════════════════════════════════════════════════════════╗
║              localproxy v1.4.0  —  ready                         ║
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
--allow-local     list    Local targets the proxy may reach (off by default; needs --origin)  [since v1.4.0]
--token-file      path    Absolute path of a file that keeps the token across restarts (off)  [since v1.4.0]
--version                 Print version information and exit
```

`--port`, `--timeout` and `--max-mb` are validated at startup; an out-of-range
value aborts with a message instead of failing later in a confusing way.

**Quote every value** — lists, paths, patterns. bash and zsh expand `*` and
`[…]` (`[fd00::5]` fails with "no matches found"), and PowerShell turns an
unquoted comma list into separate arguments. Go's flag parser stops at the
first argument that is not a flag, so every flag after it would be ignored.
With `--allow-local` or `--token-file` such a leftover argument is a start-up
error; on a v1.3.0 command line it only produces a `WARNING` line in the banner.

| Shell | Example |
|---|---|
| bash / zsh | `./localproxy --origin "https://www.jpkc.com" --port 8765 --allow-local "mysite.ddev.site,localhost:8888" --token-file "$HOME/.config/localproxy/token"` |
| PowerShell | `.\localproxy-windows-amd64.exe --origin "https://www.jpkc.com" --port 8765 --allow-local "mysite.ddev.site,localhost:8888" --token-file "$env:LOCALAPPDATA\localproxy\token"` |
| cmd.exe / `.cmd` file | `localproxy-windows-amd64.exe --origin "https://www.jpkc.com" --port 8765 --allow-local "mysite.ddev.site,localhost:8888" --token-file "%LOCALAPPDATA%\localproxy\token"` |

### `--allow-any-host`

By default localproxy only answers requests whose `Host` header names the
loopback interface (`127.0.0.0/8`, `localhost` or `[::1]`, with any port). This
blocks DNS rebinding: without it, a web page can point a hostname it controls at
`127.0.0.1` and address the proxy from your browser.

You only need `--allow-any-host` if you reach the proxy under some other local
name (for example through a container alias). Prefer `--origin` over disabling
the check.

### `--allow-local` (local and staging sites, since v1.4.0)

By default the proxy refuses every private address — loopback, LAN, CGNAT — so
a website cannot use it to reach your machine or your network. `--allow-local`
opens exactly the targets you list, for example a DDEV project or wp-env:

```bash
./localproxy --origin "https://www.jpkc.com" --port 8765 --allow-local "mysite.ddev.site"
./localproxy --origin "https://www.jpkc.com" --port 8765 --allow-local "localhost:8888"
./localproxy --origin "https://www.jpkc.com" --port 8765 --allow-local "wp.intranet.example,10.0.5.0/24" --dns system
```

**Threat model.** Any script anywhere on an allowed origin that has the token
can reach these hosts — Chrome's Local Network Access prompt does not cover
this: it only sees the page talking to `127.0.0.1`, not what the proxy sends on
into your network. Use the narrowest entries possible.

**"Read only" stops at the tool.** With `--allow-local`, "read only" for local
targets relies on the tool's code alone. Any script on an allowed origin that
holds the token could send POST requests and `_method` overrides to the allowed
local sites. Start the proxy with `--allow-local` only while you test, and only
for the names you need. (With credentials the proxy itself refuses writing
methods, see [Target authentication](#target-authentication-since-v140).)

**Entries** (comma-separated; the flag may be given more than once):

| Entry | Allows |
|---|---|
| `mysite.ddev.site` | exactly this name (lower case, no trailing dot, IDN as punycode) |
| `*.ddev.site` | every name with at least one label in front (`a.ddev.site`, `a.b.ddev.site`), not `ddev.site` itself. This allows **every** local DDEV project |
| `localhost`, `*.localhost` | fixed to `127.0.0.1` and `::1`, no DNS (RFC 6761) |
| `10.0.5.20`, `[fd00::5]` | exactly this IP |
| `10.0.5.0/24`, `[fd00::/64]` | this IP range (IPv4 at least `/16`, IPv6 at least `/48`) |
| `…:8888` | only this port. **Without a port only 80 and 443** |

- **IPv6 always in brackets** (`[fd00::5]`, `[fd00::/64]:8443`); `fd00::5:8443`
  would be a different address, so it is refused.
- **Names reach loopback only.** A name entry connects only to `127.0.0.0/8` or
  `::1`, even if DNS says otherwise — plain DNS can be forged in a café Wi-Fi. A
  LAN address is reachable only when it also lies in an IP or CIDR entry:
  `--allow-local "wp.intranet.example,10.0.5.0/24"`. A name that is not on the
  list stays blocked, whatever it resolves to (DNS rebinding gains nothing).
- **Wildcards** only in front, and only for `*.test`, `*.localhost` and
  suffixes with at least two labels (`*.ddev.site`, `*.intranet.example`).
  Refused: `*`, `*.lan`, `*.local`, `*.internal`, `*.home.arpa`, `*.fritz.box`
  (they cover every device of a home network — use exact names such as
  `nas.lan`), and public wildcard DNS services that resolve any embedded IP
  (`*.nip.io`, `*.sslip.io`, `*.xip.io`, `*.localtest.me`, `*.lvh.me`,
  `*.traefik.me`).
- **Refused ranges and ports:** `0.0.0.0/0`, `::/0`, ranges wider than `/16`
  (IPv4) or `/48` (IPv6), ranges that are public or not entirely inside one
  private class; port 0, the proxy's own `--port`, and the ports of services
  that must never be reached from a browser: 2375, 2376 (Docker API), 2379
  (etcd), 3306 (MySQL), 5432 (PostgreSQL), 6379 (Redis), 9200
  (Elasticsearch), 10250 (kubelet), 11211 (memcached), 27017 (MongoDB).
- **Always blocked**, whatever the list says: link-local and cloud metadata
  (`169.254.0.0/16`, `fd00:ec2::254`, `100.100.100.200`), documentation and
  benchmark ranges, multicast, reserved space, NAT64/6to4, and the proxy's own
  port on loopback.
- **Requires `--origin`**, and every `--origin` must then be an `https` origin
  without a path (`https://host[:port]`), or `http://localhost[:port]` /
  `http://127.0.0.1[:port]`. It cannot be combined with `--allow-any-host`.
- **No redirects from public into local targets.** A local target is reachable
  only when the URL you ask for is already on the list; a public site that
  redirects to your DDEV project ends with `blocked_target` / `redirect_into_local`.
  Local → local and local → public are fine.
- All three endpoints (`/proxy`, `/inspect`, `/page`) reach the listed targets.
- The banner shows the entries and a `WARNING` line. They are never part of an
  HTTP response; `/version` only says `localTargets: true`.

**DDEV notes.**

- **DNS:** `*.ddev.site` resolves publicly to `127.0.0.1`, so the default
  `--dns 1.1.1.1,8.8.8.8` works. Do **not** use `--dns system` for DDEV: routers
  with DNS-rebind protection (e.g. FRITZ!Box) answer `*.ddev.site` with nothing,
  and you get `dns_error`. Intranet names need `--dns system`; if you need both,
  put the DDEV names into your hosts file.
- **TLS stays verified.** DDEV's mkcert certificates are accepted only when the
  mkcert CA is in the trust store **of the machine that runs the proxy** (run
  `mkcert -install` there). Otherwise you get `tls_error` with `type`
  `Untrusted root certificate in the chain` or `Incomplete chain or unknown
  issuer`. There is no switch to skip verification.
- **Windows proxy, DDEV in WSL2:** `127.0.0.1:443` reaches the DDEV router
  through WSL's localhost forwarding.

### `--token-file` (keep the token across restarts, since v1.4.0)

Without it the token changes on every start, and every tool asks for it again.
With `--token-file` the first start writes a new token to the file; every later
start reads it back. Delete the file to get a new token.

```bash
./localproxy --origin "https://www.jpkc.com" --port 8765 --token-file "$HOME/.config/localproxy/token"
```

```powershell
.\localproxy-windows-amd64.exe --origin "https://www.jpkc.com" --port 8765 --token-file "$env:LOCALAPPDATA\localproxy\token"
```

```bat
localproxy-windows-amd64.exe --origin "https://www.jpkc.com" --port 8765 --token-file "%LOCALAPPDATA%\localproxy\token"
```

- **Absolute path only.** A relative path, or one that still contains `%`, `$`
  or a leading `~`, is a start-up error: PowerShell does not expand
  `%LOCALAPPDATA%` (cmd syntax), and bash/zsh do not expand `~` inside quotes or
  after `=`. Use `$HOME`, `$env:LOCALAPPDATA` or `%LOCALAPPDATA%` as shown.
- **Always with `--port`.** Otherwise the address changes on every start (the
  banner warns).
- **Content:** exactly the 48 lowercase hex characters the proxy generates;
  anything else is refused — no hand-made, weak tokens.
- **Rights (Linux, macOS, BSD):** the file must be a regular file of your user
  with mode `0600` or stricter (`chmod 600 <path>`), not a symbolic link; its
  folder must belong to you (or root) and must not be writable by others
  (`chmod 700 <folder>`), unless it has the sticky bit like `/tmp`. The same
  holds for **every folder above it** up to `/` (`chmod go-w <folder>`) and
  for the targets of symbolic links on the way — like ssh with `StrictModes`;
  otherwise another user could swap a folder and plant a token they know. The
  proxy creates a missing folder with `0700` and the file with `0600`. Like
  ssh, it refuses to start otherwise. In WSL, keep the file on the Linux file system,
  not under `/mnt/c`.
- **Windows:** no permission check; `%LOCALAPPDATA%` is protected by the ACL of
  your user profile. A path outside your profile (e.g. `C:\Users\Public\…`)
  gets a `WARNING` line in the banner.
- **Trade-off:** a stolen token stays valid longer — across restarts, until you
  delete the file. Together with `--allow-local` that matters more.
- The banner shows `Token : <hex> (from token file)` and the path in a
  `Tokenfile:` line; `/version` only says `tokenPersistent: true`.

---

## Endpoints

| Endpoint | Auth required | Description |
|---|---|---|
| `GET /proxy?url=...` | Yes (`X-Proxy-Token`) | Forward request to the target URL |
| `GET /proxy?url=...&follow=1` | Yes (`X-Proxy-Token`) | Same, but the proxy follows up to 5 redirects itself (GET and HEAD only) |
| `POST /proxy?url=...` | Yes (`X-Proxy-Token`) | Forward POST request with body to the target URL (`follow` is ignored) |
| `HEAD /proxy?url=...` | Yes (`X-Proxy-Token`) | Forward HEAD request to the target URL |
| `GET /inspect?url=...` | Yes (`X-Proxy-Token`) | Return connection metadata as JSON (SSL, timing, IP, headers) |
| `GET /inspect?url=...&body=1` | Yes (`X-Proxy-Token`) | Same as above, but includes the response body |
| `GET /inspect?url=...&diag=1` | Yes (`X-Proxy-Token`) | Report upstream failures inline (HTTP 200); a `tls_error` also carries the failing server's certificate details |
| `GET /page?url=...` | Yes (`X-Proxy-Token`) | Full page analysis: redirect chain + body + SSL + timing (single JSON) |
| `GET /page?url=...&diag=1` | Yes (`X-Proxy-Token`) | Same; a `tls_error` also carries the failing server's certificate details |
| `OPTIONS /proxy`, `OPTIONS /inspect`, `OPTIONS /page` | No | CORS preflight (returns 204 with CORS + PNA headers) |
| `GET /ping` | No | Health check (returns `localproxy ok`) |
| `GET /version` | No | Version info as JSON: version, license, author, repo; since v1.4.0 also `capabilities`, `localTargets`, `tokenPersistent`, `limits` |
| `GET /version?challenge=<64 hex>` | No | Same, plus `proof` — shows that the proxy holds your token, without sending it (since v1.4.0) |

### `/version`: capabilities and proof (since v1.4.0)

```json
{
  "author": "Jean Pierre Kolb",
  "license": "GPL-2.0-or-later",
  "repo": "https://github.com/JPKCom/proxy-jpkcom-dev-tools",
  "url": "https://www.jpkc.com/",
  "version": "v1.4.0",
  "capabilities": ["follow", "diag", "inspect-get", "no-location", "error-type",
                   "target-auth", "allow-local", "token-file", "error-reason", "proof"],
  "localTargets": false,
  "tokenPersistent": false,
  "limits": { "maxBytes": 52428800, "timeoutSeconds": 30 }
}
```

- **`capabilities`** lists what the binary can do, so a tool tests for a
  feature instead of comparing versions (a local build reports `dev`). The list
  only grows; names are lower case with hyphens.

  | Capability | Meaning | Since |
  |---|---|---|
  | `follow` | `/proxy?follow=1` | v1.3.0 |
  | `diag` | `diag=1` on `/inspect` and `/page` | v1.3.0 |
  | `inspect-get` | `/inspect?get=1` | v1.3.0 |
  | `no-location` | `/proxy` never sends `Location`, but `X-Upstream-Location` | v1.3.0 |
  | `error-type` | field `type` in errors | v1.3.0 |
  | `target-auth` | [Target authentication](#target-authentication-since-v140) (`X-Target-Authorization` + `X-Target-Origin`) | v1.4.0 |
  | `allow-local` | the binary knows `--allow-local` (not: whether it is set) | v1.4.0 |
  | `token-file` | the binary knows `--token-file` (not: whether it is set) | v1.4.0 |
  | `error-reason` | field `reason` on `auth_refused` and `blocked_target` | v1.4.0 |
  | `proof` | `/version?challenge=…` answers with `proof` | v1.4.0 |

- **`localTargets`** = `--allow-local` is set; **`tokenPersistent`** =
  `--token-file` is set. Booleans only: `/version` needs no token and, without
  `--origin`, every website can read it — so it never shows a list entry or a
  path.
- **`limits`:** `maxBytes` is `--max-mb` in bytes (0 = unlimited),
  `timeoutSeconds` is `--timeout`.
- **`proof`** (only with `?challenge=` and exactly 64 hex digits; otherwise the
  answer is the same as without a challenge):

  ```
  proof = hex( HMAC-SHA256( key = token,
                            message = "localproxy-proof:" + port + ":" + challenge ) )
  ```

  The key is the token as the banner shows it — its 48 ASCII characters.
  `port` is the TCP port the proxy received the request on, in decimal
  (`8765`); the message uses the challenge exactly as sent. A tool that knows
  the token checks the proof **before** it sends the token or credentials
  anywhere, computed with the port **it** talks to: if another program has
  taken the port while the proxy was not running, it cannot compute the
  proof — and it cannot pass on a proof it fetched from the real proxy on
  another port either (with `--token-file` but without `--port`, the token
  stays the same while the port changes). The HMAC reveals nothing about the
  token. Example in the browser:

  ```javascript
  const enc = new TextEncoder();
  const challenge = Array.from(crypto.getRandomValues(new Uint8Array(32)),
    b => b.toString(16).padStart(2, "0")).join("");
  const data = await (await fetch(`${PROXY_BASE}/version?challenge=${challenge}`)).json();
  const key = await crypto.subtle.importKey("raw", enc.encode(PROXY_TOKEN),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const port = new URL(PROXY_BASE).port;     // the port you send the request to
  const mac = await crypto.subtle.sign("HMAC", key,
    enc.encode("localproxy-proof:" + port + ":" + challenge));
  const expected = Array.from(new Uint8Array(mac), b => b.toString(16).padStart(2, "0")).join("");
  const genuine = data.proof === expected;   // false → do not send the token
  ```

---

## Response Metadata Headers

Every `/proxy` response includes upstream connection metadata as custom headers:

| Header | Example | Description |
|---|---|---|
| `X-Upstream-Protocol` | `HTTP/2.0` | HTTP protocol version used by the upstream server |
| `X-Upstream-IP` | `93.184.216.34` | Resolved IP address of the upstream server |
| `X-Upstream-Timing` | `dns=12;tcp=45;ssl=23;ttfb=156;total=234` | Connection timing breakdown in milliseconds |
| `X-Upstream-Content-Encoding` | `gzip` | Original `Content-Encoding` from upstream |
| `X-Upstream-Content-Length` | `34567` | Transfer size in bytes (from `Content-Length`, or counted for compressed chunked responses — then the capped size when `X-Upstream-Truncated` is set) |
| `X-Upstream-Truncated` | `1` | Present only when the body exceeded `--max-mb` and was cut short. Not set for a chunked body **without** `Content-Encoding` (see the v1.3.0 known limitations) |
| `X-Upstream-Location` | `https://www.example.com/` | On any 3xx: the target's last `Location` value, resolved against the URL that returned it (absolute, http/https only, userinfo dropped); absent when there is no usable `Location`. Replaces `Location`, which is never forwarded |
| `X-Upstream-Final-URL` | `https://www.example.com/` | With `follow=1` only: the URL the returned response came from |
| `X-Upstream-Redirects` | `1` | With `follow=1` only: how many redirects were followed (`0` if none) |
| `X-Upstream-Auth` | `sent` | Only with credentials (since v1.4.0): `sent`, `withheld-cross-origin`, `withheld-method-override` or `withheld` — see [Target authentication](#target-authentication-since-v140) |
| `X-Upstream-Cache-Control` | `public, max-age=3600` | Only with credentials (since v1.4.0): the target's `Cache-Control`; the response itself gets `no-store` |

All upstream response headers are readable by JavaScript — `Access-Control-Expose-Headers` is dynamically built from the forwarded upstream response headers plus the nine `X-Upstream-*` metadata headers (plus `X-Upstream-Auth` and `X-Upstream-Cache-Control` when credentials were used). With `follow=1`, all metadata headers describe the final hop.

Every `X-Upstream-*` header comes from the proxy. Since v1.4.0 a target that
sends such a header itself (e.g. a forged `X-Upstream-Location`) has it dropped.

**Timing values:** `dns` = DNS lookup, `tcp` = TCP connect, `ssl` = TLS handshake, `ttfb` = time to first byte (measured from the start of the request), `total` = total request time. Every request uses a fresh connection, so all timing phases are always populated.

### Redirects on `/proxy`

The upstream `Location` header is **never** passed to the browser (since
v1.3.0). With `Location` present, `fetch()` would follow the redirect straight
to the target — carrying the `X-Proxy-Token` header to a third party whenever
that target's CORS policy let the preflight through. A 3xx therefore reaches the
caller as a plain response, with the resolved target in `X-Upstream-Location`.

With `follow=1` the proxy follows the redirect itself instead:

- **Statuses:** 301, 302, 303, 307 and 308. 300 and 304 are returned as they are.
- **Limit:** 5 redirects (the PHP proxy's limit). The sixth 3xx is returned with
  `X-Upstream-Location`.
- **Stops without an error** — the 3xx is returned as it is — when the
  `Location` is missing, cannot be parsed or leaves http/https (`javascript:`,
  `data:`, …), or when it points to a URL already visited (loop).
- **SSRF:** each redirect target passes the hostname pre-check before it is
  requested; a private or reserved target ends the request with
  `403 blocked_target` (`"type": "Blocked target"`). The dialer enforces the
  same rule for the actual connection.
- **Method:** GET and HEAD keep their method on every hop. POST is never
  followed — a request body must not be replayed — and gets no
  `X-Upstream-Final-URL` / `X-Upstream-Redirects`.
- **Time:** all hops share one `--timeout`.

```bash
curl -sD- -o /dev/null -H "X-Proxy-Token: $TOKEN" \
  "http://127.0.0.1:8765/proxy?url=http://example.com/robots.txt&follow=1"
# Example output for a target that redirects http → https → www:
# HTTP/1.1 200 OK
# X-Upstream-Final-Url: https://www.example.com/robots.txt
# X-Upstream-Redirects: 2
```

---

## Target authentication (since v1.4.0)

A tool can send credentials **for the target** (a WordPress application
password, a pasted JWT) through the proxy. The browser's own `Authorization`
and `Cookie` headers are still never forwarded; credentials reach a target only
when the caller hands them over explicitly:

```
GET /proxy?url=https://wp.example/wp-json/wp/v2/users/me?context=edit
X-Proxy-Token: <token>
X-Target-Authorization: Basic <base64(user:application-password)>
X-Target-Origin: https://wp.example
```

- **Header form:** `X-Target-Authorization` holds the complete `Authorization`
  value, `Basic <credentials>` or `Bearer <token>` (token68 syntax, at most
  8192 bytes, sent once). `X-Target-Origin` is required and names the origin the
  credentials were entered for (`scheme://host[:port]`, no path); the `url` must
  be on exactly that origin. Both are allowed in the CORS preflight.
- **Only `/proxy`.** `/inspect` and `/page` refuse the header (`reason:
  endpoint`): checks and diagnostics run anonymously.
- **Only GET and HEAD.** POST with credentials is refused (`method`). POST
  without credentials works as before.
- **No method override.** A request with credentials is refused when it carries
  `X-HTTP-Method-Override`, `X-HTTP-Method` or `X-Method-Override` (any value,
  also in underscore spelling), or a `_method` query parameter with a value
  other than `GET`, `HEAD` or `OPTIONS` (WordPress reads `?_method=DELETE` as a
  DELETE). The check runs on **every** request of a redirect chain.
- **Only the exact origin.** `Authorization` is set only on requests to the
  origin of the `url` (scheme, host and port). With `follow=1`, a redirect to
  another origin ends the chain: the response is that 3xx with
  `X-Upstream-Location` and `X-Upstream-Auth: withheld-cross-origin`, and the
  other origin receives nothing. A same-origin redirect to a URL with a writing
  `_method` ends the chain the same way (`withheld-method-override`).
- **Only HTTPS**, except for an `--allow-local` target whose connected address is
  loopback (`127.0.0.0/8`, `::1`). Credentials over `http` to anything else —
  a public site, a LAN address, a listed name that resolves elsewhere — are
  refused before a byte is sent (`insecure_scheme`).
- **Allowlist of request headers.** With credentials only `Accept`,
  `Accept-Language`, `Accept-Encoding`, `User-Agent`, `Cache-Control` and
  `Pragma` are forwarded, plus the `Authorization` the proxy sets.
- **Not cached.** Every `/proxy` response varies on `X-Target-Authorization`; a
  response with credentials gets `Cache-Control: no-store` (the target's value
  moves to `X-Upstream-Cache-Control`), without `ETag` and `Expires`.
- **`X-Upstream-Auth`** (only with credentials): `sent` — `Authorization` went
  with every request of this response; `withheld-cross-origin` and
  `withheld-method-override` — the chain stopped before such a hop; `withheld` —
  userinfo only (below): at least one request of the chain went without it.
- **Never logged, never echoed.** The value appears in no log line, no error
  message, no header and no JSON field. **Never put credentials into a query
  parameter** (`?token=…`): target URLs do appear in the proxy's error log.
- **Userinfo in the `url`** (`https://user:pass@host/`) counts as implicit Basic
  credentials. It is removed from the URL before any request, so it never shows
  up in `X-Upstream-Final-URL`, JSON or a log. GET and HEAD authenticate as
  before (now also on same-origin redirect hops; a hop to another origin goes on
  without it), POST and writing method overrides are refused, and `/proxy`
  answers with `no-store` and `X-Upstream-Auth`. Userinfo together with
  `X-Target-Authorization` is refused (`userinfo`).

**What "read only" means here:** the proxy blocks writing HTTP methods and
method overrides; it cannot prevent side effects of GET routes. Some GET routes
do write (in WordPress, for example, `wp-block-editor/v1/navigation-fallback`
or site-health tests); which routes a tool calls with credentials is up to the
tool.

Every refusal is HTTP 400 `auth_refused` with a `reason` (see
[Error responses](#error-responses)); the target is not contacted.

---

## `/inspect` Endpoint

The `/inspect` endpoint returns detailed connection metadata as JSON — including SSL certificate information that browsers cannot access through the Fetch API.

Since v1.3.0 the certificate report has the same content as the PHP proxy of the JPKCom Tools: the full chain with labels and signature checks, PEM and fingerprints per certificate, the host-name check, a list of issues, and the negotiated protocol and cipher in OpenSSL notation. With `diag=1` this also works for a server whose certificate or TLS setup is broken.

### Request

```
GET http://127.0.0.1:{PORT}/inspect?url={ENCODED_TARGET_URL}
GET http://127.0.0.1:{PORT}/inspect?url={ENCODED_TARGET_URL}&body=1
GET http://127.0.0.1:{PORT}/inspect?url={ENCODED_TARGET_URL}&get=1
GET http://127.0.0.1:{PORT}/inspect?url={ENCODED_TARGET_URL}&diag=1
Header: X-Proxy-Token: {TOKEN}
```

| Parameter | Effect |
|---|---|
| `url` | Target URL (http/https). Send internationalised host names in punycode (`new URL(u).href` in JavaScript): Go's standard library has no IDNA, so for a non-ASCII host `hostMatch` is `null` and the diagnostic probe sends no SNI |
| `body=1` | GET instead of HEAD; the body is included (see below) |
| `get=1` | GET instead of HEAD, for the headers only: the body is closed unread. Ignored with `body=1` (since v1.3.0) |
| `diag=1` | Report an upstream failure inline — HTTP 200 with an `error` object instead of 502/504. A `tls_error` additionally runs the [TLS diagnostic probe](#tls-diagnostic-probe) and fills `ssl` with the failing server's certificate details |

Without `body=1`, the proxy sends a HEAD request upstream (faster, no body download). A server that refuses HEAD with **405 or 501** is asked again with GET, for the headers only: the GET body is closed unread, so a large page is never downloaded. `method` tells which request the result describes.

With `get=1`, the proxy skips the HEAD and sends that headers-only GET straight away. Some servers answer HEAD with fewer headers than GET — `www.google.com`, for example, sends `Strict-Transport-Security` only on GET — so a security-header check should use `get=1`. It is also what the PHP proxy of the JPKCom Tools puts on the wire for a headers-only fetch (cURL `CURLOPT_CUSTOMREQUEST "GET"` plus `CURLOPT_NOBODY`). As with the fallback, the body is closed unread and the connection is dropped (keep-alives are disabled), so the page is never downloaded.

With `body=1`, the proxy first sends an untraced HEAD with the browser's full `Accept-Encoding` to learn the server's preferred compression, then a GET with `Accept-Encoding: gzip, deflate`. It decompresses the body (gzip/deflate) and includes the plain text in the JSON; `timing` and `ip` describe that GET. The HEAD-detected `Content-Encoding` is restored in the `headers` map. The body is capped at `--max-mb`, on the wire and after decoding, and cut on a UTF-8 character boundary. A registered encoding the standard library cannot decode (br, zstd, compress, dcb, dcz, …), stacked encodings (`gzip, br`) or a corrupt stream set `decodeError: true`, and `body` then holds only what was decoded — never raw compressed bytes. An unregistered token (`none`, `UTF-8`, …) is treated as a mislabelled plain body: passed through if it is valid UTF-8, otherwise `decodeError: true` and an empty `body` (see [Compression](#compression)).

### Response

```json
{
  "status": 200,
  "headers": {
    "Content-Type": ["text/html; charset=utf-8"],
    "Server": ["nginx"],
    "Strict-Transport-Security": ["max-age=31536000"]
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
      {
        "subject": "example.com",
        "issuer": "R3",
        "position": 1,
        "label": "Server certificate",
        "signatureValid": true,
        "subjectOrg": null,
        "subjectDN": "CN=example.com",
        "issuerOrg": "Let's Encrypt",
        "issuerDN": "C=US, O=Let's Encrypt, CN=R3",
        "selfIssued": false,
        "isCA": false,
        "validFrom": "2024-01-23 10:23:23 UTC",
        "validUntil": "2024-04-21 10:23:22 UTC",
        "validFromTs": 1706005403,
        "validUntilTs": 1713695002,
        "daysLeft": 87,
        "serial": "04:A1:3F:…",
        "signatureAlgorithm": "sha256WithRSAEncryption",
        "key": "EC P-256 (256 bit)",
        "keyBits": null,
        "sans": ["example.com", "www.example.com"],
        "sha256": "4A:3E:C1:…",
        "sha1": "32:8B:91:…",
        "pem": "-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n"
      },
      {
        "subject": "R3",
        "issuer": "ISRG Root X1",
        "position": 2,
        "label": "Intermediate CA",
        "signatureValid": null,
        "…": "…"
      }
    ],
    "signatureAlgorithm": "SHA256-RSA",
    "publicKeyAlgorithm": "ECDSA",
    "protocol": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "cipherSuite": "TLS_AES_128_GCM_SHA256",
    "bits": 128,
    "verified": true,
    "valid": true,
    "error": null,
    "errorType": null,
    "hostMatch": true,
    "selfSigned": false,
    "issues": [],
    "certSource": "connection"
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
  "body": "<html>...",
  "method": "GET",
  "truncated": false,
  "maxBodySize": 52428800
}
```

| Field | Type | Description |
|---|---|---|
| `status` | int | Upstream HTTP status code; `0` when the request failed (`diag=1`) |
| `headers` | object | All upstream response headers, each value an array |
| `ssl` | object / null | Certificate report — see below. `null` for HTTP targets, and for a failed request unless `diag=1` produced one |
| `timing` | object | Connection timing in milliseconds (1 decimal): `dnsLookup`, `tcpConnect`, `sslHandshake`, `ttfb` (from the start of the request), `total` |
| `ip` | string | IP address the request connected to |
| `protocol` | string | HTTP protocol version actually used for this request (e.g. `HTTP/1.1`, `HTTP/2.0`); `""` on failure |
| `http3` | bool | Whether the target **advertises** HTTP/3 — see [HTTP/3 detection](#http3-detection) |
| `body` | string | Response body (only present when `body=1` is requested) |
| `method` | string | `"HEAD"`, or `"GET"` with `body=1`, with `get=1`, or after the target refused HEAD with 405/501 |
| `location` | string | 3xx only: the last `Location` value resolved against the target URL (RFC 3986) — absolute, http/https only, userinfo dropped. Absent when there is no usable `Location`; the raw value stays in `headers` |
| `truncated` | bool | `body=1`: the body hit `maxBodySize` |
| `maxBodySize` | int | The `--max-mb` cap in bytes; `0` means unlimited |
| `decodeError` | bool | `body=1`: the `Content-Encoding` could not be decoded (br, zstd, stacked, corrupt, or an unknown token with a non-UTF-8 body). Only present when `true` |
| `error` | object | `diag=1` only, when the upstream request failed: `{error, message, status, type}` as in [Error responses](#error-responses) |

#### `ssl` object

The first twelve fields are the original v1.0 shape and keep Go's naming; the rest (since v1.3.0) mirror the PHP proxy.

| Field | Description |
|---|---|
| `version` | TLS version, Go style: `"TLS 1.3"` |
| `subject`, `issuer` | Common name of the leaf and of its issuer |
| `organization`, `issuerOrg` | First `O` of the leaf's subject and issuer, `""` if none |
| `validFrom`, `validTo` | Leaf validity, RFC 3339 |
| `daysLeft` | Whole days until the leaf expires, floored — negative once expired |
| `sans` | DNS names, then IP addresses |
| `chain` | The certificates as the server sent them, leaf first (max. 10) — see below |
| `signatureAlgorithm`, `publicKeyAlgorithm` | Go names: `"SHA256-RSA"`, `"ECDSA"` |
| `protocol` | TLS version in OpenSSL notation: `"TLSv1"`, `"TLSv1.1"`, `"TLSv1.2"`, `"TLSv1.3"`. `""` when no handshake state is known (`certSource: "verify-error"`) |
| `cipher` | OpenSSL name of the negotiated suite, e.g. `"ECDHE-RSA-AES128-GCM-SHA256"` |
| `cipherSuite` | IANA name, e.g. `"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"` |
| `bits` | Symmetric strength of the suite |
| `verified` | The content connection passed verification against the system trust store |
| `valid` | Same value as `verified`, under the name the PHP proxy's SEO report uses |
| `error` | Why verification failed, in OpenSSL's verify-result wording: `"Certificate has expired"`, `"Certificate is not yet valid"`, `"Hostname mismatch"`, `"Self-signed certificate"`, `"Self-signed certificate in chain"`, `"Unable to get local issuer certificate"`, `"Certificate not trusted"`, `"TLS protocol not supported"`, `"TLS handshake failed"`. `null` if verified |
| `errorType` | The classified failure — the same text as `error.type` (see [Error responses](#error-responses)). `null` if verified |
| `hostMatch` | Whether the leaf covers the requested host (RFC 6125: SANs, or the subject if there are none; `*.` matches exactly one label; IPs compared as IPs). `null` when the host is unknown or not ASCII |
| `selfSigned` | The leaf is self-issued and its self-signature is valid |
| `issues` | `[{ "type": "error" \| "warning", "msg": "…" }]` — expired / not yet valid / expires within 14 days, host not covered, self-signed, weak signature algorithm (MD5, SHA-1; self-signed roots exempt), RSA key below 2048 bit, no intermediate sent, broken chain or wrong order. Same rules and English messages as the PHP proxy |
| `certSource` | Where the chain came from: `"connection"` (the verified connection), `"probe"` (the [TLS diagnostic probe](#tls-diagnostic-probe)) or `"verify-error"` (the unverified chain attached to the verification error, when the probe failed) |
| `probeError` | Only present when the probe failed: a generic note; details go to the proxy's terminal |

#### `chain` entries

| Field | Description |
|---|---|
| `subject`, `issuer` | First `CN`, else first `O`, else `"Unknown"` |
| `position` | 1-based position in the served chain |
| `label` | `"Server certificate"`, `"Intermediate CA"`, `"Root CA (self-signed)"`, `"Cross-signed root (acts as intermediate)"` or `"Certificate"` |
| `signatureValid` | Whether the next certificate (or, for a self-issued one, the certificate itself) signed it; `null` when the issuer was not sent |
| `subjectOrg`, `issuerOrg` | First `O`, or `null` |
| `subjectDN`, `issuerDN` | Full name in DER order, e.g. `"C=US, O=Let's Encrypt, CN=R3"` |
| `selfIssued`, `isCA` | Subject equals issuer; basic constraints say CA |
| `validFrom`, `validUntil` | `"YYYY-MM-DD hh:mm:ss UTC"` |
| `validFromTs`, `validUntilTs` | Unix seconds |
| `daysLeft` | Floored, negative once expired |
| `serial` | Upper-case hex pairs, `"04:A1:3F:…"` |
| `signatureAlgorithm` | OpenSSL long name: `sha256WithRSAEncryption`, `ecdsa-with-SHA256`, `rsassaPss`, `ED25519`, … |
| `key` | `"RSA 2048 bit"`, `"EC P-256 (256 bit)"`, `"Ed25519"`, `"DSA 1024 bit"` or `"Unknown"` |
| `keyBits` | RSA key size, `null` for other key types |
| `sans` | DNS names, then IP addresses |
| `sha256`, `sha1` | Fingerprints, upper-case hex pairs |
| `pem` | The certificate in PEM encoding |

#### Failures with `diag=1`

Without `diag=1`, a failed upstream request is answered with 502/504 and the
JSON error body — unchanged from earlier versions apart from the added `type`.
With `diag=1` the answer is HTTP 200, `status: 0` and an `error` object; for a
`tls_error`, `ssl` describes what the failing server presented:

```json
{
  "status": 0,
  "headers": {},
  "ssl": {
    "subject": "localhost",
    "issuer": "localhost",
    "chain": [{ "label": "Server certificate", "selfIssued": true, "signatureValid": true, "pem": "…", "…": "…" }],
    "protocol": "TLSv1.3",
    "cipher": "TLS_AES_128_GCM_SHA256",
    "verified": false,
    "valid": false,
    "error": "Hostname mismatch",
    "errorType": "Host name does not match the certificate",
    "hostMatch": false,
    "selfSigned": true,
    "issues": [
      { "type": "error", "msg": "The host name is not covered by the certificate (CN/SAN)." },
      { "type": "error", "msg": "The certificate is self-signed — browsers will not trust it." }
    ],
    "certSource": "probe",
    "…": "…"
  },
  "timing": { "dnsLookup": 0, "tcpConnect": 0.4, "sslHandshake": 1.5, "ttfb": 0, "total": 2.3 },
  "ip": "93.184.216.34",
  "protocol": "",
  "http3": false,
  "method": "HEAD",
  "truncated": false,
  "maxBodySize": 52428800,
  "error": {
    "error": "tls_error",
    "message": "TLS certificate hostname mismatch",
    "status": 502,
    "type": "Host name does not match the certificate"
  }
}
```

The verdict (`verified`, `error`, `errorType`) always comes from the real,
verified connection; the probe only supplies the details. A failure other than
`tls_error` returns `ssl: null`.

---

## `/page` Endpoint

The `/page` endpoint performs a complete page analysis in a single request — redirect chain tracing, body download, SSL inspection, and timing — returning everything as one JSON response. This replaces the need for multiple `/proxy` + `/inspect` calls.

### Request

```
GET http://127.0.0.1:{PORT}/page?url={ENCODED_TARGET_URL}
GET http://127.0.0.1:{PORT}/page?url={ENCODED_TARGET_URL}&diag=1
Header: X-Proxy-Token: {TOKEN}
```

`diag=1` adds the [TLS diagnostic probe](#tls-diagnostic-probe): when the chain
or the final GET fails with a `tls_error`, `ssl` describes the certificate the
failing server presented and `finalUrl` names that server's URL. Upstream
failures on `/page` are always reported inline (HTTP 200 with `error`), with or
without `diag`.

### Response

```json
{
  "url": "http://example.com",
  "finalUrl": "https://www.example.com/",
  "status": 200,
  "httpVersion": "HTTP/2.0",
  "http3": true,
  "headers": {
    "Content-Type": ["text/html; charset=utf-8"],
    "Strict-Transport-Security": ["max-age=31536000"],
    "Server": ["Apache/2.4.66 (Unix)"]
  },
  "rawHeaders": "HTTP/2 200\nContent-Type: text/html; charset=utf-8\nServer: Apache/2.4.66 (Unix)\n...",
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
      "rawHeaders": "HTTP/1.1 301 Moved Permanently\nLocation: https://www.example.com/\n...",
      "method": "HEAD",
      "location": "https://www.example.com/"
    },
    {
      "hop": 2,
      "url": "https://www.example.com/",
      "status": 200,
      "timing": 112.3,
      "ssl": true,
      "ip": "93.184.216.34",
      "server": "Apache/2.4.66 (Unix)",
      "rawHeaders": "HTTP/2 200\nContent-Type: text/html; charset=utf-8\n...",
      "method": "GET",
      "certCN": "www.example.com",
      "certExpiry": "2024-04-21",
      "certDaysLeft": 87
    }
  ],
  "ssl": { "version": "TLS 1.3", "subject": "www.example.com", "protocol": "TLSv1.3", "verified": true, "chain": [ "…" ], "…" : "…" },
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
  "error": null,
  "truncated": false,
  "maxBodySize": 52428800
}
```

| Field | Type | Description |
|---|---|---|
| `url` | string | Original input URL |
| `finalUrl` | string | Final URL after following all redirects; on a chain failure the last URL reached (with `diag=1` and a `tls_error`: the failing URL) |
| `status` | int | HTTP status code of the final page (`0` on failure) |
| `httpVersion` | string | HTTP protocol version actually used for this request (e.g. `HTTP/2.0`) |
| `http3` | bool | Whether the final page **advertises** HTTP/3 — see [HTTP/3 detection](#http3-detection) |
| `headers` | object | Response headers of the final page, each value an array |
| `rawHeaders` | string | Status line (`HTTP/1.1 200 OK`, `HTTP/2 200`) followed by the headers, one per line, sorted by name |
| `html` | string | Decompressed response body, capped at `maxBodySize` on a UTF-8 boundary. Never raw compressed bytes — see `decodeError` |
| `redirectChain` | array | Each hop — see below. On success the last entry is the final GET |
| `ssl` | object / null | Certificate report of the final page, same shape as on [`/inspect`](#ssl-object). On failure `null`, or with `diag=1` and a `tls_error` the failing server's certificate |
| `timing` | object | Connection timing of the final GET request (ms) |
| `ip` | string | IP of the final server — on failure, of the server that failed |
| `size` | int | Decompressed body size in bytes |
| `transferSize` | int | Transfer size in bytes: the upstream `Content-Length` when sane, else the bytes received |
| `contentEncoding` | string | Server's preferred compression (from HEAD probe) |
| `error` | object / null | `{error, message, status, type}` if the request failed — see [Error responses](#error-responses) |
| `truncated` | bool | The body hit `maxBodySize` |
| `maxBodySize` | int | The `--max-mb` cap in bytes; `0` means unlimited |
| `decodeError` | bool | The `Content-Encoding` could not be decoded (br, zstd, stacked, corrupt, or an unknown token with a non-UTF-8 body); `html` holds only what was decoded. Only present when `true` |

**Redirect chain hops:**

| Field | Description |
|---|---|
| `hop`, `url`, `status`, `timing`, `ssl`, `ip`, `server` | Position, URL, status code, total time (ms), whether the URL is https, connected IP, `Server` header |
| `rawHeaders` | Status line plus sorted headers, as above |
| `method` | `"HEAD"`, or `"GET"` when the target refused HEAD with 405/501, and for the final hop. Absent on error-only hops the tracer adds without making a request (loop, hop limit, blocked target) |
| `location` | 3xx hops: the resolved, absolute target |
| `certCN`, `certExpiry`, `certDaysLeft` | https hops: the leaf's common name (CN only), expiry date `YYYY-MM-DD` and floored days left |
| `error` | Why the chain stopped here, e.g. `"tls_error: TLS certificate verification failed"` or `"redirect loop detected"` |
| `errorCategory` | The error code of a failed hop: `tls_error`, `dns_error`, `connection_error`, `timeout`, `upstream_error`, `blocked_target`, `redirect_loop`, `too_many_redirects`, `bad_request` |
| `errorType` | `tls_error` hops only: the classified failure (`"Certificate expired"`, …) |

**When the chain stops early** — a transport error, a loop, more than 20
redirects, a private or non-http(s) redirect target, an unparseable `Location`
or the overall time budget — the last hop carries the error, `error.error` is
that hop's `errorCategory`, `error.message` its `error` text, and the final GET
is skipped:

```json
{
  "url": "https://example.com/start",
  "finalUrl": "https://example.com/start",
  "status": 0,
  "redirectChain": [
    {
      "hop": 1,
      "url": "https://example.com/start",
      "status": 0,
      "timing": 4.0,
      "ssl": true,
      "ip": "93.184.216.34",
      "error": "tls_error: TLS certificate hostname mismatch",
      "method": "HEAD",
      "errorCategory": "tls_error",
      "errorType": "Host name does not match the certificate"
    }
  ],
  "ssl": null,
  "ip": "93.184.216.34",
  "error": {
    "error": "tls_error",
    "message": "tls_error: TLS certificate hostname mismatch",
    "status": 502,
    "type": "Host name does not match the certificate"
  },
  "truncated": false,
  "maxBodySize": 52428800,
  "…": "…"
}
```

If the chain succeeds but the final GET fails, `error` carries that failure
with its own code and the chain is returned as traced, without a final hop.

### How it works

1. **Phase 1 — Redirect chain:** HEAD requests trace each redirect hop, recording timing, IP, status, headers and the certificate summary per hop. A server that refuses HEAD with 405/501 is asked again with GET (body closed unread). The next URL is the last `Location` value resolved per RFC 3986; it must be http/https and passes the SSRF pre-check before it is requested. Loops are detected. Up to 20 redirects are followed (like the Fetch standard); if the 21st request redirects again, the chain stops with `too_many_redirects` and the URL it points to is not requested. Each hop has its own `--timeout`, all of them share the overall budget of `3 × --timeout`.
2. **Phase 2 — Encoding probe:** An untraced HEAD request with the browser's full `Accept-Encoding` detects the server's true preferred compression (e.g. `zstd`, `br`).
3. **Phase 3 — Page fetch:** A GET request with `Accept-Encoding: gzip, deflate` downloads the body under the `--max-mb` cap, which is decompressed via stdlib. The HEAD-detected encoding is reported in `contentEncoding` and the `headers` map.
4. **Diagnosis (`diag=1` only):** if phase 1 or 3 failed with a `tls_error`, the [TLS diagnostic probe](#tls-diagnostic-probe) reads the failing server's certificate chain, protocol and cipher.

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
{ "error": "dns_error", "message": "could not resolve hostname", "status": 502, "type": "Could not resolve host" }
```

Where the error object appears:

- **`/proxy`, and `/inspect` without `diag=1`:** as the response body; the HTTP
  status equals `status`.
- **`/inspect?diag=1` and `/page`:** inline as the `error` field of an HTTP 200
  response, so the rest of the result (timing, IP, the chain so far, and with
  `diag=1` the certificate report) arrives with it. `status` still says 502 or
  504.

| Code | HTTP | Meaning |
|---|---|---|
| `bad_request` | 400 | `url` parameter missing or not a valid http/https URL. On `/page` also a redirect `Location` that cannot be parsed (inline, `status` 502) |
| `forbidden` | 403 | Invalid or missing `X-Proxy-Token` |
| `auth_refused` | 400 | Since v1.4.0: the request carries credentials (`X-Target-Authorization` or userinfo in the `url`) in a way the proxy does not allow — see `reason` below. The target was not contacted |
| `blocked_target` | 403 / 502 | Target resolves to a private or reserved address (since v1.4.0 with `reason`, see below). **403** when the SSRF pre-check catches it — the URL itself, or a redirect target on `/proxy?follow=1`. **502** (with `type` `Blocked target`) when the pre-check passed but the dialer blocks the connection after DNS resolution (e.g. DNS rebinding) on `/proxy` or `/inspect`. On `/page` a private redirect target, one with a scheme other than http/https, or a dialer block (inline, `status` 502) |
| `method_not_allowed` | 405 | HTTP method not accepted on this endpoint |
| `dns_error` | 502 | Hostname could not be resolved |
| `tls_error` | 502 | Any TLS failure: certificate (expired, hostname mismatch, unknown CA) **or** handshake (no mutually supported protocol version or cipher suite, peer alert, target not speaking TLS) |
| `connection_error` | 502 | TCP connection failed |
| `upstream_error` | 502 | Any other upstream failure |
| `redirect_loop` | 502 | `/page` only: the redirect chain returned to a URL already visited |
| `too_many_redirects` | 502 | `/page` only: more than 20 redirects (the 21st request redirected again) |
| `timeout` | 504 | Upstream request timed out — the request's own deadline, the `/page` budget, or a DNS-lookup, dial, TLS-handshake or response-header timeout of the transport |

`message` is safe to display; full error details are logged to the proxy's
terminal only.

**`reason`** (since v1.4.0) is a machine-readable sub-code for branching, set on
`auth_refused` and `blocked_target`. `error` stays the primary code, `type`
stays display text. Where to find it:

| Endpoint | Path |
|---|---|
| `/proxy`, and every rejection before the target is contacted | top-level `reason` |
| `/inspect?diag=1` (inline error) | `error.reason` |
| `/page` | `error.reason`, and `errorReason` on the redirect hop that stopped |

| `error` | `reason` | Meaning |
|---|---|---|
| `auth_refused` | `invalid_value` | `X-Target-Authorization` malformed, empty, repeated or too long; an underscore variant of a credential header; `X-Target-Origin` missing, invalid, or sent alone |
| `auth_refused` | `endpoint` | `X-Target-Authorization` on `/inspect` or `/page` |
| `auth_refused` | `method` | credentials with a method other than GET or HEAD |
| `auth_refused` | `method_override` | credentials with a method-override header or a writing `_method` in the URL |
| `auth_refused` | `userinfo` | userinfo in the `url` together with `X-Target-Authorization` |
| `auth_refused` | `origin_mismatch` | the `url` is not on the origin in `X-Target-Origin` |
| `auth_refused` | `insecure_scheme` | credentials over `http` to a target that is not `--allow-local`, or whose connected address is not loopback |
| `blocked_target` | `private` | a private address, and `--allow-local` is not set (the v1.3.0 case) |
| `blocked_target` | `not_allowlisted` | `--allow-local` is set, but this target (name, port or address) is not on the list |
| `blocked_target` | `always_blocked` | never reachable, with or without `--allow-local` (cloud metadata, link-local, reserved space, the proxy's own port) |
| `blocked_target` | `redirect_into_local` | a redirect from a public URL to an `--allow-local` target |
| `blocked_target` | `unsupported_scheme` | `/page`: a redirect to a scheme other than http/https |

The checks run in a fixed order: origin, method, token, `url`, then the
credential rules (`invalid_value` → `endpoint` → `method` → `method_override` →
`userinfo` → `origin_mismatch`), the SSRF pre-check (`blocked_target`), and
last `insecure_scheme`. A caller without a valid token therefore learns nothing
about the credential rules, and `http://foo.ddev.site` that is not on the list
reports the missing allowance (`not_allowlisted`) rather than the scheme.

**`type`** (since v1.3.0) is a human-readable class with the same texts as the
PHP proxy's `error.type`. It is set on every upstream failure, on every `/page`
chain stop (including the 502 when the dialer blocks a target) and on the
`/proxy` 403 for a blocked redirect target; the
request-validation errors (`bad_request`, `forbidden`, `blocked_target` for the
URL itself, `method_not_allowed`) carry none.

| Code | `type` |
|---|---|
| `tls_error` | The classified failure: `Certificate expired`, `Certificate not yet valid`, `Host name does not match the certificate`, `Self-signed certificate`, `Untrusted root certificate in the chain`, `Incomplete chain or unknown issuer`, `TLS protocol not supported` (no common protocol version, or a plain-HTTP server behind `https://`) or `TLS/SSL error` (anything else, e.g. a distrusted CA) |
| `dns_error` | `Could not resolve host` |
| `connection_error` | `Could not connect to host` |
| `timeout` | `Connection timeout` |
| `blocked_target` | `Blocked target` |
| `redirect_loop` | `Redirect loop detected` |
| `too_many_redirects` | `Too many redirects` |
| `bad_request` (`/page` chain) | `Invalid URL` |
| `upstream_error` | `Upstream error` |

**Timeout detection.** An upstream error counts as `timeout` when the request's
context deadline expired or the error itself reports a timeout (`net.Error`
with `Timeout()`), whatever shape the transport gave it. This check runs before
the DNS check, so a DNS lookup that times out (e.g. an unreachable `--dns`
server) is a `timeout` too, like cURL's errno 28. Before v1.3.0 only an
expired request context was recognised; a dial timeout was reported as
`connection_error`, a TLS-handshake or response-header timeout as
`upstream_error`, and a timed-out DNS lookup as `dns_error`, all with 502.

### JavaScript example

```javascript
const PROXY_BASE = "http://127.0.0.1:8765"; // entered by user
const PROXY_TOKEN = "a3f8c2...";             // entered by user
const HEADERS = { "X-Proxy-Token": PROXY_TOKEN };

// Turn a failed response into an Error. Proxy errors carry JSON
// ({error, message, status, type}); a target's own 4xx/5xx does not, and is
// recognisable by its X-Upstream-Protocol header.
async function proxyError(response) {
  const err = new Error(`Proxy error: ${response.status} ${response.statusText}`);
  err.status = response.status;
  if (!response.headers.get("X-Upstream-Protocol")) {
    try {
      const data = await response.json();
      err.message = `Proxy error: ${data.message}` + (data.type ? ` (${data.type})` : "");
      err.code = data.error;  // "dns_error", "tls_error", "timeout", ...
      err.reason = data.reason;  // since v1.4.0: "not_allowlisted", "method", ... (or undefined)
      err.type = data.type;   // "Certificate expired", ...
    } catch { /* not JSON */ }
  }
  return err;
}

// Fetch content via /proxy, following redirects on the proxy side
async function fetchViaProxy(targetUrl) {
  const response = await fetch(
    `${PROXY_BASE}/proxy?url=${encodeURIComponent(targetUrl)}&follow=1`,
    { headers: HEADERS }
  );

  if (!response.ok) {
    // A 3xx arrives here only if it was not followed (limit, loop, no usable
    // Location); X-Upstream-Location says where it pointed.
    throw await proxyError(response);
  }

  // Read upstream metadata from custom headers
  const finalUrl  = response.headers.get("X-Upstream-Final-URL"); // where the content came from
  const redirects = response.headers.get("X-Upstream-Redirects"); // "0", "1", ...
  const protocol  = response.headers.get("X-Upstream-Protocol");  // "HTTP/2.0"
  const ip        = response.headers.get("X-Upstream-IP");        // "93.184.216.34"
  const timing    = response.headers.get("X-Upstream-Timing");    // "dns=12;tcp=45;..."
  const truncated = response.headers.get("X-Upstream-Truncated") === "1";

  return response; // .text(), .json(), .arrayBuffer(), etc.
}

// Inspect a URL (SSL cert, timing, headers, IP — no body download).
// With diag=1, failures arrive as data.error and a broken certificate is
// still described in data.ssl.
async function inspectUrl(targetUrl) {
  const response = await fetch(
    `${PROXY_BASE}/inspect?url=${encodeURIComponent(new URL(targetUrl).href)}&diag=1`,
    { headers: HEADERS }
  );
  if (!response.ok) throw await proxyError(response); // 4xx: token, URL, blocked
  const data = await response.json();
  // { status, headers, ssl, timing, ip, protocol, http3, method, location, error, ... }
  if (data.error) {
    console.warn(data.error.message, data.error.type, data.ssl?.issues);
  }
  return data; // data.location: next hop of a 3xx, already resolved
}

// Full page analysis via /page (redirect chain + body + SSL + timing)
async function analyzePage(targetUrl) {
  const response = await fetch(
    `${PROXY_BASE}/page?url=${encodeURIComponent(new URL(targetUrl).href)}&diag=1`,
    { headers: HEADERS }
  );
  if (!response.ok) throw await proxyError(response);
  return response.json();
  // { url, finalUrl, status, httpVersion, headers, html, redirectChain, ssl,
  //   timing, truncated, maxBodySize, error, ... }
}

// Test connection
async function testProxy(base) {
  const r = await fetch(`${base}/ping`);
  return r.ok && (await r.text()).includes("ok");
}
```

`new URL(u).href` converts an internationalised host name to punycode, which
`/inspect` and `/page` need for the host-name check (see [Request](#request)).

### Recommended setup flow

1. User enters address (`http://127.0.0.1:PORT`) and token. With
   `--token-file` and a fixed `--port` this is needed only once.
2. Tool calls `/ping` to verify the connection.
3. Tool calls `/version?challenge=<64 random hex digits>` and checks `proof`
   with the token (see [`/version`](#version-capabilities-and-proof-since-v140))
   **before** it sends the token. A missing or wrong proof from a proxy that
   lists `proof` in `capabilities` means something else answers on that port:
   send neither token nor credentials.
4. Token probe: `GET /inspect` with `X-Proxy-Token` and **without** `url`. A
   valid token gives `400 bad_request`, an invalid one `403 forbidden` — no
   upstream request, no DNS. This answer is a fixed contract since v1.4.0.
5. Tool reads `capabilities` and enables what the proxy can do (e.g.
   credentials only with `target-auth`).
6. All subsequent requests go through `/proxy?url=...`.

---

## Security

| Measure | Details |
|---|---|
| **Localhost-only** | Binds exclusively to `127.0.0.1`, never to `0.0.0.0` |
| **Host check** | Requests must address the proxy as `127.0.0.0/8`, `localhost` or `[::1]` — blocks DNS rebinding against the proxy itself |
| **Session token** | 48-character cryptographic random token, regenerated on each start unless `--token-file` is set; compared in constant time. `/version?challenge=…` proves the proxy holds it without revealing it |
| **Origin check** | Only configured origins are allowed to send requests |
| **SSRF protection** | Enforced in the dialer, after DNS resolution and before connect — see below |
| **Credential isolation** | The browser's `Cookie`, `Authorization`, `Origin`, `Referer` and `Sec-Fetch-*` are never forwarded to the target (since v1.4.0 also in underscore spelling, e.g. `Sec_Fetch_Site`). Credentials reach a target only when a tool passes them explicitly in `X-Target-Authorization`, and only to the exact origin in `X-Target-Origin`, GET/HEAD only, over HTTPS — see [Target authentication](#target-authentication-since-v140). They are never logged |
| **Local targets (opt-in)** | Off by default. `--allow-local` opens only the listed names and ranges; names reach loopback only; fixed blocks stay; requires `--origin`; no redirects from public into local targets — see [`--allow-local`](#--allow-local-local-and-staging-sites-since-v140) |
| **Token file (opt-in)** | Off by default. `--token-file` keeps the token across restarts; absolute path, file `0600`, folder not writable by others — see [`--token-file`](#--token-file-keep-the-token-across-restarts-since-v140) |
| **Configurable DNS** | Uses Cloudflare + Google DNS by default; custom servers or system DNS via `--dns` |
| **TLS verification** | Every connection that carries HTTP data is verified. The only exception is the handshake-only [diagnostic probe](#tls-diagnostic-probe) (`diag=1` after a `tls_error`), which reads certificates and nothing else |
| **Redirect control** | The HTTP client never follows a redirect by itself, and `Location` is never forwarded to the browser (it would carry the token to the target) — `/proxy` reports `X-Upstream-Location` instead. Redirects are followed only by the proxy's own code: `/proxy?follow=1` (max. 5, GET/HEAD) and `/page` (max. 20). Every hop must be http/https and passes the SSRF pre-check; the dialer enforces the rule again |
| **Response cap** | Maximum response size is configurable (default: 50 MB), enforced on the decompressed stream too |
| **Bounded work** | Every upstream request hangs off the client's request context; `/page` has an overall time budget |
| **Hop-by-hop filter** | Proxy-internal, hop-by-hop and `Connection`-listed headers are stripped |
| **Private Network Access** | Responds with `Access-Control-Allow-Private-Network: true` for Chrome PNA preflights |
| **Metadata integrity** | Since v1.4.0 every `X-Upstream-*` header comes from the proxy; the same names sent by a target are dropped |

**Your IP address.** Every request the proxy makes comes from your internet
connection. The proxy does not throttle; a tool that sends many requests (link
checks, API exploration) must pace itself, or web application firewalls may
block your address.

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

With `--allow-local` (since v1.4.0) a second guard sits in front of the dialer.
It sees the requested name **and** the address it resolves to, connects to the
checked IP literal, and lets the `Control` hook re-check it. Only a request
whose URL is itself on the list may reach a local address; the decision travels
with the request's context, and because every request gets its own connection
(`DisableKeepAlives`), a connection opened for one request is never reused by
another. Without `--allow-local` the dialer works exactly as in v1.3.0.

### TLS diagnostic probe

Content connections — every request that carries HTTP data on `/proxy`,
`/inspect` and `/page` — are always verified against the system trust store; the
upstream transport never sets `InsecureSkipVerify` (a test enforces this). A
failed verification therefore yields only an error, not the details a
certificate checker needs: protocol, cipher, and the chain of a server that is
expired, self-signed or stuck on TLS 1.0.

With `diag=1`, a `tls_error` triggers one separate, **handshake-only** TLS
connection to read them:

- **Opt-in and narrow:** only with `diag=1`, and only after the verified request
  failed with `tls_error`.
- **Same address, same guard:** it connects to the IP the failed request had
  already connected to — no second DNS lookup, so no rebinding window — and dials
  through the same `safeDialControl` hook, which re-checks that IP.
- **No application data:** verification is skipped (`InsecureSkipVerify`) so the
  failing chain can be seen, but nothing is written or read after the handshake,
  and the connection is never handed to the HTTP transport. It accepts TLS 1.0
  and every cipher suite Go still implements (incl. RSA key exchange, 3DES, RC4)
  so legacy servers can be described.
- **Not a verdict:** `verified`, `error` and `errorType` come from the real,
  verified connection. The probe only supplies chain, protocol and cipher
  (`certSource: "probe"`).
- **Bounded:** 10 seconds, derived from the client's request rather than from
  the upstream timeout the failed request may have used up. Worst case:
  `--timeout` + 10 s on `/inspect`, the `/page` budget + 10 s on `/page`.
- **SNI:** the host name, none for an IP address or a non-ASCII host.

If the probe fails, the chain crypto/tls attached to the verification error is
used (`certSource: "verify-error"`, no protocol or cipher, `probeError` set); if
there is none, `ssl` is `null`. Servers Go cannot handshake with even when
skipping verification are described that way or not at all: certificates with a
negative serial number, RSA keys below 1024 bit, SHA-1 handshake signatures in
TLS 1.2, and SSLv3.

### HTTPS pages calling HTTP localhost

Browsers treat `http://127.0.0.1` as a **"potentially trustworthy origin"** (W3C Secure Contexts spec). Requests from an HTTPS page to the local proxy are **not blocked** as mixed content.

Chrome replaces Private Network Access with **Local Network Access**: the first
time an HTTPS page talks to `127.0.0.1`, Chrome asks you whether the site may
access devices on your local network. Allow it for the tool's site; you can
change the decision later in the site settings. `Access-Control-Allow-Private-Network`
(still sent) does not replace this prompt. The prompt only covers the page
talking to the proxy — not what the proxy sends on with `--allow-local`.
<!-- TODO(LNA hand test): confirm Chrome's exact prompt and setting labels. -->

---

## Concurrency

The proxy handles **multiple requests concurrently**. Go's `net/http` server spawns a goroutine per incoming connection. Each upstream request uses a fresh connection (`DisableKeepAlives`) so that `httptrace` captures accurate DNS, TCP, TLS timing and the resolved IP on every request. HTTP/2 is negotiated automatically via TLS ALPN when supported by the upstream server.

---

## Compression

**`/proxy`:** Brotli, gzip, and deflate are supported **transparently**. The proxy forwards the browser's `Accept-Encoding` header to the upstream server and streams the compressed response bytes back. The browser handles decompression.

**`/inspect?body=1` and `/page`:** The proxy first sends a HEAD request with the browser's full `Accept-Encoding` to detect the server's preferred compression (e.g. `zstd`, `br`), then a GET with `Accept-Encoding: gzip, deflate` to obtain a body that can be decompressed with Go's stdlib. The body is decompressed before embedding it in the JSON response. The `Content-Encoding` header in the `headers` map reflects the server's true preferred encoding from the HEAD probe, so consumers accurately detect compression support. The HEAD is untraced: reported timing and IP belong to the GET.

**Undecodable bodies:** the `Content-Encoding` value falls into one of three classes (tokens are case-insensitive, `identity` is ignored):

| `Content-Encoding` | Result |
|---|---|
| `gzip`, `x-gzip`, `deflate` (a single token) | Decoded |
| A registered coding Go's stdlib cannot decode — `br`, `zstd`, `compress`, `x-compress`, `dcb`, `dcz`, `aes128gcm`, `exi`, `pack200-gzip` ([IANA registry](https://www.iana.org/assignments/http-parameters/http-parameters.xhtml#content-coding)) — or a stack of several tokens (`gzip, br`) | `decodeError: true`, empty `html` / `body` |
| Any other token (`none`, `UTF-8`, `text/html`, `binary`, …) — a server misconfiguration seen on real sites | Treated as a mislabelled plain body: passed through unchanged when it is valid UTF-8 (as in v1.2.4); otherwise `decodeError: true` and an empty `html` / `body` |

A corrupt gzip/deflate stream yields `decodeError: true` and only what could be decoded. Raw compressed or binary bytes are never handed on as text (before v1.3.0 a `br` or `zstd` body ended up in `html` / `body` as binary garbage). Because a valid-UTF-8 check decides the third class, a mislabelled page in a legacy charset (e.g. ISO-8859-1 with umlauts) also gets `decodeError: true`.

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

Requires [Go 1.27+](https://go.dev/dl/). If Go is not yet installed:

```bash
# Linux (amd64)
wget https://go.dev/dl/go1.27.3.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.27.3.linux-amd64.tar.gz
rm go1.27.3.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc  # or ~/.zshrc
source ~/.bashrc

# macOS (Apple Silicon)
wget https://go.dev/dl/go1.27.3.darwin-arm64.tar.gz
sudo tar -C /usr/local -xzf go1.27.3.darwin-arm64.tar.gz
rm go1.27.3.darwin-arm64.tar.gz
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
git tag v1.4.0
git push origin v1.4.0
```

This cross-compiles binaries for all platforms, writes `SHA256SUMS` for the nine
binaries (and checks it), and creates a **draft** GitHub Release with all of
them (since v1.4.0). Hand-written notes in `.github/release-notes/<tag>.md` are
used as the release text when present, followed by GitHub's generated list of
changes. Download and test the binaries from the draft, then publish it.

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

Since v1.3.0 the suite also builds its own test PKI (root, intermediate, leaf
certificates with RSA, ECDSA and Ed25519 keys, plus an MD5-signed fixture) and
runs **real TLS servers** via `httptest` against it:

- **Certificate report:** OpenSSL names for protocols, cipher suites (the table
  is checked against every suite Go implements) and signature algorithms; DN
  formatting; chain labels and signature checks (incl. SHA-1 and MD5);
  RFC 6125 host matching; every `issues` rule and message.
- **TLS verdicts:** expired, not yet valid, wrong host, self-signed, untrusted
  root, incomplete chain, TLS 1.0-only server and plain HTTP behind `https://`,
  each classified from a real failing handshake.
- **Diagnostic probe:** sends no application data, sets SNI correctly, is
  blocked by the default dialer guard, reaches legacy servers (TLS 1.0 with RSA
  key exchange, 3DES, RC4); the upstream client never skips verification.
- **Endpoints:** `/inspect` with and without `diag=1`, HEAD→GET fallback,
  headers-only GET (`get=1`), `location`, body truncation and undecodable encodings; `/page` hop fallback,
  TLS failures, the hop limit, every chain-stop category, final-GET timeout,
  truncation, corrupt gzip, mislabelled plain bodies (`Content-Encoding: none`,
  `UTF-8`), hop certificate summary and the status line in `rawHeaders`;
  `/proxy` never forwarding `Location`, truncation of compressed chunked
  bodies, and `follow=1` (relative targets, HEAD, blocked hop, loop, hop limit,
  `javascript:` targets, POST).
- **Errors and helpers:** timeout detection, RFC 3986 redirect resolution (all
  §5.4 examples), capped reads and UTF-8-safe truncation.

Since v1.4.0:

- **Golden test** (`compat_golden_test.go`): a fixed request matrix — the call
  patterns of the seven JPKCom tools, every error path, preflights, `main()`
  with and without flags — against `httptest` targets; every response (status,
  headers, body) is compared with a file under `testdata/golden/`. The files
  were recorded with v1.3.0; only the differences listed in the v1.4.0 changelog
  may appear. Run `go test -run TestCompat_Golden -update` **only on purpose**,
  and review the diff of `testdata/golden/` line by line before committing it.
- **Target authentication** (`target_auth_test.go`): header form, origin
  binding, redirect stops, method and `_method` guards on every hop, https
  rule, header allowlist, cache headers, userinfo, and that no credential ever
  reaches a log, a header or a body.
- **Local targets** (`main_test.go`, `local_attack_test.go`): the
  `--allow-local` parser, matching, rebinding, fixed blocks, redirects into
  local targets, all endpoints, `reason` values, no connection reuse.
- **Capabilities and token** (`cap_tok_test.go`, `tokenfile_unix_test.go`):
  `/version` fields and `proof` test vectors, the token probe, `--token-file`
  (create and reuse, content, permissions, symbolic links, concurrent starts,
  banner).

None of the tests needs network access.

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
# One-time install (binary lands in $(go env GOPATH)/bin), built in a
# throwaway module so golang.org/x/tools can be raised — see below
d=$(mktemp -d) && cd "$d" && go mod init staticcheck-build \
  && go get honnef.co/go/tools/cmd/staticcheck@v0.8.1 golang.org/x/tools@v0.51.0 \
  && go install honnef.co/go/tools/cmd/staticcheck && cd - && rm -rf "$d"

# Run on the project
staticcheck ./...
```

Make sure `$(go env GOPATH)/bin` is on your `$PATH`. `staticcheck` is a
dev tool only — it is not part of the runtime dependencies and never
ships with the binary.

A plain `go install honnef.co/go/tools/cmd/staticcheck@v0.8.1` is not enough
on Go 1.27.2 and later: these toolchains write export data version 5, while staticcheck
v0.8.1 (2026.2.1) still requires `golang.org/x/tools` v0.44, which reads only up
to version 4 and aborts with `export data version 5 is greater than maximum
supported version 4` on every stdlib import. `golang.org/x/tools` v0.51.0 reads
version 5, but `go install pkg@version` cannot override a dependency, hence the
throwaway module. CI uses the same recipe. Once a staticcheck release requires
x/tools v0.51.0 or newer, a plain `go install` works again.

---

## Changelog

### v1.4.0 (unreleased)

Feature release for the **WP REST API Explorer** of the JPKCom Tools:
credentials for the target, local and staging sites, feature detection and a
persistent token. Same toolchain as v1.3.0 (Go 1.27.3); no new dependencies.

**Upgrade:** no new flags needed — unless you want local targets
(`--allow-local`) or a token that survives a restart (`--token-file`).

**New**

- **Target authentication** on `/proxy`: `X-Target-Authorization`
  (`Basic …` or `Bearer …`) plus the required `X-Target-Origin`. Only GET and
  HEAD, no method overrides (`_method`, `X-HTTP-Method-Override`) on any hop,
  only to the exact origin (a redirect to another origin ends the chain with
  `X-Upstream-Auth: withheld-cross-origin`), only over HTTPS except to an
  `--allow-local` target on loopback, `no-store`, a header allowlist, never
  logged. New response headers `X-Upstream-Auth` and `X-Upstream-Cache-Control`.
  See [Target authentication](#target-authentication-since-v140).
- **`--allow-local "<list>"`**: reach listed local targets (DDEV, wp-env,
  intranet). Names reach loopback only, LAN addresses only through an IP or
  CIDR entry; narrow wildcards; dangerous ports and fixed blocks refused; needs
  `--origin` with https origins, not with `--allow-any-host`; enforced in the
  dialer (rebinding-proof); no redirects from public into local targets; all
  endpoints. See [`--allow-local`](#--allow-local-local-and-staging-sites-since-v140).
- **`--token-file <absolute path>`**: the token survives a restart. Atomic
  creation, `0600`, checks of the file and of every folder on its path like
  ssh. See
  [`--token-file`](#--token-file-keep-the-token-across-restarts-since-v140).
- **`/version`** reports `capabilities`, `localTargets`, `tokenPersistent` and
  `limits`; **`/version?challenge=<64 hex>`** answers with `proof`
  (HMAC-SHA256 with the token over port and challenge), so a tool can check
  that its proxy — not another program on that port, and not one relaying to
  the proxy on another port — answers before it sends the token.
- **Error `auth_refused`** (400) and the field **`reason`** on `auth_refused`
  and `blocked_target` (`private`, `not_allowlisted`, `always_blocked`,
  `redirect_into_local`, `unsupported_scheme`), on `/page` also per hop
  (`errorReason`). See [Error responses](#error-responses).
- **Token probe as a contract:** `GET /inspect` with `X-Proxy-Token` and
  without `url` answers `400 bad_request` for a valid token and `403 forbidden`
  for an invalid one, without contacting anything.
- **Banner:** a `WARNING` line for arguments left over after the flags (they and
  every flag after them were always ignored); with `--allow-local` or
  `--token-file` such leftovers are a start-up error (quote the list).
- **Releases:** `SHA256SUMS` for all nine binaries; the release is created as a
  draft and published by hand.

**No behaviour change for existing tools.** Without the new headers and flags
every endpoint answers as in v1.3.0, except for these additive differences:

1. `Access-Control-Allow-Headers` is `Content-Type, X-Proxy-Token,
   X-Target-Authorization, X-Target-Origin` (all endpoints).
2. `/proxy` responses carry a second `Vary: X-Target-Authorization`.
3. `/version` has the additional keys `capabilities`, `localTargets`,
   `tokenPersistent` and `limits`; the old keys are unchanged strings.
4. `blocked_target` errors carry `reason` (on `/page` also the hop field
   `errorReason`).

A golden test records the v1.3.0 answers and checks exactly this.

**Security fixes** (only edge cases change):

5. **Userinfo in the `url`** (`https://user:pass@host/`) now counts as
   credentials: it is removed from the URL before any request and never
   appears in `X-Upstream-Final-URL`, JSON or the log; POST and writing method
   overrides with it are refused (`auth_refused`); `/proxy` answers with
   `no-store` and `X-Upstream-Auth`. GET and HEAD authenticate as before, now
   also on same-origin redirect hops. On every endpoint such a request only
   passes the browser headers `Accept`, `Accept-Language`, `Accept-Encoding`,
   `User-Agent`, `Cache-Control` and `Pragma` to the target (the allowlist
   for credentials); custom headers are dropped.
6. **Forged metadata:** `X-Upstream-*` headers sent by the target are dropped,
   also in underscore spelling (`X_Upstream_Auth`). So are `X-Target-Authorization`
   and `X-Target-Origin` in a target's response (like `X-Proxy-Token` since
   v1.3.0: the proxy's own header names are hop-by-hop in both directions).
   Request headers in underscore spelling of blocked names (`X_Proxy_Token`,
   `Sec_Fetch_Site`, …) are treated like the hyphen form.

### v1.3.0

Feature release: **parity with the PHP proxy of the JPKCom Tools** (`proxy.php`
2.8.0) for SSL-certificate and redirect information, so the tools' Expert Mode
shows the same details as their server-side mode. Same toolchain as v1.2.4
(Go 1.27.3); no new dependencies.

**Release order — deploy the tools first.** `/proxy` no longer forwards
`Location` (see below). The updated JPKCom Tools frontend works with older
proxies as before (unknown query parameters such as `follow=1`, `diag=1` and
`get=1` are ignored, every new field is feature-detected), but following
redirects needs v1.3.0: with an older proxy the browser still follows a 3xx
from `/proxy` to the target itself, and a redirect to another site fails at the
CORS preflight ("Failed to fetch"), exactly as with the previous frontend.
Publish the frontend first, then this release; the frontend's `MIN_VERSION`
moves to `v1.3.0`.

**New**

- **Full certificate report** on `/inspect` and `/page` (`ssl`): every chain
  entry gets position, label (`Server certificate`, `Intermediate CA`,
  `Root CA (self-signed)`, `Cross-signed root (acts as intermediate)`), whether
  the next certificate signed it, subject/issuer DN and organisation, validity
  as text and Unix time, serial, OpenSSL signature-algorithm name, key
  description, SANs, SHA-256/SHA-1 fingerprints and PEM. The report adds
  `protocol` and `cipher` in OpenSSL notation (`TLSv1.3`,
  `ECDHE-RSA-AES128-GCM-SHA256`), `cipherSuite` (IANA), `bits`, `verified` /
  `valid`, `error` / `errorType`, `hostMatch` (RFC 6125), `selfSigned`,
  `issues` (the PHP rule set and messages) and `certSource`. See
  [`ssl` object](#ssl-object).
- **`diag=1`** on `/inspect` and `/page`: a certificate checker needs details
  exactly when verification fails. With `diag=1`, `/inspect` reports an upstream
  failure inline (HTTP 200, `error` object), and a `tls_error` on either
  endpoint runs a handshake-only [TLS diagnostic probe](#tls-diagnostic-probe)
  that fills `ssl` with what the failing server presented — also for servers
  stuck on TLS 1.0/1.1, 3DES or RC4. Without `diag`, the 502/504 contract is
  unchanged.
- **`type` on error responses**: a human-readable class with the PHP proxy's
  texts (`Certificate expired`, `Could not resolve host`, …), set on every
  upstream failure. See [Error responses](#error-responses).
- **`follow=1` on `/proxy`** (GET and HEAD): the proxy follows up to 5
  redirects itself, each target SSRF-checked, and reports
  `X-Upstream-Final-URL` and `X-Upstream-Redirects`. See
  [Redirects on `/proxy`](#redirects-on-proxy).
- **`X-Upstream-Location`** on every 3xx from `/proxy`: the resolved, absolute
  redirect target.
- **`/inspect`**: `method`, `location` (resolved 3xx target), and with
  `body=1` `truncated`, `maxBodySize` and `decodeError`. **`get=1`** takes
  the headers from a GET (body closed unread) instead of a HEAD, as the PHP
  proxy's headers-only fetch does — some servers, e.g. `www.google.com`, send
  `Strict-Transport-Security` only on GET.
- **`/page`**: hops gain `method`, `location`, `errorCategory`, `errorType` and a
  certificate summary (`certCN`, `certExpiry`, `certDaysLeft`); the response
  gains `truncated`, `maxBodySize` and `decodeError`.

**Behaviour changes**

All JSON changes are additive — no key was renamed, removed or retyped — but
some values and statuses change:

- **`/proxy` never forwards `Location`.** The browser's `fetch()` followed it
  straight to the target, carrying `X-Proxy-Token` in a preflighted CORS request
  — leaking the token wherever the target's CORS policy let it through, and
  failing with "Failed to fetch" or a proxy-local 404 everywhere else. A 3xx now
  reaches the caller as such, with `X-Upstream-Location`; pass `follow=1` to have
  the proxy follow it.
- **Timeouts are reported as `timeout` (504) on every endpoint**, including dial,
  TLS-handshake and response-header timeouts, which used to be
  `connection_error` or `upstream_error` (502); a DNS lookup that times out
  (e.g. an unreachable `--dns` server) used to be `dns_error` (502). On `/page`
  this also applies to hop errors and the final GET, whose `error.status` was
  always 502.
- **`/page` reports the real error code.** A chain failure used to arrive as
  `upstream_error` whatever happened; now `error.error` is the failed hop's
  `errorCategory` (`tls_error`, `dns_error`, `timeout`, `redirect_loop`,
  `too_many_redirects`, `blocked_target`, …), with `status` 504 for a timeout.
  On a failure `ip` names the server that failed.
- **`/page` stops when a 21st redirect follows** with a `too_many_redirects`
  hop; exactly 20 redirects still reach the final page. Before, the request
  after the 20th redirect was fetched as the final page even if it redirected
  again.
- **`/page` treats an unusable `Location` as an error.** An unparseable value
  (`bad_request`) or a non-http(s) scheme (`blocked_target`) ends the chain;
  before, the tracer stopped silently and fetched the redirecting URL again as
  the final page.
- **HEAD→GET fallback:** `/inspect` and every `/page` hop repeat a request that
  the server refused with 405 or 501 as GET (headers only, body closed unread),
  as the PHP proxy does.
- **`rawHeaders`** (top level and per hop) starts with the status line
  (`HTTP/1.1 301 Moved Permanently`, `HTTP/2 200`) and lists headers sorted by
  name; Go's map order made it differ from call to call.
- **No more binary `html` / `body`:** a response in a registered coding Go
  cannot decode (`br`, `zstd`, `compress`, `dcb`, `dcz`, …), in stacked codings
  (`gzip, br`), or a corrupt gzip/deflate stream now gives `decodeError: true`
  and only the decoded text. Before, the raw compressed bytes were returned as
  the page. An unregistered token (`Content-Encoding: none`, `UTF-8`, …) still
  passes a plain body through as before, but only if it is valid UTF-8;
  binary bytes behind such a token now give `decodeError: true` and an empty
  body. See [Compression](#compression).
- **Truncated bodies** (`/page` `html`, `/inspect` `body`) are cut on a UTF-8
  character boundary and flagged with `truncated: true`.
- **`daysLeft` is floored**, matching the PHP proxy (differs only for expired
  certificates, which earlier versions never reported). It is computed on whole
  Unix seconds, so a `NotAfter` of 9999-12-31 (RFC 5280's "no expiration") is
  no longer capped at 106751 days.
- **`ssl.chain` lists at most 10 certificates** (earlier versions listed every
  certificate the server sent).
- **`chain[].subject` / `issuer`** fall back to the organisation, then
  `"Unknown"`, when a certificate has no CN (was `""`).

**Security**

- **Token leak via `Location` closed** (see above).
- **Handshake-only TLS probe.** This is the one place the proxy skips
  certificate verification, and it is deliberately narrow: only with `diag=1`
  after a `tls_error`, only to the IP the failed request had already connected
  to, through the same `safeDialControl` SSRF guard, bounded to 10 s, and the
  connection never carries application data. Every connection that carries HTTP
  data stays verified; tests enforce both rules. See
  [TLS diagnostic probe](#tls-diagnostic-probe).
- **Redirect targets** followed by `/proxy?follow=1` and `/page` must be
  http/https; userinfo is dropped, and each target passes the SSRF pre-check
  before it is requested.

**Fixes**

- `X-Upstream-IP` and `ip` could name the wrong server: with Happy Eyeballs, a
  losing dial's late `ConnectDone` overwrote the winner's address. Only a
  successful connect is recorded now.
- `/inspect?body=1` timing included the HEAD encoding probe; it now describes
  the GET alone.
- The specific certificate messages ("TLS certificate signed by unknown
  authority", "TLS certificate invalid", "TLS certificate hostname mismatch")
  were unreachable, because the wrapping `*tls.CertificateVerificationError` was
  tested first; every certificate failure read "TLS certificate verification
  failed".
- An `https://` URL pointing at a plain-HTTP server was still reported as
  `upstream_error`: `http.Client` reports that case as `http.ErrSchemeMismatch`
  rather than the `tls.RecordHeaderError` that v1.2.1 handled. It is a
  `tls_error` ("TLS protocol not supported") now.
- `/proxy` cut a compressed chunked body (`Content-Encoding` set, no
  `Content-Length`) at `--max-mb` without saying so. It now sets
  `X-Upstream-Truncated: 1`, and `X-Upstream-Content-Length` is the capped
  size.

**Known limitations**

- `X-Upstream-Truncated` is not set for a chunked `/proxy` body **without**
  `Content-Encoding`: that body is streamed, so the headers are already sent
  when the cap cuts it. A body with `Content-Length`, and a compressed chunked
  body (buffered before the headers go out), are flagged.
- The diagnostic probe cannot describe servers Go refuses to handshake with even
  without verification (negative serial numbers, RSA keys below 1024 bit, SHA-1
  handshake signatures in TLS 1.2, SSLv3); `ssl` then comes from the
  verification error or stays `null`.
- Internationalised host names must arrive in punycode for `hostMatch` and the
  probe's SNI; the standard library has no IDNA.

**Tests**

- New test PKI with real `httptest` TLS servers, covering the certificate
  report, every TLS verdict, the probe's guarantees, and the new `/inspect`,
  `/page` and `/proxy` behaviour — see [Testing](#testing). All earlier tests
  pass unchanged apart from `extractSSLInfo` gaining its host argument.

**Build & CI**

- No toolchain change: Go 1.27.3, CI pin `go-version: "1.27"`
- `gofmt`, `go vet`, `staticcheck`, `govulncheck` and `go test -race` pass

### v1.2.4

**Security release.** Toolchain-only: no changes to `main.go` or `main_test.go`,
no client-side adjustments needed. Built with **Go 1.27.3** (2026-10-19), an
[URGENT-track](https://go.dev/doc/security/policy#urgent) release with a single
security fix to `crypto/x509`. Every earlier binary is affected — please update.

**CVE-2026-111943 — distrusted intermediate certificates
([go.dev/issue/82345](https://go.dev/issue/82345)).** Go now blocks trust in a
small set of intermediate CA certificates "due to specific security concerns
around their operation". `Certificate.Verify` drops every chain that contains
one of them, matched by the SHA-256 hash of the certificate's public key (SPKI).
The filter applies on every platform: the pure-Go verifier (Linux, BSD) and the
macOS and Windows platform verifiers alike.

**Relevant — the proxy verifies the certificate of every target.** TLS
verification is always on, so all three endpoints (`/proxy`, `/inspect`,
`/page`) rely on `crypto/x509` to decide whether a target is trustworthy. Before
this release, a certificate issued through one of these intermediates was
accepted as valid. `/inspect` and `/page` also reported it as valid in their SSL
details. Now the handshake fails and the client gets a `tls_error` with the
message "TLS certificate verification failed". The error format is unchanged.

*Corrected in v1.3.0:* this note originally named the message "TLS certificate
invalid". The underlying error is an `x509.CertificateInvalidError`, but the
v1.2.4 classifier tested the wrapping `*tls.CertificateVerificationError` first,
so only the generic message was reachable. From v1.3.0 on, the specific x509
checks run first: the message is "TLS certificate invalid" and `type` is
"TLS/SSL error".

`govulncheck` does not flag this yet: at release time the Go vulnerability
database had no entry for CVE-2026-111943, so the scan is clean on 1.27.2 and
1.27.3 alike. The upgrade follows the Go team's announcement, not a scanner
finding.

**Build & CI**

- `go.mod` go directive bumped from `go 1.27.2` to `go 1.27.3`
- CI pin stays `go-version: "1.27"` and resolves to 1.27.3 automatically
- The staticcheck recipe (v0.8.1 against `golang.org/x/tools` v0.51.0) works
  unchanged on 1.27.3
- `gofmt`, `go vet`, `staticcheck`, `govulncheck`, `go test -race` and
  cross-compilation for all release targets pass on Go 1.27.3

### v1.2.3

**Security release.** Toolchain-only: no changes to `main.go` or `main_test.go`,
no client-side adjustments needed. Built with **Go 1.27.2** (2026-10-08), which
carries security fixes to the `go` command and to `crypto/tls`, `html/template`,
`net/http`, `net/textproto` and `os`. Every v1.2.x binary built with Go 1.27.0
or 1.27.1 is affected — please update.

`govulncheck` against the 1.27.1 standard library reports nine advisories whose
symbols this binary reaches, plus four in imported packages that the code does
not call. With 1.27.2 it reports none. Reachable symbols do not mean every one
of them can be triggered against the proxy. Assessed against its actual setup —
an HTTP/1-only server on loopback, and an HTTP/2-capable client to arbitrary,
user-supplied targets:

**Relevant — the proxy is the HTTP/2 client of a potentially hostile target**

- **GO-2026-6610 / CVE-2026-78660 — HTTP/2 transport accepted malformed
  framing-related headers.** An HTTP/2 response could carry malformed
  framing-related headers such as `Content-Length`. `/proxy` forwards the
  target's `Content-Length` to the browser over HTTP/1, which is exactly the
  response-smuggling pattern the advisory describes for proxies.
  (`Transfer-Encoding` was already stripped as a hop-by-hop header.) With 1.27.2
  such a response fails as an upstream error and is no longer passed through.
- **GO-2026-6611 / CVE-2026-78669 — CPU exhaustion from repeated
  `SETTINGS_INITIAL_WINDOW_SIZE` changes.** This affects HTTP/2 clients as well as
  servers. A malicious target could keep the proxy busy for the length of a
  request. The per-request timeout limited this; it is now fixed outright.

**Reachable in the call graph, not exploitable in this setup**

- **HTTP/2 server issues** — GO-2026-6617 (HPACK encoder race → crash),
  GO-2026-6612 (double flow-control refund), GO-2026-6603 (memory exhaustion via
  `Trailer`). The proxy serves plain HTTP on `127.0.0.1` without TLS and does not
  enable unencrypted HTTP/2, so its server never speaks HTTP/2.
- **CONNECT desync** — GO-2026-6613 (server, 2xx to CONNECT) and GO-2026-6605
  (client, CONNECT with a body). The proxy rejects CONNECT with 405 and never
  sends it upstream; only GET, HEAD and POST are accepted.
- **GO-2026-6607 — ECH outer extensions (`crypto/tls`)**: server-side
  ClientHello decoding. The proxy is only ever a TLS client.
- **GO-2026-6608 — MIME header memory limit (`net/textproto`)**: triggered by
  multipart form parsing, which the proxy does not do. `net/textproto` also sits
  in the HTTP/1 header path, so the fix applies there too.

**Not reached** — GO-2026-6609 (`Range` parsing in `ServeContent`/`ServeFile`),
GO-2026-6604 (`os.Root` junctions, Windows), GO-2026-6599 and GO-2026-6600
(`html/template`). The `go` command fix affects building only. CI builds this
repository's own stdlib-only code and fetches no third-party modules into the
binary.

**Build & CI**

- `go.mod` go directive bumped from `go 1.27.1` to `go 1.27.2`
- `govulncheck` reports no findings on the 1.27.2 toolchain (nine reachable
  advisories on 1.27.1)
- CI pin stays `go-version: "1.27"` and resolves to 1.27.2 automatically
- **staticcheck build fixed for Go 1.27.2.** The toolchain writes export data
  version 5, and staticcheck v0.8.1 still pins `golang.org/x/tools` v0.44, which
  stops at version 4. Without this fix the `verify` job fails on every push. CI
  now builds staticcheck v0.8.1 in a throwaway module against `golang.org/x/tools`
  v0.51.0 (replacing the `v0.8.0-rc.1` pin). See [Linting](#linting).
- `gofmt`, `go vet`, `staticcheck`, `go test -race` and cross-compilation for
  all release targets pass on Go 1.27.2

### v1.2.2

Toolchain-only release: no code changes, no behaviour changes, no client-side
adjustments needed. Built with **Go 1.27.1** (2026-09-01), a regular bug-fix
point release — explicitly **not** a security release, it carries no CVE fix.
The move keeps the binaries on the current patch level of the 1.27 series.

Of the twelve backported fixes, three touch packages the proxy imports; none of
them has an observable effect on it:

- **`net/http` — Go issue #81027.** Since 1.27.0, `Request.Body.Close` on the
  server side returned `io.EOF` instead of `nil` when a handler left part of the
  body unread (a refactor dropped the line that cleared it). `/proxy` hands the
  incoming POST body to the upstream request, and the transport closes it
  without checking that error on its failure paths — so the regression was
  invisible here. Fixed nonetheless.
- **`encoding/json` — Go issues #81083 and #81012.** A quoted `null` was
  rejected for fields tagged `,string`, and `Decoder.Token` lost
  `io.ErrUnexpectedEOF` after the move to the v2 backend. Both are decoding
  paths; the proxy only *encodes* JSON, and uses neither `,string` tags nor
  `Decoder.Token`.

The rest does not apply: `database/sql`, `debug/elf` and `simd` are not
imported; the compiler fixes cover generic methods on alias receivers and
s390x/arm64 SIMD code generation, and the `go fix` fixes touch a build-time
tool only.

**Build & CI**

- `go.mod` go directive bumped from `go 1.27.0` to `go 1.27.1`
- `govulncheck` reports no findings on the 1.27.1 toolchain
- CI pin stays `go-version: "1.27"` and resolves to 1.27.1 automatically

### v1.2.1

**Fixed — TLS handshake failures were misreported**

`classifyUpstreamError` only recognised *certificate* problems as
`tls_error`. Every other way a TLS handshake can fail was mislabelled, so the
frontend could not tell "this host is unreachable" from "this host and I cannot
agree on TLS":

| Target | Before | Now |
|---|---|---|
| Server stuck on TLS 1.0 / 1.1 | `upstream_error` | `tls_error` |
| No mutually supported cipher suite | `connection_error` | `tls_error` |
| Peer alert (`handshake_failure`, `certificate_required`, …) | `connection_error` | `tls_error` |
| Plain HTTP server behind an `https://` URL | `upstream_error` | `tls_error` |
| Connection refused / reset, DNS, certificates | *unchanged* | *unchanged* |

Two separate causes, because `errors.As` cannot see either one:

- `crypto/tls` delivers peer alerts as a `*net.OpError` with `Op` set to
  `"remote error"` or `"local error"`, wrapping the **unexported** `tls.alert`
  type — the exported `tls.AlertError` never matches, so `Op` is the only usable
  marker. These were being swallowed by the generic `*net.OpError` check.
- Failures the client rejects locally are bare `fmt.Errorf` values with no type
  whatsoever (261 of them in Go 1.27), such as
  `tls: server selected unsupported protocol version 301`. The only marker left
  is the package-wide `tls: ` message prefix, which is read off the *innermost*
  error — never the flattened chain, because the wrapping `*url.Error` contains
  the caller-supplied URL and a crafted query string could otherwise forge a TLS
  verdict.

Verified against real failing handshakes (`httptest` in the test suite, plus
badssl.com endpoints end-to-end); certificate, DNS, SSRF and genuine socket
errors keep their existing codes.

Note this only affects the `error` **code**. HTTP status stays 502 and the
`message` field remains display-safe, so no frontend change is required.

*Corrected in v1.3.0:* the "Plain HTTP server behind an `https://` URL" row only
held for a bare TLS handshake. Through `http.Client` that case surfaces as
`http.ErrSchemeMismatch` and stayed `upstream_error` until v1.3.0.

### v1.2.0

Toolchain release: the proxy moves to **Go 1.27.0** (2026-08-19). No code
changes, no API changes, no client-side adjustments — every endpoint, field and
error code behaves exactly as in v1.1.1.

This is explicitly **not** a security release. Go 1.27.0 carries no stdlib fix
that was not already in Go 1.26.6; the ten-CVE batch documented under v1.1.1
shipped in both. `govulncheck` reports no findings on either toolchain. The
reason to move is that Go 1.26 reaches end of life when Go 1.28 lands (~February
2027), and 1.27 is where the fixes will arrive from now on.

**Breaking for macOS 12 users**

- Go 1.27 discontinued support for macOS 12 Monterey and older; the darwin
  binaries now require **macOS 13 Ventura or later**. On an older macOS, stay on
  [v1.1.1](https://github.com/JPKCom/proxy-jpkcom-dev-tools/releases/tag/v1.1.1)
  — it is functionally identical. No other platform in the release matrix
  changed its minimum requirement.

**Behaviour changes inherited from the toolchain**

- **`crypto/x509` on macOS and Windows** now honours `SSL_CERT_FILE` and
  `SSL_CERT_DIR`. When either is set, roots are read from disk and verification
  switches from the platform APIs to the pure-Go verifier. This is the one
  change that can alter what `/inspect` and `/page` report about a certificate
  chain — but only for users who have those variables exported (corporate MITM
  proxies, Homebrew OpenSSL setups). `GODEBUG=x509sslcertoverrideplatform=0`
  restores the old behaviour. Linux was already reading these variables.
- **ML-DSA signature schemes** (`MLDSA44/65/87`, FIPS 204) are now advertised by
  default in TLS 1.3 ClientHellos. Verified against TLS 1.3 and TLS 1.2-only
  targets with no interop change; the negotiated suite and everything `/inspect`
  reports under `ssl` are unaffected.
- **HTTP/1 response bodies are auto-drained on `Close`**, capped at 256 KB and
  50 ms, to improve connection reuse. It runs in the transport's background read
  loop and never blocks the handler — `Close` returns in microseconds either way
  (measured). The drain is skipped when `Content-Length` is above 256 KB, but a
  **chunked** response reports `Content-Length: -1` and therefore passes that
  gate: aborting a chunked body early — which is exactly what the `--max-mb`
  truncation path does — now pulls up to ~256 KB more from the target in the
  background before the connection is dropped. Bounded, off the critical path,
  and invisible in the response, but it is extra upstream traffic that Go 1.26
  did not generate. `DisableKeepAlives` does not suppress it; `ForceAttemptHTTP2`
  keeps most HTTPS targets on h2, which never enters this loop at all.
- **`net/http` servers cap header values at 500 per request**
  (`DefaultMaxHeaderValueCount`). Inbound hardening on the local listener only;
  no browser request comes close.
- Legacy TLS escape hatches are gone for good: the `tlsrsakex`, `tls3des`,
  `tls10server`, `tlsunsafeekm` and `x509keypairleaf` GODEBUG settings were
  removed. All had been off by default since Go 1.22/1.23, so nothing changes in
  practice — a target that only speaks RSA key exchange or 3DES was already
  unreachable.
- `encoding/json` is now backed by the v2 implementation. Output is unchanged:
  HTML escaping, sorted map keys, `null` for nil slices and U+FFFD replacement
  for invalid UTF-8 in header values all verified identical. Only the text of
  internal error messages may differ, and those are never sent to the client.

**Build & CI**

- `go.mod` go directive bumped from `go 1.26.6` to `go 1.27.0`
- CI pin moved from `go-version: "1.26"` to `"1.27"` in both jobs
- `staticcheck` is now pinned to `@v0.8.0-rc.1` instead of `@latest`: the current
  stable release (2026.1 / v0.7.0) cannot read Go 1.27 export data and aborts on
  every stdlib import. Revert to `@latest` once 2026.2 is stable.
- `gofmt`, `go vet`, `staticcheck`, `govulncheck` and the full test suite pass on
  1.27.0 with no source changes

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
