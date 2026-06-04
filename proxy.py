from mitmproxy import http
from mitmproxy.proxy.layers import tls
import os

# Load blocked domains from hosts.txt
BLOCKED_DOMAINS = set()

def load_blocked_domains():
    """Load domains from hosts.txt file"""
    global BLOCKED_DOMAINS
    hosts_path = os.path.join(os.path.dirname(__file__), "hosts.txt")

    try:
        with open(hosts_path, "r") as f:
            for line in f:
                line = line.strip()
                # Skip empty lines and comments
                if line and not line.startswith("#"):
                    # Extract domain (handle format: "0.0.0.0 domain.com" or just "domain.com")
                    parts = line.split()
                    domain = parts[-1] if parts else line
                    BLOCKED_DOMAINS.add(domain.lower())
        print(f"[+] Loaded {len(BLOCKED_DOMAINS)} blocked domains from hosts.txt")
    except FileNotFoundError:
        print(f"[!] WARNING: hosts.txt not found at {hosts_path}")
    except Exception as e:
        print(f"[!] ERROR loading hosts.txt: {e}")

# Load domains when script initializes
load_blocked_domains()

def is_blocked(hostname: str) -> bool:
    """Check if hostname matches any blocked domain"""
    hostname_lower = hostname.lower()
    for blocked in BLOCKED_DOMAINS:
        if blocked in hostname_lower:
            return True
    return False

def tls_clienthello(data: tls.ClientHelloData) -> None:
    if data.context.server.address:
        hostname = data.context.server.address[0]

        # Block domains at TLS layer
        if is_blocked(hostname):
            raise ConnectionRefusedError(f"[*] Blocked HTTPS connection to: {hostname}")


def request(flow: http.HTTPFlow) -> None:
    """Handle HTTP/HTTPS requests after TLS handshake"""
    hostname = flow.request.pretty_host
    proxyServerIP = flow.client_conn.sockname[0].encode("UTF-8")

    # Special handling for Netflix - corrupt the response
    if "netflix" in hostname:
        flow.response = http.Response.make(
            200,
            b"uwu",  # probably don't need this many uwus. just corrupt the response
            {"Content-Type": "application/x-msl+json"}
        )
        print(f"[*] Corrupted Netflix response for: {hostname}")
        return

    # Block other domains from hosts.txt
    if is_blocked(hostname):
        flow.response = http.Response.make(
            404,
            b"uwu",
        )
        print(f"[*] Blocked HTTP request to: {hostname}")
        return

    BASE = os.path.dirname(__file__)
    FILE_MAP = {
        "/js/common/config/text/config.text.lruderrorpage": ("inject_elfldr_automated.js",   True),
        "/js/lapse.js":                                     ("payloads/lapse.js",            True),
        "/js/elf_loader.js":                                ("payloads/elf_loader.js",       True),
        "/js/p2jb.js":                                      ("payloads/p2jb.js",             True),
        "/js/remote_js_loader.js":                          ("payloads/remote_js_loader.js", True),
        "/js/ps4/inject_auto_bundle.js":                    ("PS4/inject_auto_bundle.js",    True),
        "/js/elfldr.elf":                                   ("payloads/elfldr.elf",          False),
        "/js/elfldr-ps5.elf":                               ("payloads/elfldr-ps5.elf",      False),
        "/js/kexp.bin":                                     ("payloads/kexp.bin",            False),
    }

    for url_path, (file_path, replace_ip) in FILE_MAP.items():
        if url_path in flow.request.path:
            full_path = os.path.join(BASE, file_path)
            print(f"[*] Serving {file_path}")
            try:
                with open(full_path, "rb") as f:
                    content = f.read()
                    if replace_ip:
                        content = content.replace(b"PLS_STOP_HARDCODING_IPS", proxyServerIP)
                    print(f"[+] Loaded {len(content)} bytes from {file_path}")
                    flow.response = http.Response.make(
                        200, content,
                        {"Content-Type": "application/octet-stream"}
                    )
            except FileNotFoundError:
                print(f"[!] ERROR: {file_path} not found at {full_path}")
                flow.response = http.Response.make(
                    404,
                    f"File not found: {file_path}".encode(),
                    {"Content-Type": "text/plain"}
                )
            break
