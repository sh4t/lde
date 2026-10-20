"""SSRF guard for POST /api/extract-packages {url}: every hop is checked before
a connection is opened, the connection goes to the checked address, and the
response body is capped."""

import http.server
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend import package_extractor as pe  # noqa: E402


# --- address policy ---------------------------------------------------------

@pytest.mark.parametrize('ip', [
    '127.0.0.1', '127.8.8.8', '10.0.0.1', '172.16.5.5', '192.168.1.1',
    '169.254.169.254',   # EC2 instance metadata
    '169.254.170.2',     # ECS task credentials
    '100.64.0.1', '100.127.255.255',  # shared address space (cloud-internal services)
    '0.0.0.0', '224.0.0.1', '255.255.255.255',
    '::1', '::', 'fe80::1', 'fd00::1',
    '::ffff:127.0.0.1', '::ffff:169.254.169.254', '::ffff:10.0.0.1',
    '2002:7f00:1::1',    # 6to4 wrapping 127.0.0.1
    '2001:0:4136:e378:8000:63bf:3fff:fdd2',  # Teredo (RFC 4380 example, client 192.0.2.45)
    '2002:c000:22d::1',  # 6to4 wrapping 192.0.2.45 (TEST-NET-1, reserved)
])
def test_blocked_addresses(ip):
    with pytest.raises(ValueError):
        pe._check_ip(ip)


@pytest.mark.parametrize('ip', ['8.8.8.8', '93.184.216.34', '100.128.0.1',
                                '2606:4700::1111', '2a00:1450:4001:81d::200e'])
def test_public_addresses_pass(ip):
    assert str(pe._check_ip(ip)) == ip


# --- URL policy -------------------------------------------------------------

@pytest.mark.parametrize('url', [
    'ftp://example.com/x', 'file:///etc/passwd', 'gopher://example.com',
    'http://example.com:8081/api', 'https://example.com:8080/',
    'http:///nohost', 'http://example.com:99999/',
])
def test_scheme_and_port_rejected_before_dns(url, monkeypatch):
    def boom(*a):
        raise AssertionError('DNS must not be consulted for a rejected scheme or port')
    monkeypatch.setattr(pe, '_resolve_host', boom)
    with pytest.raises(ValueError):
        pe._validate_url(url)


def test_host_resolving_to_internal_address_rejected(monkeypatch):
    monkeypatch.setattr(pe, '_resolve_host', lambda h, p: ['93.184.216.34', '10.0.0.5'])
    with pytest.raises(ValueError, match='blocked address 10.0.0.5'):
        pe._validate_url('https://rebinder.example/')


def test_validate_url_returns_checked_address(monkeypatch):
    monkeypatch.setattr(pe, '_resolve_host', lambda h, p: ['93.184.216.34'])
    assert pe._validate_url('https://example.com/advisory') == '93.184.216.34'


def test_unresolvable_host_rejected(monkeypatch):
    def gaierror(h, p):
        raise ValueError(f"Cannot resolve hostname {h!r}")
    monkeypatch.setattr(pe, '_resolve_host', gaierror)
    with pytest.raises(ValueError, match='Cannot resolve'):
        pe._validate_url('http://does-not-exist.invalid/')


# --- live fetch mechanics against local servers -----------------------------

class _Server:
    """A local HTTP server that records every request it receives."""

    def __init__(self, respond):
        outer = self
        outer.requests = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                outer.requests.append((self.path, dict(self.headers)))
                status, headers, body = respond(self.path)
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.httpd = http.server.HTTPServer(('127.0.0.1', 0), H)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


_PAGE = b'<html><body>' + b'<p>affected package lodash</p>' * 20 + b'</body></html>'


@pytest.fixture
def no_proxy_env(monkeypatch):
    for key in list(os.environ):
        if key.lower().endswith('_proxy'):
            monkeypatch.delenv(key, raising=False)


@pytest.fixture
def allow_local(monkeypatch, no_proxy_env):
    """Let the fetcher reach 127.0.0.1 on test ports, keeping a per-port policy
    so a test can declare one local port 'blocked'."""
    blocked_ports = set()
    monkeypatch.setattr(pe, '_check_ip', lambda ip: ip)

    def validate(url):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.port in blocked_ports:
            raise ValueError(f'URL resolves to blocked address 127.0.0.1 ({parsed.hostname})')
        return '127.0.0.1'

    monkeypatch.setattr(pe, '_validate_url', validate)
    return blocked_ports


def test_redirect_to_blocked_target_is_refused_before_any_request(allow_local):
    target = _Server(lambda path: (200, {}, _PAGE))
    hop = _Server(lambda path: (302, {'Location': f'http://127.0.0.1:{target.port}/secret'}, b''))
    try:
        allow_local.add(target.port)
        with pytest.raises(ValueError, match='Redirect refused'):
            pe._fetch_url(f'http://127.0.0.1:{hop.port}/')
        assert target.requests == [], 'the blocked redirect target must never be contacted'
        assert len(hop.requests) == 1
    finally:
        hop.close()
        target.close()


def test_redirect_to_allowed_target_is_followed(allow_local):
    target = _Server(lambda path: (200, {}, _PAGE))
    hop = _Server(lambda path: (302, {'Location': f'http://127.0.0.1:{target.port}/page'}, b''))
    try:
        html = pe._fetch_url(f'http://127.0.0.1:{hop.port}/')
        assert b'lodash'.decode() in html
        assert [p for p, _ in target.requests] == ['/page']
    finally:
        hop.close()
        target.close()


def test_connection_is_pinned_to_the_checked_address(monkeypatch, no_proxy_env):
    """The hostname is sent in Host, but the socket goes to the address the
    check returned: a name that does not resolve at all still reaches the
    server, which proves no second DNS lookup happened."""
    server = _Server(lambda path: (200, {}, _PAGE))
    try:
        monkeypatch.setattr(pe, '_ALLOWED_PORTS', frozenset({server.port}))
        monkeypatch.setattr(pe, '_check_ip', lambda ip: ip)
        monkeypatch.setattr(pe, '_resolve_host', lambda h, p: ['127.0.0.1'])
        html = pe._fetch_url(f'http://pinned.invalid:{server.port}/x')
        assert 'lodash' in html
        _, headers = server.requests[0]
        assert headers['Host'] == f'pinned.invalid:{server.port}'
    finally:
        server.close()


def test_every_hop_is_checked_at_open_time(monkeypatch, no_proxy_env):
    """Even with the redirect handler's own check bypassed, the HTTP handler
    re-checks the redirected request before connecting."""
    target = _Server(lambda path: (200, {}, _PAGE))
    hop = _Server(lambda path: (302, {'Location': f'http://127.0.0.1:{target.port}/'}, b''))
    try:
        calls = []

        def validate(url):
            calls.append(url)
            from urllib.parse import urlparse
            if urlparse(url).port == target.port:
                raise ValueError('blocked')
            return '127.0.0.1'

        monkeypatch.setattr(pe, '_check_ip', lambda ip: ip)
        monkeypatch.setattr(pe, '_validate_url', validate)
        monkeypatch.setattr(pe._SafeRedirectHandler, 'redirect_request',
                            lambda self, req, fp, code, msg, headers, newurl:
                            pe.__class__ and __import__('urllib.request').request
                            .HTTPRedirectHandler.redirect_request(
                                self, req, fp, code, msg, headers, newurl))
        with pytest.raises(ValueError, match='blocked'):
            pe._fetch_url(f'http://127.0.0.1:{hop.port}/')
        assert target.requests == []
    finally:
        hop.close()
        target.close()


def test_response_body_is_capped(allow_local, monkeypatch):
    big = _Server(lambda path: (200, {}, b'x' * 5000))
    try:
        monkeypatch.setattr(pe, '_MAX_RESPONSE_BYTES', 4096)
        with pytest.raises(ValueError, match='larger than'):
            pe._fetch_url(f'http://127.0.0.1:{big.port}/')
    finally:
        big.close()


def test_unknown_charset_falls_back_to_utf8(allow_local):
    server = _Server(lambda path: (200, {'Content-Type': 'text/html; charset=not-a-charset'}, _PAGE))
    try:
        assert 'lodash' in pe._fetch_url(f'http://127.0.0.1:{server.port}/')
    finally:
        server.close()


def test_run_rejects_blocked_url_without_fetching(monkeypatch):
    monkeypatch.setattr(pe, '_resolve_host', lambda h, p: ['169.254.169.254'])
    with pytest.raises(ValueError, match='blocked address'):
        pe.run(lambda s: None, 'http://metadata.example/latest/meta-data/', 'key')


def test_gemini_model_name_is_url_quoted(monkeypatch):
    seen = {}

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b'{"candidates":[{"finishReason":"STOP","content":{"parts":[{"text":"[]"}]}}]}'

    def fake_urlopen(req, timeout=None):
        seen['url'] = req.full_url
        return _Resp()

    monkeypatch.setattr(pe.urllib.request, 'urlopen', fake_urlopen)
    pe._call_gemini('text', 'key', model='../../evil?x=')
    assert '/models/..%2F..%2Fevil%3Fx%3D:generateContent' in seen['url']
