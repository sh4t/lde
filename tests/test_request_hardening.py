"""Request-handling hardening in server.py: Content-Length validation, the
repo-log path check, PUT /api/settings value validation, the url type check
on /api/extract-packages, the local basic_auth_credentials source, and the
dev reloader ignoring .settings.json."""

import io
import json
import os
import sys
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402
from backend import settings as settings_mod  # noqa: E402


def _handler(headers=None, body=b''):
    h = server.Handler.__new__(server.Handler)
    h.headers = dict(headers or {})
    h.rfile = io.BytesIO(body)
    h.status = None
    h.payload = None
    buf = io.BytesIO()
    h.wfile = MagicMock()
    h.wfile.write = buf.write
    h._require_auth = lambda: True
    h.send_response = lambda code, message=None: setattr(h, 'status', code)
    h.send_header = lambda key, value: None
    h.end_headers = lambda: None

    def json_response(status, data):
        h.status = status
        h.payload = data

    h._json_response = json_response
    return h


# --- _read_body ---------------------------------------------------------------

class _BlockingRfile:
    def read(self, n):
        if n < 0:
            raise AssertionError('read(-1) blocks until the client closes the socket')
        return b'{}'[:n]


@pytest.mark.parametrize('length', ['-1', '-99999', 'abc', '', '1e3'])
def test_bad_content_length_is_400_without_reading(length):
    h = _handler({'Content-Length': length})
    h.rfile = _BlockingRfile()
    with pytest.raises(ValueError, match='Content-Length'):
        h._read_body()


def test_oversized_body_is_refused_without_reading():
    h = _handler({'Content-Length': str(server.Handler._MAX_BODY + 1)})
    h.rfile = _BlockingRfile()
    with pytest.raises(ValueError, match='too large'):
        h._read_body()


def test_missing_and_zero_content_length_give_empty_body():
    assert _handler({})._read_body() == {}
    assert _handler({'Content-Length': '0'})._read_body() == {}


def test_body_is_parsed():
    body = json.dumps({'a': 1}).encode()
    assert _handler({'Content-Length': str(len(body))}, body)._read_body() == {'a': 1}


# --- GET /api/runs/{id}/logs/{org}/{repo} ------------------------------------

@pytest.fixture
def data_dir(tmp_path, monkeypatch):
    run = tmp_path / 'runs' / 'abc123'
    run.mkdir(parents=True)
    (run / 'org__repo.log').write_text('ort output')
    (tmp_path / 'runs' / 'secret.log').write_text('outside the run')
    (run / 'evil__x.log').symlink_to(tmp_path / 'runs' / 'secret.log')
    monkeypatch.setattr(server, 'DATA_DIR', str(tmp_path))
    return tmp_path


def test_repo_log_is_served(data_dir):
    h = _handler()
    h.handle_get_repo_log(('abc123', 'org', 'repo'), {})
    assert h.status == 200
    assert h.payload == {'log': 'ort output'}


@pytest.mark.parametrize('org, repo', [
    ('..', 'x'), ('org', '..'), ('a/b', 'c'), ('org', 'repo\\..'), ('', 'repo'),
    ('org', 'repo log'), ('o:rg', 'repo'),
])
def test_repo_log_rejects_bad_identifiers(data_dir, org, repo):
    h = _handler()
    with pytest.raises(ValueError, match='Invalid org or repo'):
        h.handle_get_repo_log(('abc123', org, repo), {})


def test_repo_log_refuses_symlink_out_of_the_run_dir(data_dir):
    h = _handler()
    h.handle_get_repo_log(('abc123', 'evil', 'x'), {})
    assert h.status == 404


def test_repo_log_missing_is_404(data_dir):
    h = _handler()
    h.handle_get_repo_log(('abc123', 'org', 'other'), {})
    assert h.status == 404


# --- PUT /api/settings value validation -----------------------------------------

@pytest.mark.parametrize('patch', [
    {'gemini_model': '../../v1/other'},
    {'gemini_model': 'gemini:evil'},
    {'gemini_model': 'a' * 129},
    {'gemini_model': 7},
    {'dtrack_url': 'ftp://dt.internal'},
    {'dtrack_url': 'not a url'},
    {'dtrack_ui_url': 'javascript:alert(1)'},
    {'dtrack_ui_url': 12},
    {'default_orgs': 'example-org'},
    {'default_orgs': ['ok', 'bad org']},
    {'default_orgs': [None]},
])
def test_invalid_settings_values_are_rejected(patch):
    with pytest.raises(ValueError):
        server._validate_settings_patch(patch)


@pytest.mark.parametrize('patch', [
    {'gemini_model': 'gemini-3.8-flash'},
    {'gemini_model': ''},
    {'dtrack_url': 'http://localhost:8081', 'dtrack_ui_url': 'https://dtrack.example.com/'},
    {'dtrack_url': ''},
    {'default_orgs': ['example-org', 'another_org.v2']},
    {'default_orgs': []},
    {'run_retention': 3},
])
def test_valid_settings_values_pass(patch):
    server._validate_settings_patch(patch)


def test_put_settings_runs_validation(monkeypatch, tmp_path):
    monkeypatch.delenv('LDE_SECRETS_SOURCE', raising=False)
    monkeypatch.setattr(settings_mod, 'SETTINGS_PATH', str(tmp_path / '.settings.json'))
    body = json.dumps({'gemini_model': 'x/y'}).encode()
    h = _handler({'Content-Length': str(len(body))}, body)
    with pytest.raises(ValueError, match='gemini_model'):
        h.handle_put_settings((), {})
    assert not (tmp_path / '.settings.json').exists()


# --- POST /api/extract-packages ------------------------------------------------

@pytest.mark.parametrize('url', [None, 7, ['http://x'], {'u': 1}, '', '   '])
def test_extract_packages_requires_a_string_url(monkeypatch, url):
    monkeypatch.setattr(settings_mod, 'load_settings',
                        lambda: {'gemini_api_key': 'k', 'gemini_model': 'm'})
    submitted = []
    monkeypatch.setattr(server.task_queue, 'submit', lambda *a, **k: submitted.append(a) or 'id')
    body = json.dumps({'url': url}).encode()
    h = _handler({'Content-Length': str(len(body))}, body)
    with pytest.raises(ValueError, match='url'):
        h.handle_extract_packages((), {})
    assert submitted == []


# --- basic_auth_credentials from .settings.json / env --------------------------

def test_basic_auth_credentials_in_settings_file_is_loaded(tmp_path, monkeypatch):
    path = tmp_path / '.settings.json'
    path.write_text(json.dumps({'basic_auth_credentials': {'admin': 'a' * 64}}))
    monkeypatch.setattr(settings_mod, 'SETTINGS_PATH', str(path))
    monkeypatch.delenv('LDE_SECRETS_SOURCE', raising=False)
    monkeypatch.delenv('LDE_BASIC_AUTH_CREDENTIALS', raising=False)
    assert settings_mod.load_settings()['basic_auth_credentials'] == {'admin': 'a' * 64}
    assert server._load_basic_auth_creds() == {'admin': 'a' * 64}


def test_basic_auth_credentials_env_override(tmp_path, monkeypatch):
    monkeypatch.setattr(settings_mod, 'SETTINGS_PATH', str(tmp_path / 'absent.json'))
    monkeypatch.delenv('LDE_SECRETS_SOURCE', raising=False)
    monkeypatch.setenv('LDE_BASIC_AUTH_CREDENTIALS', json.dumps({'ops': 'b' * 64}))
    assert server._load_basic_auth_creds() == {'ops': 'b' * 64}


def test_basic_auth_credentials_is_not_settable_over_the_api():
    assert 'basic_auth_credentials' not in settings_mod.ALLOWED_KEYS
    assert 'basic_auth_credentials' in settings_mod.FILE_ONLY_KEYS


def test_basic_auth_credentials_is_masked_or_omitted():
    out = settings_mod.masked({'basic_auth_credentials': {'admin': 'a' * 64}})
    assert 'basic_auth_credentials' not in out
    out = settings_mod.masked({'basic_auth_credentials': '{"admin": "aaaa"}'})
    assert out['basic_auth_credentials'] == '{"ad…'


# --- dev reloader ----------------------------------------------------------------

def test_reloader_ignores_dot_files(tmp_path, monkeypatch):
    (tmp_path / '.settings.json').write_text('{}')
    (tmp_path / 'server.py').write_text('')
    (tmp_path / 'js').mkdir()
    (tmp_path / 'js' / 'app.js').write_text('')
    (tmp_path / '.cache').mkdir()
    (tmp_path / '.cache' / 'x.json').write_text('{}')
    monkeypatch.setattr(server, 'SERVE_DIR', str(tmp_path))
    watched = {os.path.relpath(p, tmp_path) for p in server._collect_mtimes()}
    assert watched == {'server.py', os.path.join('js', 'app.js')}
