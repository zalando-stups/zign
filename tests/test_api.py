import pytest
import zign.api

from unittest.mock import MagicMock

def test_get_new_token_auth_fail(monkeypatch):
    response = MagicMock(status_code=401)
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    with pytest.raises(zign.api.AuthenticationFailed) as excinfo:
        zign.api.get_named_token('myrealm', ['myscope'], 'myuser', 'mypass', 'http://example.org')

    assert 'Authentication failed: Token Service' in str(excinfo)


def test_get_new_token_server_error(monkeypatch):
    response = MagicMock(status_code=500)
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    with pytest.raises(zign.api.ServerError) as excinfo:
        zign.api.get_new_token('myrealm', ['myscope'], 'myuser', 'mypass', 'http://example.org')

    assert 'Server error: Token Service returned HTTP status 500' in str(excinfo)


def test_get_new_token_invalid_json(monkeypatch):
    response = MagicMock(status_code=200)
    response.json.side_effect = ValueError('invalid JSON!')
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    with pytest.raises(zign.api.ServerError):
        zign.api.get_new_token('myrealm', ['myscope'], 'myuser', 'mypass', 'http://example.org')


def test_get_new_token_missing_access_token(monkeypatch):
    response = MagicMock(status_code=200)
    response.json.return_value = {}
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    with pytest.raises(zign.api.ServerError):
        zign.api.get_new_token('myrealm', ['myscope'], 'myuser', 'mypass', 'http://example.org')
