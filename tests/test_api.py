import pytest
import tokens
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


def test_get_token_existing(monkeypatch):
    monkeypatch.setattr('zign.api.get_existing_token', lambda x: {'access_token': 'tt77'})
    assert zign.api.get_token('mytok', ['myscope']) == 'tt77'


def test_get_token_configuration_error(monkeypatch):
    def get_token(name):
        raise tokens.ConfigurationError('TEST')

    monkeypatch.setattr('tokens.get', get_token)
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {})

    with pytest.raises(zign.api.ConfigurationError):
        zign.api.get_token('mytok', ['myscope'])


def test_get_token_service_success(monkeypatch):
    monkeypatch.setattr('tokens.get', lambda x: 'svc123')

    assert zign.api.get_token('mytok', ['myscope']) == 'svc123'


def test_get_token_fallback_success(monkeypatch):
    def get_token(name):
        raise tokens.ConfigurationError('TEST')

    monkeypatch.setattr('tokens.get', get_token)
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'http://localhost'})
    monkeypatch.setattr('os.getenv', lambda x: 'mypass')
    monkeypatch.setattr('zign.api.get_new_token', lambda *args, **kwargs: {'access_token': 'tt77'})

    assert zign.api.get_token('mytok', ['myscope']) == 'tt77'
