import pytest
import time
import tokens
import zign.api

from unittest.mock import MagicMock


def test_is_valid():
    now = time.time()
    assert not zign.api.is_valid({})
    assert not zign.api.is_valid({'creation_time': now - 3610, 'expires_in': 3600})
    assert zign.api.is_valid({'creation_time': now - 100, 'expires_in': 600})
    # still valid for 2 minutes, but we only return tokens valid for at least 5 more minutes
    assert not zign.api.is_valid({'creation_time': now - 3480, 'expires_in': 3600})


def test_get_named_token_deprecated(monkeypatch):
    logger = MagicMock()
    response = MagicMock(status_code=401)
    monkeypatch.setattr('zign.api.get_token', lambda x, y: 'mytok701')
    monkeypatch.setattr('zign.api.logger', logger)
    token = zign.api.get_named_token('myrealm', ['myscope'], 'myuser', 'mypass', 'http://example.org')
    assert 'mytok701' == token['access_token']
    logger.warning.assert_called_with('"get_named_token" is deprecated, please use "zign.api.get_token" instead')


def test_get_new_token_server_error(monkeypatch):
    response = MagicMock(status_code=500)
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    with pytest.raises(zign.api.ServerError) as excinfo:
        zign.api.get_new_token('myrealm', ['myscope'], 'myuser', 'mypass', 'http://example.org')

    assert 'Server error: Token Service returned HTTP status 500' in str(excinfo.value)


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


def test_get_token_service_success(monkeypatch):
    monkeypatch.setattr('tokens.get', lambda x: 'svc123')

    assert zign.api.get_token('mytok', ['myscope']) == 'svc123'


def test_get_token_fallback_success(monkeypatch):
    def get_token(name):
        raise tokens.ConfigurationError('TEST')

    monkeypatch.setattr('tokens.get', get_token)
    monkeypatch.setattr('zign.api.get_token_implicit_flow', lambda *args, **kwargs: {'access_token': 'tt77'})

    assert zign.api.get_token('mytok', ['myscope']) == 'tt77'


def test_get_named_token_existing(monkeypatch):
    existing = {'mytok': {'access_token': 'tt77', 'creation_time': time.time() - 10, 'expires_in': 3600}}
    monkeypatch.setattr('zign.api.get_tokens', lambda: existing)
    tok = zign.api.get_named_token(scope=['myscope'], realm=None, name='mytok', user='myusr', password='mypw')
    assert tok['access_token'] == 'tt77'


def test_get_named_token_services(monkeypatch):
    response = MagicMock(status_code=401)
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    monkeypatch.setattr('tokens.get', lambda x: 'svcmytok123')
    tok = zign.api.get_named_token(scope=['myscope'], realm=None, name='mytok', user='myusr', password='mypw')
    assert tok['access_token'] == 'svcmytok123'


def test_backwards_compatible_get_config(monkeypatch):
    load_config = MagicMock()
    load_config.return_value = {'url': 'http://localhost'}
    monkeypatch.setattr('stups_cli.config.load_config', load_config)
    assert {'url': 'http://localhost'} == zign.api.get_config()
    load_config.assert_called_with('zign')


def test_get_config(monkeypatch):
    load_config = MagicMock()
    load_config.return_value = {}
    store_config = MagicMock()
    def prompt(message, **kwargs):
        # just return the prompt text for easy assertion
        return message
    monkeypatch.setattr('stups_cli.config.load_config', load_config)
    monkeypatch.setattr('stups_cli.config.store_config', store_config)
    monkeypatch.setattr('click.prompt', prompt)
    monkeypatch.setattr('requests.get', lambda x, timeout: None)
    config = zign.api.get_config(zign.config.CONFIG_NAME)
    expected_config = {
        'authorize_url': 'Please enter the OAuth 2 Authorization Endpoint URL',
        'business_partner_id': 'Please enter the Business Partner ID',
        'client_id': 'Please enter the OAuth 2 Client ID',
        'token_url': 'Please enter the OAuth 2 Token Endpoint URL'
    }
    assert config == expected_config



def test_token_implicit_flow(monkeypatch):

    access_token = 'myacctok'

    def webbrowser_open(url, **kwargs):
        assert url == 'https://localhost/authorize?business_partner_id=123&client_id=foobar&redirect_uri=http://localhost:8081&response_type=token'

    server = MagicMock()
    server.return_value.query_params = {'access_token': access_token, 'refresh_token': 'foo', 'expires_in': 3600, 'token_type': 'Bearer'}

    load_config = MagicMock()
    load_config.return_value = {'authorize_url': 'https://localhost/authorize', 'token_url': 'https://localhost/token', 'client_id': 'foobar', 'business_partner_id': '123'}
    monkeypatch.setattr('stups_cli.config.load_config', load_config)
    monkeypatch.setattr('zign.api.load_config_ztoken', lambda x: {})
    monkeypatch.setattr('webbrowser.open', webbrowser_open)
    monkeypatch.setattr('zign.api.ClientRedirectServer', server)
    token = zign.api.get_token_implicit_flow('test_token_implicit_flow')
    assert access_token == token['access_token']
