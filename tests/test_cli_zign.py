import json
from click.testing import CliRunner
from unittest.mock import MagicMock
from zign.cli_zign import cli_zign


def test_create_list_delete(monkeypatch):
    token = 'abc-123'

    perform_implicit_flow = MagicMock()
    perform_implicit_flow.return_value = {'access_token': token, 'expires_in': 1, 'token_type': 'test'}
    monkeypatch.setattr('zign.api.perform_implicit_flow', perform_implicit_flow)

    load_config = MagicMock()
    load_config.return_value = {'authorize_url': 'https://localhost/authorize', 'token_url': 'https://localhost/token', 'client_id': 'foobar', 'business_partner_id': '123'}
    monkeypatch.setattr('stups_cli.config.load_config', load_config)

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli_zign, ['token', '-n', 'mytok', '--password', 'mypass'], catch_exceptions=False)

        assert token == result.output.rstrip().split('\n')[-1]

        result = runner.invoke(cli_zign, ['list', '-o', 'json'], catch_exceptions=False)
        data = json.loads(result.output)
        assert len(data) >= 1
        assert 'mytok' in [r['name'] for r in data]

        result = runner.invoke(cli_zign, ['delete', 'mytok'], catch_exceptions=False)
        result = runner.invoke(cli_zign, ['list', '-o', 'json'], catch_exceptions=False)
        data = json.loads(result.output)
        assert 'mytok' not in [r['name'] for r in data]

        # should work again for already deleted tokens
        result = runner.invoke(cli_zign, ['delete', 'mytok'], catch_exceptions=False)
