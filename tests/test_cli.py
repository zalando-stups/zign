from click.testing import CliRunner
from unittest.mock import MagicMock
from zign.cli import cli


def test_token(monkeypatch):

    token = 'abc-123'

    load_config = MagicMock()
    load_config.return_value = {'authorize_url': 'https://localhost/authorize', 'token_url': 'https://localhost/token', 'client_id': 'foobar', 'business_partner_id': '123'}
    perform_implicit_flow = MagicMock()
    perform_implicit_flow.return_value = {'access_token': token, 'expires_in': 1, 'token_type': 'test'}

    monkeypatch.setattr('zign.api.perform_implicit_flow', perform_implicit_flow)
    monkeypatch.setattr('stups_cli.config.load_config', load_config)

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['token', '-n', 'mytok', '--refresh'], catch_exceptions=False)

        assert token == result.output.rstrip().split('\n')[-1]

def test_token_with_refresh_url(monkeypatch):
    token = 'abc-123'

    get_token_implicit_flow = MagicMock()
    get_token_implicit_flow.return_value = {'access_token': token, 'expires_in': 1, 'token_type': 'test'}
    monkeypatch.setattr('zign.cli.get_token_implicit_flow', get_token_implicit_flow)

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['token', '-n', 'mytok', '--refresh', '-t', 'https://www.example.org/token', '-a', 'https://www.example.org/auth'],
                               catch_exceptions=False)

        assert token == result.output.rstrip().split('\n')[-1]
        get_token_implicit_flow.assert_called_with('mytok', authorize_url='https://www.example.org/auth',
                                                   token_url='https://www.example.org/token',
                                                   business_partner_id=None, client_id=None, refresh=True)
