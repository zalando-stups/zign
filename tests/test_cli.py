from click.testing import CliRunner
from mock import MagicMock
import yaml
from zign.cli import cli


def test_no_command(monkeypatch):
    token = 'abc-123'

    response = MagicMock()
    response.json.return_value = {'access_token': token}

    monkeypatch.setattr('keyring.set_password', MagicMock())
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['token', '-n', 'mytok', '--password', 'mypass', '--url', 'https://localhost/'], catch_exceptions=False)

    assert token == result.output.strip()

