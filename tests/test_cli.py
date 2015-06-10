import json
from click.testing import CliRunner
from mock import MagicMock
import yaml
from zign.cli import cli


def test_no_command(monkeypatch):
    token = 'abc-123'

    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'access_token': token}

    monkeypatch.setattr('keyring.set_password', MagicMock())
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))

    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['-c', 'myconfig.yaml', 'token', '-n', 'mytok', '--password', 'mypass'], catch_exceptions=False, input='localhost\n')

        assert token == result.output.rstrip().split('\n')[-1]

        result = runner.invoke(cli, ['-c', 'myconfig.yaml', 'list', '-o', 'json'], catch_exceptions=False)
        data = json.loads(result.output)
        assert len(data) >= 1


def test_empty_config(monkeypatch):
    token = 'abc-123'

    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'access_token': token}

    monkeypatch.setattr('keyring.set_password', MagicMock())
    monkeypatch.setattr('zign.api.CONFIG_FILE_PATH', 'myconfig.yaml')
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))

    runner = CliRunner()

    with runner.isolated_filesystem():
        with open('myconfig.yaml', 'w') as fd:
            fd.write('')
        result = runner.invoke(cli, ['token', '-n', 'mytok', '--password', 'mypass'], catch_exceptions=False, input='localhost\n')
        assert token == result.output.rstrip().split('\n')[-1]

