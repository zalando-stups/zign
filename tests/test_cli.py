from click.testing import CliRunner
import yaml
from zign.cli import cli


def test_no_command():
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, [], catch_exceptions=False)

