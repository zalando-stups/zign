import click
import stups_cli.config
from clickclick import AliasedGroup
from zign import cli

from .api import get_token
from .cli import output_option, print_version

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True,
              help='Print the current version number and exit.')
@click.pass_context
def cli_zign(ctx):
    ctx.obj = stups_cli.config.load_config('zign')


@cli_zign.command('list')
@output_option
@click.pass_context
def list_tokens(ctx, output):
    '''List tokens'''
    ctx.invoke(cli.list_tokens, output=output)


@cli_zign.command('delete')
@click.argument('name')
@click.pass_context
def delete_token(ctx, name):
    '''Delete a named token'''

    ctx.invoke(cli.delete_token, name=name)


@cli_zign.command()
@click.argument('scope', nargs=-1)
# all these options are deprecated, but still here for compatibility
@click.option('--url', help='DEPRECATED: URL to generate access token', metavar='URI')
@click.option('--realm', help='DEPRECATED: Use custom OAuth2 realm', metavar='NAME')
@click.option('-n', '--name', help='DEPRECATED: Custom token name (will be stored)', metavar='TOKEN_NAME')
@click.option('-U', '--user', help='DEPRECATED: Username to use for authentication', envvar='ZIGN_USER', metavar='NAME')
@click.option('-p', '--password', help='DEPRECATED: Password to use for authentication', envvar='ZIGN_PASSWORD')
@click.option('--insecure', help='DEPRECATED: Do not verify SSL certificate', is_flag=True, default=False)
@click.option('-r', '--refresh', help='DEPRECATED: Force refresh of the access token', is_flag=True, default=False)
@click.pass_obj
def token(obj, scope, url, realm, name, user, password, insecure, refresh):
    '''Create a new token or use an existing one'''

    access_token = get_token(name, scope)
    print(access_token)


def main():
    cli_zign()
