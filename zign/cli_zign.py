import os

import click
from clickclick import AliasedGroup

import stups_cli.config

from .api import get_named_token, ServerError
from .cli import output_option, print_version
from zign import cli

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
@click.option('--url', help='URL to generate access token', metavar='URI')
@click.option('--realm', help='Use custom OAuth2 realm', metavar='NAME')
@click.option('-n', '--name', help='Custom token name (will be stored)', metavar='TOKEN_NAME')
@click.option('-U', '--user', help='Username to use for authentication', envvar='ZIGN_USER', metavar='NAME')
@click.option('-p', '--password', help='Password to use for authentication', envvar='ZIGN_PASSWORD', metavar='PWD')
@click.option('--insecure', help='Do not verify SSL certificate', is_flag=True, default=False)
@click.option('-r', '--refresh', help='Force refresh of the access token', is_flag=True, default=False)
@click.pass_obj
def token(obj, scope, url, realm, name, user, password, insecure, refresh):
    '''Create a new token or use an existing one'''

    user = user or obj.get('user') or os.getenv('USER')

    try:
        token = get_named_token(scope, realm, name, user, password, url, insecure, refresh, prompt=True)
    except ServerError as e:
        raise click.UsageError(e)
    access_token = token.get('access_token')

    print(access_token)


def main():
    cli_zign()
