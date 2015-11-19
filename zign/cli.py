import os
import time

import click
import yaml
from clickclick import AliasedGroup, print_table, OutputFormat

import zign
import stups_cli.config
from .api import get_named_token, get_tokens, ServerError
from .config import TOKENS_FILE_PATH


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

output_option = click.option('-o', '--output', type=click.Choice(['text', 'json', 'tsv']), default='text',
                             help='Use alternative output format')


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('Zign {}'.format(zign.__version__))
    ctx.exit()


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True,
              help='Print the current version number and exit.')
@click.pass_context
def cli(ctx):
    ctx.obj = stups_cli.config.load_config('zign')


def format_expires(token: dict):
    now = time.time()
    remaining = token.get('creation_time', 0) + token.get('expires_in', 0) - now
    return '{}m'.format(round(remaining / 60))


@cli.command('list')
@output_option
@click.pass_obj
def list_tokens(obj, output):
    '''List tokens'''
    data = get_tokens()

    rows = []
    for key, val in sorted(data.items()):
        rows.append({'name': key,
                     'access_token': val.get('access_token'),
                     'scope': val.get('scope'),
                     'creation_time': val.get('creation_time'),
                     'expires_in': format_expires(val)})

    with OutputFormat(output):
        print_table('name access_token scope creation_time expires_in'.split(), rows,
                    titles={'creation_time': 'Created'})


@cli.command('delete')
@click.argument('name')
@click.pass_obj
def delete_token(obj, name):
    '''Delete a named token'''
    data = get_tokens()

    try:
        del data[name]
    except:
        pass

    with open(TOKENS_FILE_PATH, 'w') as fd:
        yaml.safe_dump(data, fd)


@cli.command()
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

    user = user or os.getenv('USER')

    try:
        token = get_named_token(scope, realm, name, user, password, url, insecure, refresh, prompt=True)
    except ServerError as e:
        raise click.UsageError(e)
    access_token = token.get('access_token')

    print(access_token)


def main():
    cli()
