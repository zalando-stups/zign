import time

import click
import yaml
from clickclick import AliasedGroup, print_table, OutputFormat

import zign
import stups_cli.config
from .api import get_token_implicit_flow, get_tokens, AuthenticationFailed
from .config import CONFIG_NAME, TOKENS_FILE_PATH


CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

output_option = click.option('-o', '--output', type=click.Choice(['text', 'json', 'tsv']), default='text',
                             help='Use alternative output format')


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('{command} {version}'.format(command=ctx.info_name, version=zign.__version__))
    ctx.exit()


@click.group(cls=AliasedGroup, invoke_without_command=True, context_settings=CONTEXT_SETTINGS)
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True,
              help='Print the current version number and exit.')
@click.pass_context
def cli(ctx):
    ctx.obj = stups_cli.config.load_config(CONFIG_NAME)

    if not ctx.invoked_subcommand:
        ctx.invoke(token)


def format_expires(token: dict):
    now = time.time()
    remaining = token.get('creation_time', 0) + token.get('expires_in', 0) - now
    return '{}m'.format(round(remaining / 60))


@cli.command('list')
@output_option
def list_tokens(output):
    '''List tokens'''
    data = get_tokens()

    rows = []
    for key, val in sorted(data.items()):
        access_token = val.get('access_token')
        rows.append({'name': key,
                     'access_token': access_token,
                     'scope': val.get('scope'),
                     'creation_time': val.get('creation_time'),
                     'expires_in': format_expires(val)})

    with OutputFormat(output):
        print_table('name access_token scope creation_time expires_in'.split(), rows,
                    titles={'creation_time': 'Created'}, max_column_widths={'access_token': 36})


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
@click.option('-n', '--name', help='Custom token name (will be stored)', metavar='TOKEN_NAME')
@click.option('-a', '--authorize-url', help='OAuth 2 Authorization Endpoint URL to generate access token',
              metavar='AUTH_URL')
@click.option('-c', '--client-id', help='Client ID to use', metavar='CLIENT_ID')
@click.option('-p', '--business-partner-id', help='Business Partner ID to use', metavar='PARTNER_ID')
@click.option('-r', '--refresh', help='Force refresh of the access token', is_flag=True, default=False)
def token(name, authorize_url, client_id, business_partner_id, refresh):
    '''Create a new Platform IAM token or use an existing one.'''

    try:
        token = get_token_implicit_flow(name, authorize_url=authorize_url, client_id=client_id,
                                        business_partner_id=business_partner_id, refresh=refresh)
    except AuthenticationFailed as e:
        raise click.UsageError(e)
    access_token = token.get('access_token')
    click.echo(access_token)


def main():
    cli()
