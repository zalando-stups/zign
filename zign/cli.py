import click
import os
import keyring
import requests
import time
import yaml

import zign

from clickclick import error, AliasedGroup, print_table, OutputFormat

KEYRING_KEY = 'zign'
CONFIG_DIR_PATH = click.get_app_dir('zign')
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'zign.yaml')
TOKENS_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'tokens.yaml')

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])

output_option = click.option('-o', '--output', type=click.Choice(['text', 'json', 'tsv']), default='text',
                             help='Use alternative output format')


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('Zign {}'.format(zign.__version__))
    ctx.exit()


@click.group(cls=AliasedGroup, context_settings=CONTEXT_SETTINGS)
@click.option('--config-file', '-c', help='Use alternative configuration file',
              default=CONFIG_FILE_PATH, metavar='PATH')
@click.option('-V', '--version', is_flag=True, callback=print_version, expose_value=False, is_eager=True,
              help='Print the current version number and exit.')
@click.pass_context
def cli(ctx, config_file):
    path = os.path.expanduser(config_file)
    data = {}
    if os.path.exists(path):
        with open(path, 'rb') as fd:
            data = yaml.safe_load(fd)
    ctx.obj = data


def format_expires(token: dict):
    now = time.time()
    remaining = token.get('creation_time', 0) + token.get('expires_in', 0) - now
    return '{}m'.format(round(remaining / 60))


@cli.command('list')
@output_option
@click.pass_obj
def list_tokens(obj, output):
    '''List tokens'''
    try:
        with open(TOKENS_FILE_PATH) as fd:
            data = yaml.safe_load(fd)
    except:
        data = {}

    rows = []
    for key, val in sorted(data.items()):
        rows.append({'name': key,
                     'access_token': val.get('access_token'),
                     'scope': val.get('scope'),
                     'creation_time': val.get('creation_time'),
                     'expires_in': format_expires(val)})

    with OutputFormat(output):
        print_table('name access_token scope creation_time expires_in'.split(), rows)


def is_valid(token: dict):
    now = time.time()
    return token and now < (token.get('creation_time', 0) + token.get('expires_in', 0))


@cli.command()
@click.argument('scope', nargs=-1)
@click.option('--url', help='URL to generate access token', metavar='URI')
@click.option('--realm', help='Use custom OAuth2 realm', metavar='NAME')
@click.option('-n', '--name', help='Custom token name (will be stored)', metavar='TOKEN_NAME')
@click.option('-U', '--user', help='Username to use for authentication', envvar='USER', metavar='NAME')
@click.option('-p', '--password', help='Password to use for authentication', envvar='ZIGN_PASSWORD', metavar='PWD')
@click.option('--insecure', help='Do not verify SSL certificate', is_flag=True, default=False)
@click.option('-r', '--refresh', help='Force refresh of the access token', is_flag=True, default=False)
@click.pass_obj
def token(obj, scope, url, realm, name, user, password, insecure, refresh):
    '''Create a new token or use an existing one'''

    config = obj

    if name and not refresh:
        try:
            with open(TOKENS_FILE_PATH) as fd:
                data = yaml.safe_load(fd)
        except:
            data = {}
        existing_token = data and data.get(name)
        if is_valid(existing_token):
            print(existing_token.get('access_token'))
            return

    url = url or config.get('url')

    while not url:
        url = click.prompt('Please enter the OAuth access token service URL')
        if not url.startswith('http'):
            url = 'https://{}'.format(url)

        try:
            requests.get(url, timeout=5, verify=not insecure)
        except:
            raise
            error('Could not reach {}'.format(url))
            url = None

        config['url'] = url

    os.makedirs(CONFIG_DIR_PATH, exist_ok=True)
    with open(CONFIG_FILE_PATH, 'w') as fd:
        yaml.dump(config, fd)

    password = password or keyring.get_password(KEYRING_KEY, user)

    if not password:
        password = click.prompt('Password', hide_input=True)

    params = {'json': 'true'}
    if realm:
        params['realm'] = realm
    if scope:
        params['scope'] = ' '.join(scope)
    response = requests.get(url, params=params, auth=(user, password), verify=not insecure)

    if response.status_code == 200:
        keyring.set_password(KEYRING_KEY, user, password)

    result = response.json()

    access_token = result.get('access_token')

    if not access_token:
        raise click.UsageError(yaml.safe_dump(result))

    if name:
        try:
            with open(TOKENS_FILE_PATH) as fd:
                data = yaml.safe_load(fd)
        except:
            pass

        if not data:
            data = {}

        data[name] = result
        data[name]['creation_time'] = time.time()

        with open(TOKENS_FILE_PATH, 'w') as fd:
            yaml.safe_dump(data, fd)

    print(access_token)


def main():
    cli()
