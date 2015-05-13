import click
import os
import keyring
import yaml
import time

import zign

from clickclick import Action, choice, error, AliasedGroup, info, print_table

CONFIG_DIR_PATH = click.get_app_dir('zign')
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'zign.yaml')
LAST_UPDATE_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'last_update.yaml')

CONTEXT_SETTINGS = dict(help_option_names=['-h', '--help'])


def print_version(ctx, param, value):
    if not value or ctx.resilient_parsing:
        return
    click.echo('Zign {}'.format(zign.__version__))
    ctx.exit()


@click.group(cls=AliasedGroup, invoke_without_command=True, context_settings=CONTEXT_SETTINGS)
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


@cli.command('list')
@click.pass_obj
def list_tokens(obj):
    '''List tokens'''

    pass


@cli.command('token')
@click.pass_obj
def create_token(obj):
    '''Create a new token'''
    pass


def main():
    cli()
