import os
import click

KEYRING_KEY = 'zign'
CONFIG_DIR_PATH = click.get_app_dir('zign')
TOKENS_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'tokens.yaml')
