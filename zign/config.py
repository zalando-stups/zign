import os
import click

KEYRING_KEY = 'zign'
OLD_CONFIG_NAME = 'zign'
CONFIG_NAME = 'zalando-token-cli'
CONFIG_DIR_PATH = click.get_app_dir(CONFIG_NAME)
TOKENS_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'tokens.yaml')
REFRESH_TOKEN_FILE_PATH = os.path.join(CONFIG_DIR_PATH, 'refresh-token.yaml')
