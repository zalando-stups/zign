import click
from clickclick import error
import keyring
import os
import time
import requests
import yaml

from .config import KEYRING_KEY, CONFIG_DIR_PATH, CONFIG_FILE_PATH, TOKENS_FILE_PATH


def get_new_token(realm, scope, user, password, url=None, insecure=False):
    if not url:
        with open(CONFIG_FILE_PATH) as fd:
            data = yaml.safe_load(fd)
        url = data.get('url')
    params = {'json': 'true'}
    if realm:
        params['realm'] = realm
    if scope:
        params['scope'] = ' '.join(scope)
    response = requests.get(url, params=params, auth=(user, password), verify=not insecure)
    return response.json()


def get_named_token(scope, realm, name, user, password, url=None, insecure=False, refresh=False, use_keyring=True):
    try:
        with open(CONFIG_FILE_PATH) as fd:
            config = yaml.safe_load(fd)
    except:
        config = {}

    if name and not refresh:
        try:
            with open(TOKENS_FILE_PATH) as fd:
                data = yaml.safe_load(fd)
        except:
            data = {}
        existing_token = data and data.get(name)
        if is_valid(existing_token):
            return existing_token

    url = url or config.get('url')

    while not url:
        url = click.prompt('Please enter the OAuth access token service URL')
        if not url.startswith('http'):
            url = 'https://{}'.format(url)

        try:
            requests.get(url, timeout=5, verify=not insecure)
        except:
            error('Could not reach {}'.format(url))
            url = None

        config['url'] = url

    os.makedirs(CONFIG_DIR_PATH, exist_ok=True)
    with open(CONFIG_FILE_PATH, 'w') as fd:
        yaml.dump(config, fd)

    password = password or keyring.get_password(KEYRING_KEY, user)

    if not password:
        password = click.prompt('Password', hide_input=True)

    result = get_new_token(realm, scope, user, password, insecure=insecure)

    if result and use_keyring:
        keyring.set_password(KEYRING_KEY, user, password)

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

    return result


def is_valid(token: dict):
    now = time.time()
    return token and now < (token.get('creation_time', 0) + token.get('expires_in', 0))
