import click
from clickclick import error, info, UrlType
import keyring
import os
import stups_cli.config
import time
import tokens
import requests
import socket
import webbrowser
import yaml

from .config import KEYRING_KEY, TOKENS_FILE_PATH
from oauth2client import tools
from requests import RequestException
from urllib.parse import parse_qs
from urllib.parse import urlparse
from urllib.parse import urlencode
from urllib.parse import urlunsplit

TOKEN_MINIMUM_VALIDITY_SECONDS = 60*5  # 5 minutes

SUCCESS_PAGE='''<!DOCTYPE HTML>
<html lang="en-US">
  <head>
    <title>Authentication Successful - Zign</title>
    <style>
        body {
            font-family: sans-serif;
        }
    </style>
  </head>
  <body>
    <p>You are now authenticated with Zign.</p>
    <p>The authentication flow has completed. You may close this window.</p>
  </body>
</html>'''

EXTRACT_TOKEN_PAGE='''<!DOCTYPE HTML>
<html lang="en-US">
  <head>
    <!-- fill out the blanks please -->
    <title>...</title>
    <style>
        body {
            font-family: sans-serif;
        }
        #error {
            color: red;
        }
    </style>
    <script>
        (function() {
            function parseQueryString(qs) {
                const result = {}
                for(const part of qs.split("&")) {
                    const [key, val = ""] = part.split("=")
                    result[decodeURIComponent(key)] = decodeURIComponent(val)
                }
                return result
            }
            const fragment = window.location.hash.substring(1)
            const params = parseQueryString(fragment)
            if (params.access_token) {
                window.location.href = "http://localhost:8081/?" + fragment
            } else {
                document.getElementById("error").style = "display: block;"
            }
        })();
    </script>
  </head>
  <body>
    <p style="display:none;" id="error">
        Please put a nice message here.
    </p>
  </body>
</html>'''

class ServerError(Exception):
    def __init__(self, message):
        self.message = message

    def __str__(self):
        return 'Server error: {}'.format(self.message)


class AuthenticationFailed(ServerError):
    def __str__(self):
        return 'Authentication failed: {}'.format(self.message)


class ConfigurationError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return 'Configuration error: {}'.format(self.msg)

class ClientRedirectHandler(tools.ClientRedirectHandler):
    '''Handles OAuth 2.0 redirect and return a success page if the flow has completed.'''

    def do_GET(self):
        '''Handle the GET request from the redirect.

        Parses the token from the query parameters and returns a success page if the flow has completed'''

        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        query_string = urlparse(self.path).query
        print('Path', self.path)
        print('Query string', query_string)
        #self.server.query_params = '' parse_qs(query_string)

        if not query_string:
            self.wfile.write(page.encode('utf-8')) 
        else:
<<<<<<< 6412c646b3bd16843198733b1782bb5ea38adedc
            page = EXTRACT_TOKEN_PAGE
=======
            if 'access_token' in self.server.query_params:
                page = SUCCESS_PAGE
            else:
                page = ERROR_PAGE
>>>>>>> Started javascript redirect

        self.wfile.write(page.encode('utf-8'))

def get_config():
    return stups_cli.config.load_config('zign')


def get_tokens():
    try:
        with open(TOKENS_FILE_PATH) as fd:
            data = yaml.safe_load(fd)
    except:
        data = None
    return data or {}


def get_new_token(realm: str, scope: list, user, password, url=None, insecure=False):
    if not url:
        config = get_config()
        url = config.get('url')
    params = {'json': 'true'}
    if realm:
        params['realm'] = realm
    if scope:
        params['scope'] = ' '.join(filter(is_user_scope, scope))
    response = requests.get(url, params=params, auth=(user, password), verify=not insecure)
    if response.status_code == 401:
        raise AuthenticationFailed('Token Service returned {}'.format(response.text))
    elif response.status_code != 200:
        raise ServerError('Token Service returned HTTP status {}: {}'.format(response.status_code, response.text))
    try:
        json_data = response.json()
    except:
        raise ServerError('Token Service returned invalid JSON data')

    if not json_data.get('access_token'):
        raise ServerError('Token Service returned invalid JSON (access_token missing)')
    return json_data


def get_existing_token(name: str) -> dict:
    '''Return existing token if it exists and if it's valid, return None otherwise'''
    data = get_tokens()
    existing_token = data.get(name)
    if is_valid(existing_token):
        return existing_token


def store_token(name: str, result: dict):
    data = get_tokens()

    data[name] = result
    data[name]['creation_time'] = time.time()

    dir_path = os.path.dirname(TOKENS_FILE_PATH)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    with open(TOKENS_FILE_PATH, 'w') as fd:
        yaml.safe_dump(data, fd)


def get_token_browser_redirect(name, refresh=False, auth_url=None, scope=None, client_id=None,
                                     business_partner_id=None):
    '''Get a named access token and opens a browser to authenticate through the configured auth URL'''

    if name and not refresh:
        existing_token = get_existing_token(name)
        # This will clear any non-JWT tokens
        if existing_token and existing_token.get('access_token').count('.') >= 2:
            return existing_token

    config = get_config()

    auth_url = auth_url or config.get('auth_url')
    scope = scope or config.get('scope')
    client_id = client_id or config.get('client_id')
    business_partner_id = business_partner_id or config.get('business_partner_id')

    while not auth_url:
        auth_url = click.prompt('Please enter the OAuth access token service URL', type=UrlType())

        try:
            requests.get(auth_url, timeout=5)
        except RequestException:
            error('Could not reach {}'.format(auth_url))
            auth_url = None

        config['auth_url'] = auth_url

    while not scope:
        scope = click.prompt('Please enter the scope to be requested')
        config['scope'] = scope

    while not client_id:
        client_id = click.prompt('Please enter the client ID')
        config['client_id'] = client_id

    while not business_partner_id:
        business_partner_id = click.prompt('Please enter the business partner ID')
        config['business_partner_id'] = business_partner_id

    stups_cli.config.store_config(config, 'zign')

    success = False
    port_number = 8081
    max_port_number = port_number + 100

    while True:
        try:
            httpd = tools.ClientRedirectServer(('localhost', port_number), ClientRedirectHandler)
        except socket.error as e:
            if port_number > max_port_number:
                success = False
                break
            port_number += 1
        else:
            success = True
            break

    if success:
        redirect_uri = 'http://localhost:{}'.format(port_number)

        params = { 'response_type' : 'token',
                   'scope' : config['scope'],
                   'business_partner_id': config['business_partner_id'],
                   'client_id': config['client_id'],
                   'redirect_uri': 'http://localhost:{}'.format(port_number) }

        param_list = [ '{}={}'.format(key, params[key]) for key in params ]
        param_string = '&'.join(param_list)

        parsed_auth_url = urlparse(auth_url)
        browser_url = urlunsplit((parsed_auth_url.scheme, parsed_auth_url.netloc, parsed_auth_url.path,
                              param_string, ''))


        webbrowser.open(browser_url, new=1, autoraise=True)
        click.echo('Your browser has been opened to visit:\n\n\t{}\n'.format(browser_url))
    else:
        raise AuthenticationFailed('Failed to launch local server')

    httpd.handle_request()
    print(httpd.query_params)
    if 'access_token' in httpd.query_params:
        token = httpd.query_params['access_token']
    else:
        raise AuthenticationFailed('Failed to retrieve token')

    return token


def get_named_token(scope, realm, name, user, password, url=None,
                    insecure=False, refresh=False, use_keyring=True, prompt=False):
    '''get named access token, return existing if still valid'''

    if name and not refresh:
        existing_token = get_existing_token(name)
        if existing_token:
            return existing_token

    if name and not realm:
        access_token = get_service_token(name, scope)
        if access_token:
            return {'access_token': access_token}

    config = get_config()

    url = url or config.get('url')

    while not url and prompt:
        url = click.prompt('Please enter the OAuth access token service URL', type=UrlType())

        try:
            requests.get(url, timeout=5, verify=not insecure)
        except:
            error('Could not reach {}'.format(url))
            url = None

        config['url'] = url

    stups_cli.config.store_config(config, 'zign')

    password = password or keyring.get_password(KEYRING_KEY, user)

    while True:
        if not password and prompt:
            password = click.prompt('Password for {}'.format(user), hide_input=True)

        try:
            result = get_new_token(realm, scope, user, password, url=url, insecure=insecure)
            break
        except AuthenticationFailed as e:
            if prompt:
                error(str(e))
                info('Please check your username and password and try again.')
                password = None
            else:
                raise

    if result and use_keyring:
        keyring.set_password(KEYRING_KEY, user, password)

    if name:
        store_token(name, result)

    return result


def is_valid(token: dict):
    now = time.time()
    return token and now < (token.get('creation_time', 0) + token.get('expires_in', 0) - TOKEN_MINIMUM_VALIDITY_SECONDS)


def is_user_scope(scope: str):
    '''Is the given scope supported for users (employees) in Token Service?'''
    return scope in set(['uid', 'cn'])


def get_service_token(name: str, scopes: list):
    '''Get service token (tokens lib) if possible, otherwise return None'''
    tokens.manage(name, scopes)
    try:
        access_token = tokens.get(name)
    except tokens.ConfigurationError:
        # will be thrown if configuration is missing (e.g. OAUTH2_ACCESS_TOKEN_URL)
        access_token = None
    except tokens.InvalidCredentialsError:
        # will be thrown if $CREDENTIALS_DIR/*.json cannot be read
        access_token = None

    return access_token


def get_token(name: str, scopes: list):
    '''Get an OAuth token, either from Token Service
    or directly from OAuth provider (using the Python tokens library)'''

    # first try if a token exists already
    token = get_existing_token(name)

    if token:
        return token['access_token']

    access_token = get_service_token(name, scopes)
    if access_token:
        return access_token

    config = get_config()
    user = config.get('user') or os.getenv('ZIGN_USER') or os.getenv('USER')

    if not user:
        raise ConfigurationError('Missing OAuth username. ' +
                                 'Either set "user" in configuration file or ZIGN_USER environment variable.')

    if not config.get('url'):
        raise ConfigurationError('Missing OAuth access token service URL. ' +
                                 'Please set "url" in configuration file.')

    password = os.getenv('ZIGN_PASSWORD') or keyring.get_password(KEYRING_KEY, user)
    token = get_new_token(config.get('realm'), scopes, user, password,
                          url=config.get('url'), insecure=config.get('insecure'))
    if token:
        store_token(name, token)
        return token['access_token']
