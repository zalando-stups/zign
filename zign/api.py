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

from .config import KEYRING_KEY, OLD_CONFIG_NAME, CONFIG_NAME, REFRESH_TOKEN_FILE_PATH, TOKENS_FILE_PATH
from oauth2client import tools
from requests import RequestException
from urllib.parse import parse_qs
from urllib.parse import urlparse
from urllib.parse import urlunsplit

TOKEN_MINIMUM_VALIDITY_SECONDS = 60*5  # 5 minutes

SUCCESS_PAGE = '''<!DOCTYPE HTML>
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

EXTRACT_TOKEN_PAGE = '''<!DOCTYPE HTML>
<html lang="en-US">
  <head>
    <title>Redirecting...</title>
    <style>
        body {{
            font-family: sans-serif;
        }}
        #error {{
            color: red;
        }}
    </style>
    <script>
        (function extractFragmentQueryString() {{
            function displayError(message) {{
              var errorElement = document.getElementById("error");
              errorElement.textContent = message || "Unknown error";
            }}

            function parseQueryString(qs) {{
                return qs.split("&")
                        .reduce(function (result, param) {{
                          var split = param.split("=");
                          if (split.length === 2) {{
                            var key = decodeURIComponent(split[0]);
                            var val = decodeURIComponent(split[1]);
                            result[key] = val;
                          }}
                          return result;
                        }}, {{}});
            }}
            var query = window.location.hash.substring(1);
            var params = parseQueryString(query);
            if (params.access_token) {{
                window.location.href = "http://localhost:{port}/?" + query;
            }} else {{
                displayError("Error: No access_token in URL.")
            }}
        }})();
    </script>
  </head>
  <body>
    <noscript>
        <p>Your browser does not support Javascript! Please enable it or switch to a Javascript enabled browser.</p>
    </noscript>
    <p>Redirecting...</p>
    <p id="error"></p>
  </body>
</html>'''

ERROR_PAGE = '''<!DOCTYPE HTML>
<html lang="en-US">
  <head>
    <title>Authentication Failed - Zign</title>
  </head>
  <body>
    <p><font face=arial>The authentication flow did not complete successfully. Please try again. You may close this
    window.</font></p>
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

        if not query_string:
            self.wfile.write(EXTRACT_TOKEN_PAGE.format(port=self.server.server_port).encode('utf-8'))
        else:
            self.server.query_params = parse_qs(query_string)
            if 'access_token' in self.server.query_params:
                page = SUCCESS_PAGE
            else:
                page = ERROR_PAGE
            self.wfile.write(page.encode('utf-8'))


def get_config(config_module=None, override=None):
    '''Returns the specified module's configuration. Defaults to ztoken.

    Prompts for configuration values if ztoken module config is not present or has missing values.

    If override is present, only prompts for non-existent values.
    '''
    if not config_module or config_module == OLD_CONFIG_NAME:
        # backwards compatible (used by Piu!):
        return stups_cli.config.load_config(OLD_CONFIG_NAME)

    override = override or {}

    # Make sure no keys with empty values are present
    override = {k: v for (k, v) in override.items() if v}
    config = stups_cli.config.load_config(config_module)
    old_config = config.copy()

    for oauth2_url, message in {'authorize_url': 'Authorization', 'token_url': 'Token'}.items():
        while oauth2_url not in override and oauth2_url not in config:
            config[oauth2_url] = click.prompt('Please enter the OAuth 2 {} Endpoint URL'.format(message),
                                              type=UrlType())

            try:
                requests.get(config[oauth2_url], timeout=5)
            except RequestException:
                error('Could not reach {}'.format(config[oauth2_url]))
                del config[oauth2_url]

    if 'client_id' not in override and 'client_id' not in config:
        config['client_id'] = click.prompt('Please enter the OAuth 2 Client ID')

    if 'business_partner_id' not in override and 'business_partner_id' not in config:
        config['business_partner_id'] = click.prompt('Please enter the Business Partner ID')

    if config != old_config:
        store_config_ztoken(config, config_module)

    config.update(override)
    return config


def get_tokens():
    return load_config_ztoken(TOKENS_FILE_PATH)


def load_config_ztoken(config_file: str):
    try:
        with open(config_file) as fd:
            data = yaml.safe_load(fd)
    except:
        data = None
    return data or {}


def get_new_token(realm: str, scope: list, user, password, url=None, insecure=False):
    if not url:
        config = get_config(OLD_CONFIG_NAME)
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

    store_config_ztoken(data, TOKENS_FILE_PATH)


def store_config_ztoken(data: dict, path: str):
    dir_path = os.path.dirname(path)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    with open(path, 'w') as fd:
        yaml.safe_dump(data, fd)


def get_token_implicit_flow(name=None, authorize_url=None, token_url=None, client_id=None, business_partner_id=None,
                            refresh=False):
    '''Gets a Platform IAM access token using browser redirect flow'''

    override = {'name':                 name,
                'authorize_url':        authorize_url,
                'token_url':            token_url,
                'client_id':            client_id,
                'business_partner_id':  business_partner_id}
    config = get_config(CONFIG_NAME, override=override)

    if name and not refresh:
        existing_token = get_existing_token(name)
        # This will clear any non-JWT tokens
        if existing_token and existing_token.get('access_token').count('.') >= 2:
            return existing_token

    data = load_config_ztoken(REFRESH_TOKEN_FILE_PATH)

    # Always try with refresh token first
    refresh_token = data.get('refresh_token')
    if refresh_token:
        payload = {'grant_type':            'refresh_token',
                   'client_id':             config['client_id'],
                   'business_partner_id':   config['business_partner_id'],
                   'refresh_token':         refresh_token}
        try:
            r = requests.post(config['token_url'], timeout=20, data=payload)
            r.raise_for_status()

            token = r.json()
            token['scope'] = ''
            if name:
                token['name'] = name
                store_token(name, token)

            # Store the latest refresh token
            store_config_ztoken({'refresh_token': token['refresh_token']}, REFRESH_TOKEN_FILE_PATH)
            return token
        except RequestException as exception:
            error(exception)

    # Get new token
    success = False
    # Must match redirect URIs in client configuration (http://localhost:8081-8181)
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
        params = {'response_type':          'token',
                  'business_partner_id':    config['business_partner_id'],
                  'client_id':              config['client_id'],
                  'redirect_uri':           'http://localhost:{}'.format(port_number)}

        param_list = ['{}={}'.format(key, params[key]) for key in params]
        param_string = '&'.join(param_list)
        parsed_authorize_url = urlparse(config['authorize_url'])
        browser_url = urlunsplit((parsed_authorize_url.scheme, parsed_authorize_url.netloc, parsed_authorize_url.path,
                                  param_string, ''))

        webbrowser.open(browser_url, new=1, autoraise=True)
        info('Your browser has been opened to visit:\n\n\t{}\n'.format(browser_url))
    else:
        raise AuthenticationFailed('Failed to launch local server')

    while not httpd.query_params:
        # Handle first request, which will redirect to Javascript
        # Handle next request, with token
        httpd.handle_request()

    if 'access_token' in httpd.query_params:
        token = {'access_token':    httpd.query_params['access_token'][0],
                 'refresh_token':   httpd.query_params['refresh_token'][0],
                 'expires_in':      int(httpd.query_params['expires_in'][0]),
                 'token_type':      httpd.query_params['token_type'][0],
                 'scope':           ''}

        store_config_ztoken({'refresh_token': token['refresh_token']}, REFRESH_TOKEN_FILE_PATH)
        stups_cli.config.store_config(config, CONFIG_NAME)

        if name:
            token['name'] = name
            store_token(name, token)
        return token
    else:
        raise AuthenticationFailed('Failed to retrieve token')


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

    config = get_config(OLD_CONFIG_NAME)

    url = url or config.get('url')

    while not url and prompt:
        url = click.prompt('Please enter the OAuth access token service URL', type=UrlType())

        try:
            requests.get(url, timeout=5, verify=not insecure)
        except:
            error('Could not reach {}'.format(url))
            url = None

        config['url'] = url

    stups_cli.config.store_config(config, OLD_CONFIG_NAME)

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

    config = get_config(OLD_CONFIG_NAME)
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
