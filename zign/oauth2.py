from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse


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


class ClientRedirectHandler(BaseHTTPRequestHandler):
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
            query_params = {}
            for key, val in parse_qs(query_string).items():
                query_params[key] = val[0]
            self.server.query_params = query_params
            if 'access_token' in self.server.query_params:
                page = SUCCESS_PAGE
            else:
                page = ERROR_PAGE
            self.wfile.write(page.encode('utf-8'))

    def log_message(self, format, *args):
        """Do not log messages to stdout while running as cmd. line program."""


class ClientRedirectServer(HTTPServer):
    """A server to handle OAuth 2.0 redirects back to localhost.

    Waits for a single request and parses the query parameters
    into query_params and then stops serving.
    """
    query_params = {}

    def __init__(self, address):
        super().__init__(address, ClientRedirectHandler)
