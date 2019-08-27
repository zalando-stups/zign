import pytest
import socket
import zign.oauth2


def test_raises_on_used_port():
    server1 = zign.oauth2.ClientRedirectServer(('localhost', 8081))

    with pytest.raises(socket.error):
        server2 = zign.oauth2.ClientRedirectServer(('localhost', 8081))
