# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.

    .. spelling::

       auth
       http
"""
from typing import Optional
import requests
import time
import base64
from ...http import httpHeaders
from ..exception import ProxyAuthenticationFailed
from ...http.proxy import HttpProxyBasePlugin
from ...http.parser import HttpParser


class AuthPlugin(HttpProxyBasePlugin):
    """Performs proxy authentication."""
    def checkuser(user,password):
        for i in range(1,60):
            print("checkuser: "+ str(i))
            try:
                url = 'http://sellgmail.us:5050/api/action=checkuser_proxy&user='+user+'&pass='+password
                response = requests.get(url,timeout=30)
                contentstr=str(response.content)
                if contentstr.find('ok')>=0:
                    print('checkuser ok')
                    return 1
            except:
                print('loi  checkuser')
            time.sleep(1)
    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        #print(httpHeaders.PROXY_AUTHORIZATION)
        #print("code")
        #print(self.flags.auth_code)
        proxynhap=b'dXNlcjE6cGFzc3dvcmQx'
        if proxynhap and request.headers:
            if httpHeaders.PROXY_AUTHORIZATION not in request.headers:
                raise ProxyAuthenticationFailed()
            parts = request.headers[httpHeaders.PROXY_AUTHORIZATION][1].split()
            decoded_data = base64.b64decode(parts[1])
            result = decoded_data.decode('utf-8').split(':')
            print(result[0])
            print(result[1])
            if len(parts) != 2 \
                    or parts[0].lower() != b'basic' \
                    or parts[1] != proxynhap:
                raise ProxyAuthenticationFailed()
        return request
