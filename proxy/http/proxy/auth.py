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

stattime=int(time.time())
datacheck=0
class AuthPlugin(HttpProxyBasePlugin):
    """Performs proxy authentication."""
    def checkuser(user,password):
        global stattime
        global datacheck
        entime=int(time.time())
        if stattime-entime>=60 or datacheck==0:
            stattime=int(time.time())
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
        else:
            return datacheck
        
    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        #print(httpHeaders.PROXY_AUTHORIZATION)
        #print("code")
        #print(self.flags.auth_code)
        global datacheck
        if self.flags.auth_code and request.headers:
            if httpHeaders.PROXY_AUTHORIZATION not in request.headers:
                raise ProxyAuthenticationFailed()
            parts = request.headers[httpHeaders.PROXY_AUTHORIZATION][1].split()
           
            
            if len(parts) != 2 or parts[0].lower() != b'basic':
                raise ProxyAuthenticationFailed()
            else :
                decoded_data = base64.b64decode(parts[1])
                result = decoded_data.decode('utf-8').split(':')
                print(result[0])
                print(result[1])
                datacheck=AuthPlugin.checkuser(result[0],result[1])
                if datacheck==1:
                    print("xac thuc ok")
                else:
                    raise ProxyAuthenticationFailed()
        return request
