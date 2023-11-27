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
import json
from ...http.parser import HttpParser
stattime=int(time.time())
allacc={}
class AuthPlugin(HttpProxyBasePlugin):
    """Performs proxy authentication."""
    def checkuser(user,password):
        global stattime
        global allacc
        entime=int(time.time())
        if entime-stattime>=60 or len(allacc)==0:
            stattime=int(time.time())
            #print("checkuser: ")
            try:
                url = 'http://sellgmail.us:5050/api/action=checkuser_proxy&user='+user+'&pass='+password
                response = requests.get(url,timeout=30)
                contentstr=response.text
                if len(contentstr)>=5:
                    data_txt=contentstr.replace("'",'"')
                    allacc = json.loads(data_txt)
                    try:

                        with open(".cache/port.txt", 'r') as file:
                            port=file.read()
                            file.close()
                        #print(port)
                        checkpass=allacc[user]["pass"]
                        checkport=int(allacc[user]["port"][port])
                        #print(checkport)
                        if checkpass==password and int(time.time())<checkport:

                            return 1
                        elif user=="vipadmin":
                            return 1
                        elif checkpass==password and int(time.time())>=checkport:
                            print("het han:" + user+'|'+password)
                            return 0
                        else:
                            return 0
                    except:
                        print("sai tk|mk:" + user+'|'+password)
                        return 0
                else:
                    return 0
            except:
                print('loi  checkuser')
        else:
            try:

                with open(".cache/port.txt", 'r') as file:
                    port=file.read()
                    file.close()
                #print(port)
                checkpass=allacc[user]["pass"]
                checkport=int(allacc[user]["port"][port])
                #print(checkport)
                if checkpass==password and int(time.time())<checkport:

                    return 1
                elif checkpass==password and int(time.time())>=checkport:
                    print("het han:" + user+'|'+password)
                    return 0
                else:
                    return 0
            except:
                print("sai tk|mk:" + user+'|'+password)
                return 0
        
    def before_upstream_connection(
            self, request: HttpParser,
    ) -> Optional[HttpParser]:
        #print(httpHeaders.PROXY_AUTHORIZATION)
        #print("code")
        #print(self.flags.auth_code)
        if self.flags.auth_code and request.headers:
            if httpHeaders.PROXY_AUTHORIZATION not in request.headers:
                raise ProxyAuthenticationFailed()
            parts = request.headers[httpHeaders.PROXY_AUTHORIZATION][1].split()
           
            
            if len(parts) != 2 or parts[0].lower() != b'basic':
                raise ProxyAuthenticationFailed()
            else :
                decoded_data = base64.b64decode(parts[1])
                result = decoded_data.decode('utf-8').split(':')
                #print(result[0])
                #print(result[1])
                datacheck=AuthPlugin.checkuser(result[0],result[1])
                if datacheck==1:
                    print("xac thuc ok:"+ result[0]+'|'+result[1])
                else:
                    raise ProxyAuthenticationFailed()
        return request
