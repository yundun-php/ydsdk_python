import ssl
import json
import time
import socket
import string
import urllib
import platform
import hashlib, base64, hmac
from inspect import ismethod
from collections import OrderedDict
from socket import timeout as timeoutError
from urllib.error import URLError, HTTPError
from urllib.parse import quote, unquote, urlencode
from urllib.request import Request, urlopen, HTTPRedirectHandler, build_opener
from urllib.request import HTTPBasicAuthHandler, HTTPPasswordMgrWithDefaultRealm, ProxyHandler, ProxyBasicAuthHandler, HTTPSHandler

version = "0.2.0"

machineIpCount = 0
machineIp = "0.0.0.0"
machineIpLastArgsKey = ""

def ksort(raw):
    orderData = OrderedDict({})
    kAll = raw.keys()
    kSort = sorted(kAll)
    for k in kSort:
        if isinstance(raw[k], dict):
            orderData[k] = ksort(raw[k])
        else:
            orderData[k] = raw[k]
    return orderData

def get_machine_ip(ipVersion = 4, dest="119.29.29.29", port=53):
    """查询本机ip地址: 网络通发udp包取IP; 网络不通，根据host取ip"""
    global machineIp, machineIpCount, machineIpLastArgsKey
    argsKey = "%d-%s-%d" % (ipVersion, dest, port)
    if machineIp != "0.0.0.0" and argsKey == machineIpLastArgsKey and machineIpCount < 100:
        machineIpCount = machineIpCount + 1
        return machineIp

    machineIpCount = 0
    machineIpLastArgsKey = argsKey
    try:
        if ipVersion == 4:
            procotol = socket.AF_INET
        else:
            procotol = socket.AF_INET6
        s = socket.socket(procotol, socket.SOCK_DGRAM)
        s.connect((dest, port))
        machineIp = s.getsockname()[0]
    except:
        ## 网络不通，取host
        machineIp = socket.gethostbyname(socket.getfqdn(socket.gethostname()))
    finally:
        s.close()
    return machineIp

def url_encoder(params):
    g_encode_params = {}

    def _encode_params(params, p_key=None):
        encode_params = {}
        if isinstance(params, dict):
            for key in params:
                encode_key = '{}[{}]'.format(p_key,key)
                encode_params[encode_key] = params[key]
        elif isinstance(params, (list, tuple)):
            for offset,value in enumerate(params):
                encode_key = '{}[{}]'.format(p_key, offset)
                encode_params[encode_key] = value
        else:
            g_encode_params[p_key] = params

        for key in encode_params:
            value = encode_params[key]
            _encode_params(value, key)

    if isinstance(params, dict):
        for key in params:
            _encode_params(params[key], key)

    return urlencode(g_encode_params)

class RedirectHandler(HTTPRedirectHandler):
    '''捕获重定向信息'''
    redirects = []

    def __init__(self):
        self.redirects = []

    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        self.redirects.append({'code':code, 'url':newurl})
        return HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, hdrs, newurl)

class YdSdk:
    """云盾SDK
    支持get/post/patch/put/delete方法
    参数说明
        app_id 云盾分配的app_id
        app_secert 云盾分配的app_secert, 用于签名数据
        api_pre api前缀
        user_id 当前使用者在云盾的用户ID
        timeout 请求超时时间，默认10秒，请合理设置
    每次调用会返回三个参数：(原始字符串，解析后的json字典，错误字符串)
    注意事项
        针对所有请求，uri与get参数是分离的，如 https://apiv4.yundun.com/V4/version?v=1, 调用时v=1参数，须通过query传递

    示例：
        ### 实例化 YdSdk
        import logging
        from ydsdk import YdSdk

        ## 添加日志
        logger = logging.getLogger()
        formatter = logging.Formatter('%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s')
        
        ##日志输出到文件
        fileHandle = logging.FileHandler('/tmp/ydsdk.log', encoding='utf-8')
        fileHandle.setFormatter(formatter)
        logger.addHandler(fileHandle)
        
        ##日志输出到stdout
        streamHandle = logging.StreamHandler()
        streamHandle.setFormatter(formatter)
        logger.addHandler(streamHandle)

        sdk = YdSdk({
            "app_id": 'xxxxxxxxxxxxxxxx',
            "app_secert": 'xxxxxxxxxxxxxxxxxxxxxxxxxx', 
            "api_pre": "https://apiv4.yundun.com/V4/",
            "user_id": 1, 
            "timeout": 30,
            "logger": logger,               ##如果不需要，此参数可不传
        })

        ### get 方式请求数据
        raw, jsonData, err = sdk.get('test')
        print(raw, jsonData, err)
        
        ### post/put/patch/delete 方式请求数据
        query    = {}
        postData = {'domain_id': 1, 'status': 2}
        raw, body, err = sdk.post('test.save', postData = postData, query=query)
        print(raw, jsonData, err)
    """

    _code = 0                                                   ## 异常状态码
    _host = ""                                                  ## 指定 Host 头
    _msg = '同步请求异常！请稍后重试！或者联系技术支持！'       ## 异常提示信息
    _appId = ""                                                 ## 分配置appId
    _appSecert = ""                                             ## 分配置appSecert
    _headers = {}                                               ## 请求头
    _apiPre = ''                                                ## api前缀
    _timeout = 30                                               ## 超时设置
    _userId = 0                                                 ## 用户ID
    _clientIp = ""                                              ## 客户端IP
    _userAgent = ""                                             ## userAgent, 内置
    _logger = None

    def __init__(self, params = {}):
        global version
        uname = platform.uname()
        self._appId     = 'app_id' in params     and params['app_id']       or ''
        self._appSecert = 'app_secert' in params and params['app_secert']   or ''
        self._userId    = 'user_id' in params    and params['user_id']      or 0
        self._clientIp  = get_machine_ip()                                                      ## 自动取机器IP
        self._userAgent = 'YdSdk %s; Python-urllib/%s; %s %s' % (version, platform.python_version(), uname[0], uname[2])
        self._apiPre    = 'api_pre' in params    and params['api_pre'].rstrip("/")      or ''
        self._host      = 'host' in params       and params['host']         or ''
        self._timeout   = 'timeout' in params    and params['timeout']      or 30
        if 'logger' in params:
            logger = params['logger']
            if ismethod(logger.debug) and ismethod(logger.info) and ismethod(logger.warning) and ismethod(logger.error):
                self._logger = logger
            else:
                raise Exception("logger object must has function: debug/info/warning/error")

    def sign(self, data={}):
        data['algorithm'] = 'HMAC-SHA256'
        data['issued_at'] = str(time.time())
        orderData = ksort(data)
        jraw = json.dumps(orderData, separators=(',', ':'))
        base64Raw = base64.b64encode(jraw.encode('utf-8'))
        sign = base64.b64encode(hmac.new(self._appSecert.encode('utf-8'), base64Raw, digestmod=hashlib.sha256).digest())
        signStr = sign.decode('utf-8')
        signReplace = signStr.replace("+", "-")
        signReplace = signReplace.replace("/", "_")
        return signReplace

    def formatHeaders(self, headers = {}):
        '''格式化header头'''
        headersDict = {}
        for row in headers:
            headersDict[row[0]] = row[1]
        return headersDict

    def _payload(self, payload = {}, headers = {}):
        '''构造payload数据, 并对数据做签名'''
        payload['user_id']          = str(self._userId)
        payload['client_ip']        = self._clientIp
        payload['client_userAgent'] = self._userAgent

        headers['X-Auth-Sign']   = self.sign(payload)
        headers['X-Auth-App-Id'] = self._appId
        headers['X-Auth-Sdk-Version'] = '1.0.3'
        headers['Content-Type']  = "application/json;charset=utf-8"
        headers['User-Agent']    = self._userAgent
        if self._host != "": headers['HOST']  = self._host
        return payload, headers

    def get(self, api, query = {}, headers = {}):
        '''GET请求'''
        api = api.lstrip("/")
        orderPayload, headers = self._payload(query, headers)
        bodyQuery = url_encoder(orderPayload)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre, api) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        result, requestDataStr =  self.request(api, 'GET', headers=headers)
        return self.parseResponse(result, requestDataStr)

    def post(self, api, query = {}, postData={}, headers = {}):
        '''POST请求'''
        api = api.lstrip("/")
        orderPayload, headers = self._payload(postData, headers)
        bodyQuery = url_encoder(query)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre, api) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        result, requestDataStr =  self.request(api, 'POST', data=orderPayload, headers=headers)
        return self.parseResponse(result, requestDataStr)

    def patch(self, api, query = {}, postData={}, headers = {}):
        '''PATCH请求'''
        api = api.lstrip("/")
        orderPayload, headers = self._payload(postData, headers)
        bodyQuery = url_encoder(query)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre, api) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        result, requestDataStr =  self.request(api, 'PATCH', data=orderPayload, headers=headers)
        return self.parseResponse(result, requestDataStr)

    def put(self, api, query = {}, postData={}, headers = {}):
        '''PUT请求'''
        api = api.lstrip("/")
        orderPayload, headers = self._payload(postData, headers)
        bodyQuery = url_encoder(query)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre, api) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        result, requestDataStr =  self.request(api, 'PUT', data=orderPayload, headers=headers)
        return self.parseResponse(result, requestDataStr)

    def delete(self, api, query = {}, postData={}, headers = {}):
        '''DELETE请求'''
        api = api.lstrip("/")
        orderPayload, headers = self._payload(postData, headers)
        bodyQuery = url_encoder(query)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre, api) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        result, requestDataStr =  self.request(api, 'DELETE', data=orderPayload, headers=headers)
        return self.parseResponse(result, requestDataStr)

    def parseResponse(self, result, requestDataStr):
        '''解析 response'''
        body = result['body'].decode('utf-8')
        if result['http_code'] == 0:
            return body, {}, result['error']
        else:
            if len(body) > 2 and body[0] == "{" and body[-1] == "}":
                try:
                    return body, json.loads(body), ""
                except json.decoder.JSONDecodeError as e:
                    if self._logger is not None: self._logger.error("%s responseBody: %s requestData: %s" % (repr(e), body, requestDataStr))
                    return body, {}, "json decode error: %s" % repr(e)
            else:
                if self._logger is not None: self._logger.error('the response body is not json, responseBody: %s requestData: %s' % (body, requestDataStr))
                return body, {}, 'the response body is not json'

    def request(self, url=None, method="GET", data={}, headers={}, auth={}, proxy={}):
        '''发起请求'''
        method = method.upper()
        requestDataStr = json.dumps({"url": url, "method": method, "data": data, "headers": headers}, ensure_ascii=False)
        start = time.time()
        try:
            #跳转记录
            redirect_handler = RedirectHandler()
    
            #basic验证
            auth_handler = HTTPBasicAuthHandler()
            if auth and 'user' in auth.keys() and 'passwd' in auth.keys():
                passwdHandler = HTTPPasswordMgrWithDefaultRealm()
                passwdHandler.add_password(realm=None, uri=url, user=auth['user'], passwd=auth['passwd'])
                auth_handler = HTTPBasicAuthHandler(passwdHandler)
    
            #代理
            proxy_handler = ProxyHandler()
            if proxy and 'url' in proxy.keys():
               proxy_handler = ProxyHandler({'http': proxy['url']})
    
            #代理验证
            proxy_auth_handler = ProxyBasicAuthHandler()
            if proxy and 'url' in proxy.keys() and 'user' in proxy.keys() and 'passwd' in proxy.keys():
               proxyPasswdHandler = HTTPPasswordMgrWithDefaultRealm()
               proxyPasswdHandler.add_password(realm=None, uri=proxy['url'], user=proxy['user'], passwd=proxy['passwd'])
               proxy_auth_handler = ProxyBasicAuthHandler(proxyPasswdHandler)
    
            #HTTPS
            context = ssl.SSLContext()
            context.verify_mode = ssl.CERT_NONE
            context.check_hostname = False
            https_handler = HTTPSHandler(context=context)
            body = json.dumps(data).encode('utf-8')
    
            opener = build_opener(redirect_handler, auth_handler, proxy_handler, proxy_auth_handler, https_handler)
            request_handler= Request(quote(url, safe=string.printable), data=body, method=method)
            for key, value in headers.items():
                request_handler.add_header(key, value)
            response = opener.open(request_handler, timeout=self._timeout)
            end = time.time()
            return {
                'url': url,
                'method': method,
                'request_headers': request_handler.headers,
                'response_headers': self.formatHeaders(response.getheaders()),
                'http_code': response.status,
                'redirects':redirect_handler.redirects,
                'body': response.read(),
                'nettime': end-start,
                'error':''
            }, requestDataStr
        except HTTPError as e:          # 400 401 402 403 500 501 502 503 504
            if self._logger is not None: self._logger.error("%s requestData: %s" % (repr(e), requestDataStr))
            end = time.time()
            return {
                'url': url,
                'method': method,
                'request_headers': headers,
                'response_headers': dict(e.headers),
                'http_code': e.code,
                'redirects': [],
                'body': b'',
                'nettime': end-start,
                'error': repr(e)
            }, requestDataStr
        except URLError as e:
            if self._logger is not None: self._logger.error("%s requestData: %s" % (repr(e), requestDataStr))
            end = time.time()
            return {
                'url': url,
                'method': method,
                'request_headers': headers,
                'response_headers': {},
                'http_code': 0,
                'redirects': [],
                'body': b'',
                'nettime': end-start,
                'error': repr(e)
            }, requestDataStr
        except timeoutError as e:
            if self._logger is not None: self._logger.error("%s requestData: %s" % (repr(e), requestDataStr))
            end = time.time()
            return {
                'url': url,
                'method': method,
                'request_headers': headers,
                'response_headers': {},
                'http_code': 0,
                'redirects': [],
                'body': b'',
                'nettime': end-start,
                'error': repr(e)
            }, requestDataStr
        except Exception as e:
            if self._logger is not None: self._logger.error("%s requestData: %s" % (repr(e), requestDataStr))
            return {
                'url': url,
                'method': method,
                'request_headers': headers,
                'response_headers': {},
                'http_code': 0,
                'redirects': [],
                'body': b'',
                'nettime': 0,
                'error': repr(e)
            }, requestDataStr

__all__ = ["get_machine_ip", "YdSdk"]
