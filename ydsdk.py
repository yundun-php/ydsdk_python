import ssl
import json
import string
import urllib
from time import time
import hashlib, base64, hmac
from collections import OrderedDict
from socket import timeout as timeoutError
from urllib.error import URLError, HTTPError
from urllib.parse import quote, unquote, urlencode
from urllib.request import Request, urlopen, HTTPRedirectHandler, build_opener
from urllib.request import HTTPBasicAuthHandler, HTTPPasswordMgrWithDefaultRealm, ProxyHandler, ProxyBasicAuthHandler, HTTPSHandler

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
    """云盾SDK"""
    ##异常状态码
    _code = 0
    _host = ""
    _msg = '同步请求异常！请稍后重试！或者联系技术支持！'
    _appId = ""
    _appSecert = ""
    _headers = {}
    _apiPre = ''
    _timeout = 30
    _userId = 0
    _clientIp = ""
    _userAgent = ""

    def __init__(self, params = {}):
        self._appId         = 'app_id' in params     and params['app_id']       or ''
        self._appSecert     = 'app_secert' in params and params['app_secert']   or ''
        self._userId        = 'user_id' in params    and params['user_id']      or 0
        self._clientIp      = 'client_ip' in params  and params['client_ip']    or ''
        self._userAgent     = 'userAgent' in params  and params['userAgent']    or ''
        self._apiPre        = 'api_pre' in params    and params['api_pre'] or ''
        self._host          = 'host' in params       and params['host']         or ''
        self._timeout       = 'timeout' in params    and params['timeout']      or 30
        self._apiPre = (len(self._apiPre) > 0 and self._apiPre[-1] == '/') and self._apiPre[0:-1] or ("%s/" % self._apiPre)

    def sign(self, data={}):
        data['algorithm'] = 'HMAC-SHA256'
        data['issued_at'] = time()
        jraw = json.dumps(data, separators=(',', ':'))
        base64Raw = base64.b64encode(jraw.encode('utf-8'))
        sign = base64.b64encode(hmac.new(self._appSecert.encode('utf-8'), base64Raw, digestmod=hashlib.sha256).digest())
        return "%s.%s" % (sign.decode('utf-8'), base64Raw.decode('utf-8'))

    def formatHeaders(self, headers = {}):
        '''格式化header头'''
        headersDict = {}
        for row in headers:
            headersDict[row[0]] = row[1]
        return headersDict

    def _payload(self, payload = {}, headers = {}):
        '''构造payload数据, 并对数据做签名'''
        payload['user_id']          = self._userId
        payload['client_ip']        = self._clientIp
        payload['client_userAgent'] = self._userAgent
        orderPayload = OrderedDict({'body': payload})

        headers['X-Auth-Sign']   = self.sign(orderPayload)
        headers['X-Auth-App-Id'] = self._appId
        headers['Content-Type']  = "application/json;charset=utf-8"
        if self._host != "": headers['HOST']  = self._host
        return orderPayload, headers

    def get(self, api, query = {}, headers = {}):
        '''GET请求'''
        orderPayload, headers = self._payload(query, headers)
        bodyQuery = url_encoder(orderPayload)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        result =  self.request(api, 'GET', headers=headers)
        return self.parseResponse(result)

    def post(self, api, query = {}, postData={}, headers = {}):
        '''POST请求'''
        orderPayload, headers = self._payload(postData, headers)
        bodyQuery = url_encoder(query)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        result =  self.request(api, 'POST', data=orderPayload, headers=headers)
        return self.parseResponse(result)

    def patch(self, api, query = {}, postData={}, headers = {}):
        '''PATCH请求'''
        orderPayload, headers = self._payload(postData, headers)
        bodyQuery = url_encoder(query)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        result =  self.request(api, 'PATCH', data=orderPayload, headers=headers)
        return self.parseResponse(result)

    def put(self, api, query = {}, postData={}, headers = {}):
        '''PUT请求'''
        orderPayload, headers = self._payload(postData, headers)
        bodyQuery = url_encoder(query)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        result =  self.request(api, 'PUT', data=orderPayload, headers=headers)
        return self.parseResponse(result)

    def delete(self, api, query = {}, postData={}, headers = {}):
        '''DELETE请求'''
        orderPayload, headers = self._payload(postData, headers)
        bodyQuery = url_encoder(query)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        result =  self.request(api, 'DELETE', data=orderPayload, headers=headers)
        return self.parseResponse(result)
    
    def parseResponse(self, result):
        body = result['body']
        if result['http_code'] == 0:
            return body, {}, result['error']
        else:
            try: 
                return body.decode('utf-8'), json.loads(body.decode('utf-8')), ""
            except json.decoder.JSONDecodeError as e:
                return body.decode('utf-8'), {}, "json decode error: %s" % e

    def request(self, url=None, method="GET", data={}, headers={}, auth = {}, proxy={}):
        '''发起请求'''
        method = method.upper()
        start = time()
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
            end = time()
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
            }
        except HTTPError as e:          # 400 401 402 403 500 501 502 503 504
            end = time()
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
            }
        except URLError as e:
            end = time()
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
            }
        except timeoutError as e:
            end = time()
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
            }
        except Exception as e:
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
            }

