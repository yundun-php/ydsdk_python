import json
import requests
import time
import copy
import socket
import string
import urllib
import platform
import hashlib, base64, hmac
from inspect import ismethod
from urllib.parse import urlencode
from collections import OrderedDict


version = "0.2.4"

machineIpCount = 0
machineIp = "0.0.0.0"
machineIpLastArgsKey = ""

## 字典转为有序字典
def toOrderedDict(raw):
    rawCopy = copy.deepcopy(raw)
    for k,v in rawCopy.items():
        if isinstance(v, dict):
            rawCopy[k] = toOrderedDict(v)
    return OrderedDict(rawCopy)

## 字典所有的值转字符串
def dictValueToStr(raw):
    rawCopy = copy.deepcopy(raw)
    for k,v in rawCopy.items():
        if isinstance(v, dict):
            rawCopy[k] = dictValueToStr(v)
        else:
            rawCopy[k] = str(v)
    return rawCopy

## 只排序一维key
def ksort(raw, dataFrom = ''):
    orderData = OrderedDict({})
    kAll = raw.keys()
    kSort = sorted(kAll)
    for k in kSort:
        if dataFrom == "get":
            if isinstance(raw[k], dict):
                orderData[k] = raw[k]
            else:
                orderData[k] = str(raw[k])
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
    _oldSign = False                                            ## 兼容旧版的签名发送机制

    def __init__(self, params = {}, oldSign = False):
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
        self._oldSign   = oldSign
        if 'logger' in params:
            logger = params['logger']
            if ismethod(logger.debug) and ismethod(logger.info) and ismethod(logger.warning) and ismethod(logger.error):
                self._logger = logger
            else:
                raise Exception("logger object must has function: debug/info/warning/error")

    def sign(self, data={}, dataFrom = ''):
        signData = copy.deepcopy(data)
        if "_files" in signData: del signData["_files"]

        orderData = ksort(signData, dataFrom)
        jraw = json.dumps(orderData, separators=(',', ':'))
        base64Raw = base64.b64encode(jraw.encode('utf-8'))
        sign = base64.b64encode(hmac.new(self._appSecert.encode('utf-8'), base64Raw, digestmod=hashlib.sha256).digest())
        if self._oldSign:
            return "%s.%s" % (sign.decode('utf-8'), base64Raw.decode('utf-8'))
        else:
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

    def _payload(self, query = {}, postData = {}, headers = {}, dataFrom = ''):
        '''构造payload数据, 并对数据做签名'''
        if dataFrom == 'get':
            query['user_id']          = str(self._userId)
            query['client_ip']        = self._clientIp
            query['client_userAgent'] = self._userAgent
            query['algorithm']        = 'HMAC-SHA256'
            query['issued_at']        = str(time.time())
        else:
            postData['user_id']          = self._userId
            postData['client_ip']        = self._clientIp
            postData['client_userAgent'] = self._userAgent
            postData['algorithm']        = 'HMAC-SHA256'
            postData['issued_at']        = str(time.time())
        query = dictValueToStr(query)
        signData = copy.deepcopy(query)
        for k, v in postData.items():
            signData[k] = v
        orderQuery = toOrderedDict(query)
        orderPostData = toOrderedDict(postData)
        orderSignData = toOrderedDict(signData)

        headers['X-Auth-Sign']   = self.sign(orderSignData, dataFrom)
        headers['X-Auth-App-Id'] = self._appId
        headers['X-Auth-Sdk-Version'] = '1.0.3'
        headers['Content-Type']  = "application/json;charset=utf-8"
        headers['User-Agent']    = self._userAgent
        if self._host != "": headers['HOST'] = self._host
        headersCopy = copy.deepcopy(headers)
        return orderQuery, orderPostData, headersCopy

    def get(self, api, query={}, headers={}):
        '''GET请求'''
        api = api.lstrip("/")
        dataFrom = 'get'
        orderQuery, orderPostData, headers = self._payload(query=query, headers=headers, dataFrom = dataFrom)
        bodyQuery = url_encoder(orderQuery)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre, api) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        try:
            requestDataStr = json.dumps({"url": api, "method": "GET", "data": {}, "headers": headers}, ensure_ascii=False)
            result = requests.get(api, headers=headers)
            return self.parseResponse({"body":result.text, "http_code":result.status_code, "error":""}, requestDataStr)
        except Exception as e:
            return "", 0, str(e)

    def post(self, api, query={}, postData={}, headers={}, files={}):
        '''POST请求'''
        api = api.lstrip("/")
        orderQuery, orderPostData, headers = self._payload(query=query, postData = postData, headers = headers)
        bodyQuery = url_encoder(orderQuery)

        del headers['Content-Type']
        api = bodyQuery == "" and "%s/%s" % (self._apiPre, api) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        try:
            requestDataStr = json.dumps({"url": api, "method": "GET", "data": {}, "headers": headers}, ensure_ascii=False)
            if files:
                result = requests.post(api, data=orderPostData, headers=headers, files=files)
            else:
                result = requests.post(api, json=orderPostData, headers=headers)
            return self.parseResponse({"body":result.text, "http_code":result.status_code, "error":""}, requestDataStr)
        except Exception as e:
            return "", 0, str(e)

    def patch(self, api, query = {}, postData={}, headers = {}):
        '''PATCH请求'''
        api = api.lstrip("/")
        orderQuery, orderPostData, headers = self._payload(query=query, postData = postData, headers = headers)
        bodyQuery = url_encoder(orderQuery)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre, api) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        try:
            requestDataStr = json.dumps({"url": api, "method": "GET", "data": {}, "headers": headers}, ensure_ascii=False)
            result = requests.patch(api, json=orderPostData, headers=headers)
            return self.parseResponse({"body":result.text, "http_code":result.status_code, "error":""}, requestDataStr)
        except Exception as e:
            return "", 0, str(e)

    def put(self, api, query = {}, postData={}, headers = {}):
        '''PUT请求'''
        api = api.lstrip("/")
        orderQuery, orderPostData, headers = self._payload(query=query, postData = postData, headers = headers)
        bodyQuery = url_encoder(orderQuery)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre, api) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        try:
            requestDataStr = json.dumps({"url": api, "method": "GET", "data": {}, "headers": headers}, ensure_ascii=False)
            result =  requests.put(api, json=orderPostData, headers=headers)
            return self.parseResponse({"body":result.text, "http_code":result.status_code, "error":""}, requestDataStr)
        except Exception as e:
            return "", 0, str(e)

    def delete(self, api, query = {}, postData={}, headers = {}):
        '''DELETE请求'''
        api = api.lstrip("/")
        orderQuery, orderPostData, headers = self._payload(query=query, postData = postData, headers = headers)
        bodyQuery = url_encoder(orderQuery)

        api = bodyQuery == "" and "%s/%s" % (self._apiPre, api) or "%s/%s?%s" % (self._apiPre, api, bodyQuery)
        try:
            requestDataStr = json.dumps({"url": api, "method": "GET", "data": {}, "headers": headers}, ensure_ascii=False)
            result = requests.delete(api, json=orderPostData, headers=headers)
            return self.parseResponse({"body":result.text, "http_code":result.status_code, "error":""}, requestDataStr)
        except Exception as e:
            return "", 0, str(e)

    def parseResponse(self, result, requestDataStr):
        '''解析 response'''
        #body = result['body'].decode('utf-8')
        body = result['body']
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

__all__ = ["get_machine_ip", "YdSdk"]
