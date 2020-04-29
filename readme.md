# 云盾 api sdk for python

### 说明

* 接口基地址： 'http://apiv4.yundun.com/V4/';
* 接口遵循RESTful,默认请求体json,接口默认返回json
* app_id, app_secret 联系技术客服，先注册一个云盾的账号，用于申请绑定api身份

### 签名算法

* 每次请求都签名，保证传输过程数据不被篡改
* 客户端：sha256签名算法，将参数base64编码+app_secret用sha256签名，每次请求带上签名
* 服务端：拿到参数用相同的算法签名，对比签名是否正确

### sdk 使用说明

* 环境：python >=3.5
* 支持get/post/patch/put/delete方法
* 参数说明
    * app_id 云盾分配的app_id
    * app_secert 云盾分配的app_secert, 用于签名数据
    * api_pre api前缀
    * user_id 当前使用者在云盾的用户ID
    * timeout 请求超时时间，默认10秒，请合理设置
* 每次调用会返回三个参数：(原始字符串，解析后的json字典，错误字符串)
* 注意事项
    针对所有请求，uri与get参数是分离的，如 http://apiv4.yundun.com/V4/version?v=1, 调用时v=1参数，须通过query传递
        raw, body, err = sdk.get('version', query={'v': 1})

### 安装

pip install ydsdk

### 使用

```
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
    "app_id": 'xxxxxxxxxxx',
    "app_secert": 'xxxxxxxxxxxxx', 
    "api_pre": "http://apiv4.yundun.com/V4/",
    "user_id": 1, 
    "timeout": 30,
    "logger": logger,               ##如果不需要，此参数可不传
})

### get 方式请求数据
raw, jsonData, err = sdk.get('test')
print(raw, jsonData, err)

### post 方式请求数据
query    = {}
postData = {'domain_id': 1, 'status': 2}
raw, body, err = sdk.post('test.save', postData = postData, query=query)
print(raw, jsonData, err)

### patch 方式请求数据
query    = {}
postData = {'domain_id': 1, 'status': 2}
raw, body, err = sdk.patch('test.save', postData = postData, query=query)
if err != "":
    print("error: ", err)
else:
    print(raw, jsonData)

### put 方式请求数据
query    = {}
postData = {'domain_id': 1, 'status': 2}
raw, body, err = sdk.put('test.save', postData = postData, query=query)
print(raw, jsonData, err)

### delete 方式请求数据
query    = {}
postData = {'domain_id': 1, 'status': 2}
raw, body, err = sdk.put('test.save', postData = postData, query=query)
print(raw, jsonData, err)


### put方式请求数据
query    = {}
postData = {'domain_id': 1, 'status': 2}
raw, body, err = sdk.put('test.save', postData = postData, query=query)
print(raw, jsonData, err)
```

### 更新日志

#### 2020.04.29 v0.1.7
```
规范demo中的api地址
```
