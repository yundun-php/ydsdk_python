### 实例化 YdSdk
import logging
from ydsdk import YdSdk

## 添加日志
logger = logging.getLogger()
formatter = logging.Formatter('%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s')
logger.setLevel(10)

##日志输出到文件
fileHandle = logging.FileHandler('/tmp/ydsdk.log', encoding='utf-8')
fileHandle.setFormatter(formatter)
logger.addHandler(fileHandle)

##日志输出到stdout
streamHandle = logging.StreamHandler()
streamHandle.setFormatter(formatter)
logger.addHandler(streamHandle)

def printResult(raw, jsonData, err):
    print("raw：", raw)
    if err == "":
        if "status" in jsonData:
            print("请求成功：", jsonData["status"]["code"], jsonData["status"]["message"])
        elif "code" in jsonData:
            print("请求成功：", jsonData["code"])
        else:
            pass
    else:
        print("请求失败：", err)
    print("")

sdk = YdSdk({
    "app_id": 'xxxxxxxxxxxxxxxxxxxx',
    "app_secert": 'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy', 
    "api_pre": "http://api.local.com/V4/",
    'user_id': 1111, 
    "timeout": 30,
    "client_ip": "127.0.0.1",
    "user_agent": "",
    'logger': logger,
})

##### get 方式请求数据
##raw, jsonData, err = sdk.get('test.sdk.get')
###raw, jsonData, err = sdk.get('Web.Domain.list')
##print(raw, jsonData, err)

postData = {
    'ca_name': 'git.nodevops.cn',
    'ca_crt_file_name': 'git.nodevops.cn.pem',
    'ca_key_file_name': 'git.nodevops.cn.key',
    'ca_cert':'',
    'ca_key':'',
}
files = [
    ('ca_crt', ('git.nodevops.cn.pem', open('./x.pem', 'rb'), 'image/png')),
    ('ca_key', ('git.nodevops.cn.key', open('./x.key', 'rb'), 'image/png')),
]
raw, body, err = sdk.post('Web.ca.self.add', postData=postData, files=files)
printResult(raw, body, err)
