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
    "app_id": 'KjCBrsqvrKH2fjSiYx9J',
    "app_secert": 'ade3f5cbb354b1e91d72bd9ddd242595', 
    #"api_pre": "http://api4.yd.local.cn/V4/",
    "api_pre": "http://yundunapiv4.test.nodevops.cn/V4/",
    'user_id': 88350, 
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
    ('ca_crt', ('git.nodevops.cn.pem', open('/home/jingwu/Downloads/git.nodevops.cn.pem', 'rb'), 'image/png')),
    ('ca_key', ('git.nodevops.cn.key', open('/home/jingwu/Downloads/git.nodevops.cn.key', 'rb'), 'image/png')),
]
raw, body, err = sdk.post('Web.ca.self.add', postData=postData, files=files)
printResult(raw, body, err)
