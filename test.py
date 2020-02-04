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

sdk = YdSdk({
    #"app_id": 'imALmx7kWcvTk19Nse8W',
    #"app_secert": '9164ee655de3b220846fe8b98e6290ac',
    #"api_pre": "http://apiv4.yundun.com/V4/",
    "app_id": 'KjCBrsqvrKH2fjSiYx9J',
    "app_secert": 'ade3f5cbb354b1e91d72bd9ddd242595', 
    "api_pre": "http://api4.yd.local.cn/V4/",
    'user_id': 123377,
    "timeout": 30,
    'logger': logger,
})

### get 方式请求数据
raw, jsonData, err = sdk.get('test.sdk.get')
#raw, jsonData, err = sdk.get('Web.Domain.list')
print(raw, jsonData, err)
