from ydsdk import YdSdk

sdk = YdSdk({
    "app_id": 'KjCBrsqvrKH2fjSiYx9J',
    "app_secert": 'ade3f5cbb354b1e91d72bd9ddd242595', 
    "api_pre": "http://api4.yd.local.cn/V4/",
    'user_id': 88350, 
    "client_ip": "127.0.0.1",
    "user_agent": "",
    "timeout": 30,
})

## get
raw, body, err = sdk.get('firewall.oplog')
if err != "":
    print("error: ", err)
else:
    print(raw, body)

### post
#postData = {'body1': 1, 'body2': 2}
#query    = {'domain_id': 1, 'group_id': 0}
#raw, body, err = sdk.post('firewall.policy.save', postData = postData, query=query)
#print(raw, body, err)
