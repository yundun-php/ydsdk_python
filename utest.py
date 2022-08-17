## 单元测试

import unittest
from ydsdk import YdSdk
from unittest import TestCase

class TestYdSdk(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sdk = YdSdk({
            "app_id": 'xxxxxxxxxxxxxxxxxxxx',
            "app_secert": 'yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy', 
            "api_pre": "http://api.local.com/V4/",
            'user_id': 1111, 
            "client_ip": "127.0.0.1",
            "user_agent": "",
            "timeout": 30,
        })
        cls._queryKey = "id"
        cls._query = {cls._queryKey: '1'}
        cls._postKey = "name"
        cls._post = {cls._postKey: 'tester'}

    @classmethod
    def tearDownClass(cls):
        pass

    def test_get(self):
        api = 'test.sdk.get'

        raw, body, err = self.sdk.get(api, self._query)
        self.assertEqual(body['status']['code'], 1)
        self.assertEqual(body['data'][self._queryKey], self._query[self._queryKey])

        raw, body, err = self.sdk.post(api, self._query)
        self.assertEqual(body['status']['code'], 2)

    def test_put(self):
        api = 'test.sdk.put'

        raw, body, err = self.sdk.put(api, self._query, self._post)
        self.assertEqual(body['status']['code'], 1)
        self.assertEqual(body['data'][self._queryKey], self._query[self._queryKey])
        self.assertEqual(body['data'][self._postKey], self._post[self._postKey])

        raw, body, err = self.sdk.post(api, self._query, self._post)
        self.assertEqual(body['status']['code'], 2)

    def test_post(self):
        api = 'test.sdk.post'

        raw, body, err = self.sdk.post(api, self._query, self._post)
        self.assertEqual(body['status']['code'], 1)
        self.assertEqual(body['data'][self._queryKey], self._query[self._queryKey])
        self.assertEqual(body['data'][self._postKey], self._post[self._postKey])

        raw, body, err = self.sdk.put(api, self._query, self._post)
        self.assertEqual(body['status']['code'], 2)

    def test_patch(self):
        api = 'test.sdk.patch'

        raw, body, err = self.sdk.patch(api, self._query, self._post)
        self.assertEqual(body['status']['code'], 1)
        self.assertEqual(body['data'][self._queryKey], self._query[self._queryKey])
        self.assertEqual(body['data'][self._postKey], self._post[self._postKey])

        raw, body, err = self.sdk.post(api, self._query, self._post)
        self.assertEqual(body['status']['code'], 2)

    def test_delete(self):
        api = 'test.sdk.delete'

        raw, body, err = self.sdk.delete(api, self._query, self._post)
        self.assertEqual(body['status']['code'], 1)
        self.assertEqual(body['data'][self._queryKey], self._query[self._queryKey])
        self.assertEqual(body['data'][self._postKey], self._post[self._postKey])

        raw, body, err = self.sdk.post(api, self._query, self._post)
        self.assertEqual(body['status']['code'], 2)

    def test_domain_set_save(self):
        ## 602 为签名失败，此处仅验证深度数据排序时的问题
        api = 'web.domain.set.save'
        postData = {"domain_id":"233707","group":{"domain_proxy_conf":{"max_fails":"300","fails_timeout":10,"keep_new_src_time":30,"proxy_keepalive":0,"proxy_connect_timeout":30,"s":"/v5manage/webcdndomain/saveProxyConf"}}}
        raw, body, err = self.sdk.put(api, self._query, postData)
        self.assertNotEqual(body['status']['code'], 602)

if __name__ == '__main__':
    unittest.main()

