## 单元测试

import unittest
from ydsdk import YdSdk
from unittest import TestCase

class TestYdSdk(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.sdk = YdSdk({
            "app_id": 'KjCBrsqvrKH2fjSiYx9J',
            "app_secert": 'ade3f5cbb354b1e91d72bd9ddd242595', 
            "api_pre": "http://api4.yd.local.cn/V4/",
            'user_id': 88350, 
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

if __name__ == '__main__':
    unittest.main()

