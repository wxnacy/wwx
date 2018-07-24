#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Author: wxnacy(wxnacy@gmail.com)
# Description:

from enum import Enum
import requests

class Action(Enum):
    token = 'token'
    user_get = 'user/get'
    user_info = 'user/info'
    shorturl = 'shorturl'
    create_menu = 'menu/create'
    get_menu = 'menu/get'
    material = 'material/batchget_material'
    material_one = 'material/get_material'
    material_count = 'material/get_materialcount'
    qrcode_create = 'qrcode/create'
    showqrcode = 'showqrcode'
    media_get = 'media/get'
    menu_addconditional = 'menu/addconditional'
    ticket_getticket = 'ticket/getticket'
    send_template = 'message/template/send'

    gettoken = 'gettoken'

    oauth2_access_token = 'oauth2/access_token'
    oauth2_userinfo = 'userinfo'

class Message():
    def __init__(self, *args, **kwargs):
        pass

    def test(self):
        print('Hello World')


class PublicPlatform():
    def __init__(self, app_id, app_secret, **kwargs):
        self.app_id = app_id
        self.app_secret = app_secret
        self.origin_url = 'https://api.weixin.qq.com/cgi-bin/{}'

    

    def get_access_token(self):
        """获取access_token
        https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421140183
        """
        return self._get(Action.token.value, grant_type='client_credential',
                         **self._auth_args())
    def _auth_args(self):
        return {'appid': self.app_id, 'secret': self.app_secret}

    def _get(self, _action, **kwargs):
        url = self.origin_url.format(_action)
        print(url)
        res = requests.get(url, params=kwargs)
        return res.json()

    def _post(self, _action, **kwargs):

        # monkey_patch()
        url = self.origin_url.format(_action)
        params = {"access_token": kwargs.get('access_token')}
        kwargs.pop('access_token')
        print(kwargs)
        kwargs = json.dumps(kwargs,ensure_ascii=False).encode('utf-8')
        res = requests.post(url, params=params,
                            data=kwargs,
                            headers={"Content-Type":"application/json;charset=UTF-8"})
        res = json.loads(str(res.content, 'utf8'))
        return res

