#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Author: wxnacy(wxnacy@gmail.com)
# Description:

from enum import Enum
import requests
import xmltodict
import json
import base64
import hashlib
from Crypto.Cipher import AES
from urllib import parse
from datetime import datetime

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

    def get_jsapi_ticket(self, access_token):
        """获取access_token
        https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421141115
        """
        return self._get(Action.ticket_getticket.value,
                type='jsapi',access_token=access_token)

    def _auth_args(self):
        return {'appid': self.app_id, 'secret': self.app_secret}

    def _get(self, _action, **kwargs):
        '''get 请求'''
        url = self.origin_url.format(_action)
        res = requests.get(url, params=kwargs)
        return res.json()

    def _post(self, _action, **kwargs):
        '''post 请求'''
        url = self.origin_url.format(_action)
        params = {"access_token": kwargs.get('access_token')}
        kwargs.pop('access_token')
        kwargs = json.dumps(kwargs,ensure_ascii=False).encode('utf-8')
        res = requests.post(url, params=params, data=kwargs,
            headers={"Content-Type":"application/json;charset=UTF-8"})
        res = json.loads(str(res.content, 'utf8'))
        return res

class Message():
    class MsgType(Enum):
        text = 'text'
        news = 'news'
        event = 'event'
        image = 'image'
        voice = 'voice'
        video = 'video'
        location = 'location'
        link = 'link'
        tcs = 'transfer_customer_service'

    class Event(Enum):
        subscribe = 'subscribe'
        unsubscribe = 'unsubscribe'
        click = 'CLICK'
        view = 'VIEW'
        location = 'LOCATION'
        SCAN = 'SCAN'

    def __init__(self, xml_input):
        self.msg = json.loads(json.dumps(xmltodict.parse(xml_input)))
        data = self.msg['xml']
        self.owner_id = data['ToUserName']
        self.sender_id = data['FromUserName']
        self.msg_type = data['MsgType']

        self.event = data.get('Event')
        self.event_key = data.get('EventKey')
        # 用户发送消息给公众号会产生的字段
        self.msg_id = data.get('MsgId')
        self.content = data.get('Content')
        self.pic_url = data.get('PicUrl')
        self.media_id = data.get('MediaId')
        self.thumb_media_id = data.get('ThumbMediaId')
        self.media_format = data.get('Format')  # amr speex
        self.location_x = data.get('Location_X')
        self.location_y = data.get('Location_Y')
        self.scale = data.get('Scale')  # 缩放范围
        self.label = data.get('Label')  # 地理位置
        self.title = data.get('Title')
        self.description = data.get('Description')
        self.url = data.get('Url')
        # 用户点击菜单会产生的字段
        self.latitude = data.get('Latitude')
        self.longitude = data.get('Longitude')
        self.precision = data.get('Precision')  # 位置精度

    def is_text(self):
        return self.msg_type == self.MsgType.text.value

    def is_event(self):
        return self.msg_type == self.MsgType.event.value

    def is_image(self):
        return self.msg_type == self.MsgType.image.value

    def is_video(self):
        return self.msg_type == self.MsgType.video.value

    def reply_text(self, content):
        """回复文本"""
        return self._generator_reply(content)

    def reply_tcs(self):
        """转发客服"""
        return self._generator_reply(msg_type=self.MsgType.tcs.value)

    def reply_news(self, news):
        """回复图文消息"""
        return self._generator_reply(msg_type=self.MsgType.news.value,
                                     news=news)

    def reply_image(self, media_id):
        """回复图片"""
        return self._generator_reply(msg_type=self.MsgType.image.value,
                                     media_id=media_id)

    def reply_video(self, media_id):
        """回复视频"""
        return self._generator_reply(msg_type=self.MsgType.video.value,
                                     media_id=media_id)

    def make_news(self, data):
        return [self.News(**o).to_dict() for o in data]

    def get_user(self):
        """获取用户信息"""

        pass

    def _generator_reply(self, *args, **kwargs):
        content = args[0] if args else kwargs.get('content')
        msg_type = kwargs.get('msg_type') or self.MsgType.text.value

        xml = dict(
            ToUserName=self.sender_id,
            FromUserName=self.owner_id,
            CreateTime=int(datetime.now().timestamp()),
            MsgType=msg_type
        )

        if msg_type == self.MsgType.text.value:
            xml['Content'] = content
        elif msg_type == self.MsgType.news.value:
            items = kwargs.get('news')
            xml['Articles'] = dict(item=items)
            xml['ArticleCount'] = len(items)
        elif msg_type == self.MsgType.image.value:
            xml['Image'] = dict(MediaId=kwargs.get('media_id'))
        elif msg_type == self.MsgType.video.value:
            xml['Video'] = dict(MediaId=kwargs.get('media_id'))

        return xmltodict.unparse({"xml": xml})

    @classmethod
    def xml2dict(cls, xml_input):
        '''解析xml数据'''
        msg = json.loads(json.dumps(xmltodict.parse(xml_input)))
        return msg

    class News():
        def __init__(self, title, thumb_url, url, digest=""):
            self.Title = title
            self.PicUrl = thumb_url
            self.Url = url
            self.Description = digest

def sha1(text):
    sha1 = hashlib.sha1()
    sha1.update(text.encode("utf-8"))
    return sha1.hexdigest()

class AESecurity():

    def __init__(self, key):
        self.key = key
        self.iv = key[:16]
        self.mode = AES.MODE_CBC

    # 解密后，去掉补足的空格用strip() 去掉
    def decrypt(self, text):
        cryptor = AES.new(self.key, self.mode, self.iv)
        plain_text = cryptor.decrypt(text).decode("utf-8")
        return plain_text

class WXSecurity():

    def __init__(self, token, encoding_aes_key):
         self.token = token
         self.encoding_aes_key = encoding_aes_key

    def check_request(self, signature, timestamp, nonce):
        '''检查请求是否复核加密'''
        data = [self.token, str(timestamp), str(nonce)]
        data.sort()
        sign = sha1(''.join(data))
        return sign == signature

    def decrypt_security_body(self, msg_encrypt, msg_signature, timestamp, nonce):
        '''获取加密消息体'''
        check_data = [self.token, msg_encrypt, timestamp, nonce]
        check_data.sort()
        sign = sha1(''.join(check_data))
        if sign != msg_signature:
            raise Exception('消息验证失败')

        try:
            aes_key = base64.b64decode('{}='.format(self.encoding_aes_key))
            aes = AESecurity(aes_key)
            aes_msg = base64.b64decode(msg_encrypt)
            body = aes.decrypt(aes_msg)

            res = body[20:body.rfind('>') + 1]
            return res
        except Exception as e:
            raise Exception('加密消息解析失败')

