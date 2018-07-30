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
import chardet
from Crypto.Cipher import AES
from urllib import parse
from datetime import datetime
from . import security

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

    # 开放平台动作
    component_api_component_token = 'component/api_component_token'
    component_api_create_preauthcode = 'component/api_create_preauthcode'
    component_api_query_auth = 'component/api_query_auth'
    component_api_authorizer_token = 'component/api_authorizer_token'
    component_api_get_authorizer_info = 'component/api_get_authorizer_info'


class OpenPlatform():
    '''
    第三方平台
    doc: https://open.weixin.qq.com/cgi-bin/showdocument?action=dir_list&t=resource/res_list&verify=1&id=open1453779503&token=&lang=zh_CN
    '''
    def __init__(self, app_id, app_secret, **kwargs):
        self.app_id = app_id
        self.app_secret = app_secret
        self.origin_url = 'https://api.weixin.qq.com/cgi-bin/{}'

    def get_access_token(self, verify_ticket):
        '''获取 component_access_token'''
        url = self.origin_url.format(Action.component_api_component_token.value)
        res = requests.post(url, json={
            "component_appid": self.app_id,
            "component_appsecret": self.app_secret,
            "component_verify_ticket": verify_ticket
        })
        return res.json()

    def get_pre_auth_code(self, component_access_token):
        '''获取预授权码 pre_auth_code'''
        res = self._post(Action.component_api_create_preauthcode.value,
            component_access_token=component_access_token)
        return res

    def api_query_auth(self, component_access_token, authorization_code):
        '''获取身份'''
        res = self._post(Action.component_api_query_auth.value,
                component_access_token = component_access_token,
                authorization_code = authorization_code)
        return res

    def api_authorizer_token(self, component_access_token,
            authorizer_appid, authorizer_refresh_token):
        '''获取授权方 token '''
        res = self._post(Action.component_api_authorizer_token.value,
                component_access_token = component_access_token,
                authorizer_appid = authorizer_appid,
                authorizer_refresh_token = authorizer_refresh_token)
        return res

    def api_get_authorizer_info(self, component_access_token,
            authorizer_appid)
        '''获取授权方信息'''
        res = self._post(Action.component_api_get_authorizer_info.value,
                component_access_token = component_access_token,
                authorizer_appid = authorizer_appid)
        return res

    def _post(self, _action, **kwargs):
        '''post 请求'''
        url = self.origin_url.format(_action)
        params = {"component_access_token": kwargs.get('component_access_token')}
        kwargs.pop('component_access_token')
        kwargs['component_appid'] = self.app_id
        kwargs = json.dumps(kwargs,ensure_ascii=False).encode('utf-8')
        res = requests.post(url, params=params, data=kwargs,
            headers={"Content-Type":"application/json;charset=UTF-8"})
        res = json.loads(str(res.content, 'utf8'))
        return res

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

    def get_user_info(self, access_token, openid, lang=None):
        '''
        获取用户信息
        https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1421140839
        '''
        return self._get(Action.user_info.value, access_token=access_token,
                         openid=openid, lang=lang)

    def generator_short_url(self, access_token, long_url):
        """
        将一条长链接转成短链接。
        https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1443433600
        :param access_token:
        :param long_url:
        :return:
        """
        return self._post(Action.shorturl.value, action='long2short',
                          access_token=access_token, long_url=long_url)

    def send_template(self, access_token, openid, template_id, data, url="",
            topcolor=""):
        """
        发送模板消息
        https://mp.weixin.qq.com/advanced/tmplmsg?action=faq&token=813469155&lang=zh_CN
        :return:
        """
        return self._post(Action.send_template.value, access_token=access_token,
            touser=openid, template_id=template_id, url=url, topcolor=topcolor,
            data=data)

    def send_miniprogram_template(self,access_token, openid, template_id, data, miniprogram, url=""):
        """
        发送微信小程序模板消息
        https://mp.weixin.qq.com/advanced/tmplmsg?action=faq&token=813469155&lang=zh_CN
        :return:
        """
        return self._post(Action.send_template.value, access_token=access_token,
                          touser=openid, template_id=template_id, url=url, miniprogram=miniprogram,
                          data=data)


    def get_material_list(self, access_token, type, offset=0, count=20):
        """
        获取素材列表
        https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1444738734
        :param access_token:
        :return:
        """
        return self._post(Action.material.value, access_token=access_token,
                          type=type, offset=offset, count=count)

    def get_material(self, access_token, media_id):
        """
        获取永久素材
        https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1444738730
        :param access_token:
        :return:
        """
        return self._post(Action.material_one.value, access_token=access_token,
                          media_id=media_id)

    def get_material_count(self, access_token):
        """
        获取素材列表
        https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1444738734
        :param access_token:
        :return:
        """
        return self._get(Action.material_count.value, access_token=access_token)

    def get_media_url(self, access_token, media_id):
        """
        获取素材列表
        https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1444738734
        :param access_token:
        :return:
        """
        return 'https://api.weixin.qq.com/cgi-bin/media/get?access_token={}&media_id={}'.format(
            access_token, media_id)

    def create_menu(self, access_token, button):
        """
        创建菜单
        """
        # json.dumps(kwargs, ensure_ascii=False)
        return self._post(Action.create_menu.value, access_token=access_token,
                          button=button)

    def get_menu(self, access_token):
        """
        获取菜单
        """
        return self._get(Action.get_menu.value, access_token=access_token)

    def menu_addconditional(self,access_token, button, matchrule):
        """
        创建个性化菜单
        https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1455782296
        """
        return self._post(Action.menu_addconditional.value,
                access_token=access_token, button=button, matchrule=matchrule)


    def qrcode_create(self, access_token, scene,
                      action_name='QR_LIMIT_STR_SCENE',expire_seconds=2592000):
        """
        创建二维码ticket
        https://mp.weixin.qq.com/wiki?t=resource/res_main&id=mp1443433542
        :param access_token:
        :param scene:
        :param action_name: 二维码类型，QR_SCENE为临时的整型参数值，
                                        QR_STR_SCENE为临时的字符串参数值，
                                        QR_LIMIT_SCENE为永久的整型参数值，
                                        QR_LIMIT_STR_SCENE 为永久的字符串参数值
        :return:
        """
        kwargs = dict(
            action_name=action_name
        )
        if not action_name.startswith('QR_LIMIT'):
            kwargs['expire_seconds'] = expire_seconds

        if 'STR' not in action_name:
            kwargs['action_info'] = {"scene": {"scene_id": int(scene)}}
        else:
            kwargs['action_info'] = {"scene": {"scene_str": scene}}

        res = self._post(Action.qrcode_create.value, access_token=access_token,
                         **kwargs)

        if 'ticket' in res:
            query = parse.urlencode(dict(ticket=res['ticket']))
            res['qrcode_url'] = 'https://mp.weixin.qq.com/cgi-bin/showqrcode?{}'.format(
                query)
        print(res)
        return res

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
        self.msg = self.xml2dict(xml_input)
        data = self.msg['xml']
        self.owner_id = data.get('ToUserName')
        self.sender_id = data.get('FromUserName')
        self.msg_type = data.get('MsgType')

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

    def reply_video(self, media_id, title=None, description=None):
        """回复视频"""
        return self._generator_reply(msg_type=self.MsgType.video.value,
            media_id=media_id, title=title, description=description)

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
            if kwargs.get('title'):
                xml['Video']['Title'] = kwargs['title']
            if kwargs.get('description'):
                xml['Video']['Description'] = kwargs['description']


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


class WXSecurity():

    def __init__(self, token, encoding_aes_key):
        self.token = token
        self.encoding_aes_key = encoding_aes_key
        aes_key = base64.b64decode('{}='.format(self.encoding_aes_key))
        self.aes = security.AESecurity(aes_key)

    def check_request(self, signature, timestamp, nonce):
        '''检查请求是否复核加密'''
        data = [self.token, str(timestamp), str(nonce)]
        data.sort()
        sign = security.sha1(''.join(data))
        return sign == signature

    def decrypt_security_body(self, msg_encrypt, msg_signature, timestamp,
            nonce):
        '''获取加密消息体'''
        check_data = [self.token, msg_encrypt, timestamp, nonce]
        check_data.sort()
        sign = security.sha1(''.join(check_data))
        if sign != msg_signature:
            raise Exception('消息验证失败')

        try:
            aes_msg = base64.b64decode(msg_encrypt)
            print(aes_msg)
            body = self.aes.decrypt(aes_msg)

            res = body[20:body.rfind('>') + 1]
            return res
        except Exception as e:
            raise Exception('加密消息解析失败')

