#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Author: wxnacy(wxnacy@gmail.com)
# Description:

from Crypto.Cipher import AES
import hashlib

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
        plain_text = cryptor.decrypt(text).decode('ISO-8859-1')
        return plain_text
