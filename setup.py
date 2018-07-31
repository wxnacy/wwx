#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Author: wxnacy(wxnacy@gmail.com)
# Description:

from setuptools import setup, find_packages

setup(
    name = 'wwx',
    version = '0.2.16',
    keywords='wx',
    description = 'a library for wx Developer',
    license = 'MIT License',
    url = 'https://github.com/wxnacy/wwx',
    author = 'wxnacy',
    author_email = 'wxnacy@gmail.com',
    packages = find_packages(),
    include_package_data = True,
    platforms = 'any',
    install_requires = [
        'requests>=2.19.1',
        'pycrypto>=2.6.1',
        'xmltodict>=0.11.0'
        ],
)

