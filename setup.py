#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Author: wxnacy(wxnacy@gmail.com)
# Description:

from setuptools import setup, find_packages

setup(
    name = 'wwx',
    version = '0.0.4',
    keywords='wx',
    description = 'a library for wx Developer',
    license = 'MIT License',
    url = 'https://github.com/wxnacy/wwx',
    author = 'wxnacy',
    author_email = 'wxnacy@gmail.com',
    packages = find_packages(),
    include_package_data = True,
    platforms = 'any',
    install_requires = [],
)

