# wwx 微信公众号接口封装工具

无数次被微信公众号虐待，终于决定将公众号相关的接口封装成 python 包来让人使用。

## 安装

```bash
$ pip install wwx
```

## 公众平台

## 第三方平台

**初始化对象**

```python
#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Author: wxnacy(wxnacy@gmail.com)

from wwx import OpenPlatform

op = OpenPlatform(app_id, app_secret)
```


### 授权流程

- **获取第三方平台 component_access_token**

```python
#!/usr/bin/env python
# -*- coding:utf-8 -*-
# Author: wxnacy(wxnacy@gmail.com)

res = op.get_access_token(verify_ticket)
print(res)

# 返回
# component_access_token	第三方平台access_token
# expires_in	            有效期
```
