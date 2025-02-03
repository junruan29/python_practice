import time

import requests
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


# 自动处理cookie
# session = requests.session()
# session.get("请求1")
# session.get("请求2")
def base64_api(b64):
    data = {"username": "yuan0316", "password": "yuan0316", "typeid": 3, "image": b64}
    result = json.loads(requests.post("http://api.ttshitu.com/predict", json=data).text)
    if result['success']:
        return result["data"]["result"]
    else:
        return result["message"]


session = requests.session()
session.headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
    "Content-Type": "application/json;charset=UTF-8"}

session.get("https://user.wangxiao.cn/login")

# (1) 破解验证码
url = "https://user.wangxiao.cn/apis//common/getImageCaptcha"
res = session.post(url)
base64_img = res.json().get("data").split(",")[-1]
with open("code.png", "wb") as f:
    f.write(base64.b64decode(base64_img))
code = base64_api(base64_img)
print(code)

# (2) # 对密码加密【RSA 公钥加密，私钥解密】
password = "13121758648yuan" + str(int(time.time() * 1000))
# 获取公钥
public_key_base64 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDA5Zq6ZdH/RMSvC8WKhp5gj6Ue4Lqjo0Q2PnyGbSkTlYku0HtVzbh3S9F9oHbxeO55E8tEEQ5wj/+52VMLavcuwkDypG66N6c1z0Fo2HgxV3e0tqt1wyNtmbwg7ruIYmFM+dErIpTiLRDvOy+0vgPcBVDfSUHwUSgUtIkyC47UNQIDAQAB"
public_key = base64.b64decode(public_key_base64)
# print("public_key:", public_key)
# 公钥加密

# <1> 通过公钥获取钥匙对象
rsa_pk = RSA.importKey(public_key)
# <2> 通过钥匙对象获取算法对象
rsa = PKCS1_v1_5.new(rsa_pk)
# <3> 基于算法对象进行加密
encrypt_password = rsa.encrypt(password.encode())
print("encrypt_password:::", encrypt_password)

# base64
encrypt_password_base64 = base64.b64encode(encrypt_password).decode()
print(encrypt_password_base64)

# (3) 模拟登录
data = {
    "userName": "13121758648",
    "password": encrypt_password_base64,
    "imageCaptchaCode": code
}
url = "https://user.wangxiao.cn/apis//login/passwordLogin"

res = session.post(url, data=json.dumps(data))
print("res:::", res.text)
