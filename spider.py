from Des import *
from urllib.parse import quote
from time import time, sleep
from PIL import Image
import requests
import sys
from bs4 import BeautifulSoup

s = requests.session()
headers = {
    'Cache-Control': 'max-age=0',
    'Connection': 'keep-alive',
    'Referer': 'http://www.jste.net.cn/uids/login.jsp',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) \
    Chrome/58.0.3029.110 Safari/537.36 SE 2.X MetaSr 1.0'
}


def custom_encode(data):  # 懒得注释了，直接从js中拷贝出来，改成python的代码
    tab = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    data_bytes = list(data.encode())
    while len(data_bytes) % 3 != 0:
        data_bytes.append(0)
    b = 0
    length = len(data_bytes)
    r = ''
    while b < length:
        g = data_bytes[b]
        h = data_bytes[b + 1]
        j = data_bytes[b + 2]
        k = g >> 2
        m = ((g & 3) << 4) | (h >> 4)
        n = ((h & 15) << 2) | (j >> 6)
        o = j & 63
        third_char = '=' if h == 0 else tab[n]
        fourth_char = '=' if j == 0 else tab[o]
        r = r + tab[k] + tab[m] + third_char + fourth_char
        b = b + 3
    return r[::-1]  # 反序输出


def encode_pwd(str_name, str_pwd):
    encoded_pwd = custom_encode(str_pwd)
    encoded_pwd = custom_encode(encoded_pwd)  # 先连续对密码加密两次
    if len(str_name) % 2 == 1:
        encoded_pwd = custom_encode(encoded_pwd)  # 如果用户名长度是奇数，则再加密一次
    return encoded_pwd


def strenc(data, firstkey, secondkey):
    bts_data = extend_to_16bits(data)  # 将data长度扩展成64位的倍数
    bts_firstkey = extend_to_16bits(firstkey)  # 将 first_key 长度扩展成64位的倍数
    bts_secondkey = extend_to_16bits(secondkey)  # 将 second_key 长度扩展成64位的倍数
    i = 0
    bts_result = []
    while i < len(bts_data):
        bts_temp = bts_data[i:i + 8]  # 将data分成每64位一段，分段加密
        j, k = 0, 0
        while j < len(bts_firstkey):
            des_k = des(bts_firstkey[j: j + 8], ECB)  # 分别取出 first_key 的64位作为密钥
            bts_temp = list(des_k.encrypt(bts_temp))
            j += 8
        while k < len(bts_secondkey):
            des_k = des(bts_secondkey[k:k + 8], ECB)  # 分别取出 second_key 的64位作为密钥
            bts_temp = list(des_k.encrypt(bts_temp))
            k += 8
        bts_result.extend(bts_temp)
        i += 8
    str_result = ''
    for each in bts_result:
        str_result += '%02X' % each  # 分别加密data的各段，串联成字符串
    return str_result


def extend_to_16bits(data):  # 将字符串的每个字符前插入 0，变成16位，并在后面补0，使其长度是64位整数倍
    bts = data.encode()
    filled_bts = []
    for each in bts:
        filled_bts.extend([0, each])  # 每个字符前插入 0
    while len(filled_bts) % 8 != 0:  # 长度扩展到8的倍数
        filled_bts.append(0)  # 不是8的倍数，后面添加0，便于DES加密时分组
    return filled_bts


def get_rand_code():
    random_code_url = r'http://www.jste.net.cn/uids/genImageCode?rnd='
    time_stamp = str(int(time() * 1000))
    random_code_url += time_stamp
    try:
        req = s.get(random_code_url, headers=headers, stream=True)
        with open('rand_code.jpg', 'wb') as f:
            for chunk in req.iter_content(chunk_size=1024):
                f.write(chunk)
    except requests.RequestException:
        print('网络链接错误，请稍后重试/(ㄒoㄒ)/~~')
        sys.exit()
    with Image.open('rand_code.jpg')as img:
        img.show()


def login_site(reqid, randomcode, reqkey):
    post_data = {
        'randomCode': randomcode,
        'returnURL': None,
        'appId': 'uids',
        'site': None,
        'encrypt': 1,
        'reqId': reqid,
        'req': reqkey
    }
    try:
        req = s.post('http://www.jste.net.cn/uids/login.jsp', headers=headers, data=post_data)
        print('Status Code：%s' % req.status_code)  # 不知道为什么浏览器上登陆成功返回的是302，这里返回200
        if 'Set-Cookie' in req.headers.keys():  # 还好，看到response中出现Set-Cookie，就登陆成功了
            return True
        else:
            return False
    except requests.RequestException:
        print('网络链接错误，请稍后重试/(ㄒoㄒ)/~~')
        return False


def main():
    print(''.center(100, '-'))
    uname = input('请输入你的用户名：')
    pwd = input('请输入你的登陆密码：')
    get_rand_code()
    secondkey = input('请输入看到的验证码：')  # 取得验证码，作为second_key，提交数据时作为 randomCode 的值
    firstkey = str(int(time() * 1000))  # 取得提交时的时间戳，作为first_key，提交数据时候作为 reqId 的值
    crypt_pwd = encode_pwd(uname, pwd)  # 对输入的密码进行第一次加密
    data = quote(uname) + '\n' + crypt_pwd  # 用户名URI编码后和密码加密后的文本链接等待被DES加密
    post_req = strenc(data, firstkey, secondkey)  # 主要是DES计算，作为 req 的值提交数据
    if login_site(reqid=firstkey, randomcode=secondkey, reqkey=post_req) is True:
        print(''.center(100, '-'))
        print('登陆成功，O(∩_∩)O哈哈~...')
        try:
            req = s.get('http://www.jste.net.cn/train/credit_hour/top.jsp')  # 打开一个网页测试一下
            soup = BeautifulSoup(req.text, 'html5lib')  # 网页为多框架，测试下访问TOP框架中的文本
            print(soup.select('.b')[0].text.replace('\n', '').replace(' ', ''))
        except requests.RequestException:
            print('网络链接错误，请稍后重试/(ㄒoㄒ)/~~')


if __name__ == '__main__':  # 启动程序
    main()
