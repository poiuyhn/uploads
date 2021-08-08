import re
import string
import requests
import js2py


# eval加密的解密
def unpack(p, a, c, k, e=None, d=None):
    ''' unpack
    Unpacker for the popular Javascript compression algorithm.
    @param  p  template code
    @param  a  radix for variables in p
    @param  c  number of variables in p
    @param  k  list of c variable substitutions
    @param  e  not used
    @param  d  not used
    @return p  decompressed string
    '''
    # Paul Koppen, 2011
    for i in range(c-1,-1,-1):
        if k[i]: p = re.sub('\\b'+int2base(i,a)+'\\b', k[i], p)
    return p


def int2base(x, base):
    digs = string.digits + string.ascii_letters
    if x < 0:
        sign = -1
    elif x == 0:
        return digs[0]
    else:
        sign = 1
    x *= sign
    digits = []
    while x:
        digits.append(digs[int(x % base)])
        x = int(x / base)
    if sign < 0:
        digits.append('-')
    digits.reverse()
    return ''.join(digits)


# 判断字符串是否是数字
def is_number(s):
    try:
        float(s)
        return True
    except ValueError:
        pass
    return False


# 位运算
def pr(a,b):
    result = int(a)^int(b)
    return result


# 端口字符串转数字
def pwd2digit(pStr, pwd_dict):
    pStr_ = re.findall('\w+\^\w+', pStr)
    for i in pStr_:
        pStr_[pStr_.index(i)] = i.split('^')
    for i in pStr_:
        pStr_[pStr_.index(i)] = pr([pwd_dict[i[0]]][0], [pwd_dict[i[1]]][0])
    result = ''.join([str(i) for i in pStr_])
    return result


# 将result_of_IIFE的结果位运算后，转为端口的参考字典
def bitwise_XOR(list1):
    if len(list1) > 1:
        l = list1
    else:
        l = re.split(';',list1[0])
    for i in l:
        if i == '':
            l.remove(i)
    d = {}
    d_ = []
    for i in l:
        m = re.split(r'[=|^]',i)
        if len(m) == 2:
            d[m[0]] = m[1]
        elif len(m) == 3:
            if m[1].isdigit() == True and m[2].isdigit() == True:
                d[m[0]] = pr(int(m[1]), int(m[2]))
            else:
                d_.append([m[0], m[1], m[2]])
    for k in d_:
        if is_number(k[1]) and is_number(k[2]):
            d[k[0]] = pr(d[k[1]], d[k[2]])
        elif not is_number(k[1]) and not is_number(k[2]):
            d[k[0]] = pr(d[k[1]], d[k[2]])
        elif is_number(k[1]):
            d[k[0]] = pr(k[1], d[k[2]])
        elif is_number(k[2]):
            d[k[0]] = pr(d[k[1]], k[2])
    return d


# 端口的'密码本'
def portDecrypt(need_to_decrypt):
    if 'function' in need_to_decrypt:
        # eval加密的解密:
        result_of_eval = eval('unpack' + need_to_decrypt[need_to_decrypt.find('}(')+1:-1])
        # 通过js2py执行eval内的立即执行函数:
        result_of_eval_ = result_of_eval.replace('eval', ';')
        result_of_IIFE = js2py.eval_js(result_of_eval_)
        pattern = re.compile(r'\w+=\d+\^?[^\}]+')
        pwd_list = re.findall(pattern, result_of_IIFE)
    else:
        pwd_list = need_to_decrypt
    # print(pwd_list) # ['E=7;NZF=515^4145;SPYS9N=3430^53281;N=3;Z=2;F=9;F6T=390^9991;ZVSPYS=742^8000;V=8;S=0;O=4;S1V=10017^808;SPYS=5;ZTONE=11986^8888;T=6;ONEFS=9448^8080;ONE=1;E8E=8465^9090;STO=10420^999;SPYS2Z=11259^8118;S6TZ=S^ZVSPYS;SONENN=ONE^ZTONE;O0EE=Z^STO;Z3ONEV=N^NZF;ONESSPYSONE=O^S1V;SPYS7SO=SPYS^SPYS9N;N8FS=T^ONEFS;ONE8OSPYS=E^SPYS2Z;EFZF=V^F6T;E1VT=F^E8E;']
    # 将result_of_IIFE的结果位运算后，转为端口的参考字典:
    pwd_dict = bitwise_XOR(pwd_list)
    # print(pwd_dict) # {'E': '7', 'NZF': 4658, 'SPYS9N': 56647, 'N': '3', 'Z': '2', 'F': '9', 'F6T': 9857, 'ZVSPYS': 7590, 'V': '8', 'S': '0', 'O': '4', 'S1V': 9225, 'SPYS': '5', 'ZTONE': 3178, 'T': '6', 'ONEFS': 15224, 'ONE': '1', 'E8E': 659, 'STO': 11091, 'SPYS2Z': 13389, 'S6TZ': 7590, 'SONENN': 3179, 'O0EE': 11089, 'Z3ONEV': 4657, 'ONESSPYSONE': 9229, 'SPYS7SO': 56642, 'N8FS': 15230, 'ONE8OSPYS': 13386, 'EFZF': 9865, 'E1VT': 666}
    return pwd_dict


# 获取网页源代码
def get_index():
    header = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 11_2_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.114 Safari/537.36'}
    try:
        rsp = requests.get(url=url, headers=header, timeout=3)
        if rsp.status_code == 200:
            html = rsp.text
            pattern = re.compile('table><script>[\S\s\n\r]+?</script>', re.S)
            info = re.findall(pattern, html)
            script = info[0].replace('table><script>', '').replace('</script>', '').strip()
            return html, script
        else:
            exit('TRY AGAIN.')
    except Exception as e:
        exit(e)


# 解析网页源代码
def parse_proxy_info(html, pwd_dict):
    pattern = re.compile('out.*?spy14>(.*?)<.*?>"(\+.*?\)\)).*?([HTTPS|SOCKS5]+).*? <font class=spy14>(.*?\))', re.S)
    info = re.findall(pattern, html)
    if len(info) > 0:
        print('[PROXY]: {}'.format(len(info)))
    else:
        exit('TRY AGAIN')
    for i in info:
        ip = i[0]
        # 将每一个代理的端口字符串，通过对照端口参考字典，拿到端口数值
        port = pwd2digit(i[1], pwd_dict)
        protocol = i[2].lower()
        isp = i[3]
        proxy = '{}://{}:{}'.format(protocol, ip, port)
        print(proxy)
        unchecked.append([proxy, isp])


# 保存到文本
def Proxy2txt(fileName):
    toTxT = ''
    for i in unchecked:
        toTxT = toTxT + i[0] + '\n'
    with open(fileName,'w+') as f:
        f.write(toTxT)


def main():
    # 获取网页源代码
    html = get_index()
    # 获取端口的'密码本'
    pwd_dict = portDecrypt(html[1])
    # 根据端口的'密码本', 将端口转为数字, 按ip:port格式保存到文本
    result = parse_proxy_info(html[0], pwd_dict)
    Proxy2txt('Proxy@spys.txt')


if __name__ == '__main__':
    url = 'https://spys.one/en/https-ssl-proxy/' # HTTPS proxy
    unchecked = []
    main()