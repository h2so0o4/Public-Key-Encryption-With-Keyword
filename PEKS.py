from pypbc import *
import hashlib

Hash1 = hashlib.sha256
Hash2 = hashlib.sha256


# 公钥可搜索加密-2004-Boneh


# 密钥生成算法，输入安全参数qbits和rbits，返回[params, g, pk, sk]
def KeyGen(qbits=512, rbits=160):
    params = Parameters(qbits=qbits, rbits=rbits)  # 参数初始化
    pairing = Pairing(params)  # 根据参数实例化双线性对
    # 返回公共参数
    g = Element.random(pairing, G2)  # g是G2的一个生成元 G2:素数阶为q的循环群
    sk = Element.random(pairing, Zr)  # 私钥是一个素数域Zp内的随机数
    pk = Element(pairing, G2, value=g ** sk)  # 公钥是[g, h = g^sk]  G2是返回值的类型
    return [params, g, sk, pk]


# PEKS算法，输入公共参数[params, g]，公钥pk，关键字word，返回[A, B] A=g^r B为可搜索的关键字的加密（具体参考论文）
def PEKS(params, g, pk, word):
    # PEKS 算法输入公钥pk（论文中是h），G1的生成元g，关键字W
    pairing = Pairing(params)  # 参数初始化

    # 首先生成t = e(H1(W),h^r)，H1(W)是对关键字进行哈希函数处理，这里使用的是hash256算法
    # 希望使用过程中元素的运算或赋值都使用这样的方式来进行，pairing是一定要写的，G1代表返回值的类型，
    hash_value = Element.from_hash(pairing, G1, Hash1(str(word).encode('utf-8')).hexdigest())
    r = Element.random(pairing, Zr)  # 定义一个Zp内的随机数r
    h_r = Element(pairing, G1, value=pk ** r)
    # t = pairing.apply(hash_value, h_r)

    # g_r = Element(pairing,G1,value = g ** r)
    t = pairing.apply(hash_value, pk ** r)  # 生成双线性对e(H1(W),h^r)
    return [g ** r, Hash2(str(t).encode('utf-8')).hexdigest()]


# 陷门生成算法，输入公共参数[params]，私钥sk，待查关键字word，返回陷门td
def Trapdoor(params, sk, word):
    pairing = Pairing(params)
    hash_value = Element.from_hash(pairing, G1, Hash1(str(word).encode('utf-8')).hexdigest())
    return hash_value ** sk


# 测试算法，输入公共参数[params]，公钥pk，S=[A, B]，陷门td，返回布尔值True/False
def Test(params, pk, cipher, td):
    pairing = Pairing(params)
    [A, B] = cipher
    td = Element(pairing, G1, value=str(td))
    temp = pairing.apply(td, A)
    temp = Hash2(str(temp).encode('utf-8')).hexdigest()
    return temp == B


if __name__ == '__main__':

    [params, g, sk, pk] = KeyGen(512, 160)

    message = ('123', 'plaintext', 'haha')
    n = 0
    cipher = {}
    for i in message:
        cipher[n] = PEKS(params, g, pk, i)
        n = n + 1

    keyword = '123'
    td = Trapdoor(params, sk, keyword)
    for key in cipher:
        B = Test(params, pk, cipher[key], td)
        if B:
            print("在密文中检索到关键字%s" % keyword)
