import hashlib,math,config,RFC6979_demo
from random import randint
from SM2_ECG import *
from Prepare import *


def keygen():
    dA=randint(1,n-1)
    PA=ECG_k_point(dA,point_g)
    return (dA,PA)

def sm2_sign(M,IDA,dA,PA,q,n):
    ZA = get_Z(IDA, PA)
    M1=ZA+M
    e=hash_function(M1)
    e = bytes_to_int(bits_to_bytes(e))
    while True:
        k = RFC6979_demo.demo_RFC6979(dA,M,q)           # 使用RFC6979生成确定性k，定义见头文件 RFC6979_demo.py
        X = ECG_k_point(k, point_g)
        x1=bytes_to_int(ele_to_bytes(X.x))
        r=(e+x1)%n
        if(r==0 or r+k==n):
            continue
        s=(config.inverse(1+dA, n)*(k-r*dA)) % n
        if(s==0):
            continue
        break
    return (r,s)


def sm2_verify(M,IDA,r,s,PA,n):
    ZA = get_Z(IDA, PA)
    M1 = ZA + M
    e = hash_function(M1)
    e = bytes_to_int(bits_to_bytes(e))
    t=(r+s)%n
    if(t==0):
        return False
    X=ECG_ele_add(ECG_k_point(s,point_g),ECG_k_point(t,PA))
    x1=bytes_to_int(ele_to_bytes(X.x))
    R=(e+x1)%n
    if(R==r):
        return True
    else:
        return False


if __name__=='__main__':
    print("初始化签名参数......")
    config.set_default_config()
    parameters = config.get_parameters()
    point_g = Point(config.get_Gx(), config.get_Gy())
    q = config.get_q()
    n = config.get_n()

    IDA = 'ALICE123@YAHOO.COM'
    M="hello world"
    print("生成公私钥......")
    sk,pk=keygen()
    print(f"私钥:{sk}\n公钥:{pk}")
    r,s=sm2_sign(M,IDA,sk,pk,q,n)
    print("生成签名......")
    print(f"r:{r}\ns:{s}")
    print("验证签名......")
    if(sm2_verify(M,IDA,r,s,pk,n)):
        print("验签通过")