def parse_row(text):
    symb = []
    for i in range(len(text)):
        symb.append(ord(text[i]))
    return symb

def make_str(symb):
    msg = ''
    for c in symb:
        msg = msg + str(c) + "-"
    return msg[:-1]

def parse_str(text):
    return text.split('-')

def get_msg(symb):
    msg = ''
    for c in symb:
        msg = msg + chr(int(c))
    return msg

def gcd(a,b):
    if b==0:
        return a
    else:
        return gcd(b,a%b)
    
def extendGcd(a, b): 
    if b == 0:
        x = 1
        y = 0
        return x, y
    else:
        x1, y1 = extendGcd(b, a % b)
        x = y1
        y = x1 - (int)(a / b) * y1
        return x, y
    
def fastMul(a,b,n):
    res=1
    while b!=0:
        if b%2==0:
          b=b/2
          a=(a*a)%n
        elif b%2!=0:
          b=b-1
          res=(res*a)%n
    return res

def generateKey(p, q):
    n = p * q  
    fn = (p - 1) * (q - 1)     
    e = 65537 
    x, y = extendGcd(e, fn) 
    if x < 0: 
        x = x + fn
    d = x
    return (n, e),(n, d) 

def encrypt_s(m, publicKey):
    n = publicKey[0]
    e = publicKey[1]
    c = fastMul(m, e, n)
    return c

def decrypt_s(c, privateKey):
    n = privateKey[0]
    d = privateKey[1]
    m = fastMul(c, d, n)
    return m

def encrypt(publicKey, text):
    n = publicKey[0]
    e = publicKey[1]
    symb = parse_row(text)
    tmp = []
    for i in symb:
        c = fastMul(i, e, n)
        tmp.append(c)
    encrypted = make_str(tmp)
    return encrypted

def decrypt(privateKey, text):
    n = privateKey[0]
    d = privateKey[1]
    symb = parse_str(text)
    tmp = []
    for i in symb:
        m = fastMul(int(i), d, n)
        tmp.append(m)
    msg = get_msg(tmp)
    return msg

