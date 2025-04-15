import secrets,random

def _gcd(a, b):
    '''
    calculates the gcd of two ints
    '''
    while b != 0:
        a, b = b, a % b
    return a

def _egcd(a, b):
    '''
    calculates the modular inverse from e and phi
    '''
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = _egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def rsa_algo():
    """RSA"""
    # треба змінити
    num_1, num_2 = 1,2
    n = num_1*num_2

    phi = (num_1-1)*(num_2-1)
    e = random.randint(1, phi)
    g = _gcd(e,phi)
    while g != 1:
        e = random.randint(1, phi)
        g = _gcd(e, phi)

    d = _egcd(e, phi)[1]

    d = d % phi
    if d < 0:
        d += phi

    return ((e,n), (d,n))
