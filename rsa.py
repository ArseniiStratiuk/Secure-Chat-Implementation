import secrets, random

def gcd(a, b):
    '''
    calculates the gcd of two ints
    '''
    while b != 0:
        a, b = b, a % b
    return a

def egcd(a, b):
    '''
    calculates the modular inverse from e and phi
    '''
    if a == 0:
        return (b, 0, 1)
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def rsa_algo():
    """RSA"""
    # треба чекати чи просте число
    num_1, num_2 = secrets.randbits(1024), secrets.randbits(1024)
    n = num_1*num_2

    phi = (num_1-1)*(num_2-1)
    e = random.randint(2, phi-1)
    while gcd(e, phi) != 1:
        e = random.randint(2, phi-1)

    d = egcd(e, phi)[1] % phi
    if d < 0:
        d += phi

    return (e,n), (d,n)

def encrypt(message, public_key):
    """
    c = (m^e) mod n
    """
    key, n = public_key
    encrypted_blocks = [pow(ord(char), key, n) for char in message]
    return encrypted_blocks

def decrypt(encrypted_blocks, private_key):
    """
    m = (c^d) mod n
    """
    key, n = private_key
    decrypted_chars = [chr(pow(block, key, n)) for block in encrypted_blocks]
    return "".join(decrypted_chars)
