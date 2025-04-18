"""RSA implementation for secure chat application.

This module provides RSA encryption, decryption, and digital signature functions.
"""
import secrets
import random
import hashlib


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
    # iterative implementation of extended Euclidean algorithm
    x, y = 0, 1
    last_x, last_y = 1, 0

    while b != 0:
        quot = a // b
        a, b = b, a % b
        x, last_x = last_x - quot * x, x
        y, last_y = last_y - quot * y, y

    return (a, last_x, last_y)

def is_prime(n, k=5):
    """check if num is prime"""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Записуємо n-1 як 2^s * d
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2  # [2, n-2]
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=1024):
    while True:
        temp = secrets.randbits(bits)
        if is_prime(temp):
            return temp

def rsa_algo():
    """RSA"""
    num_1, num_2 = generate_prime(), generate_prime()
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


def sign(message, private_key):
    """Create a digital signature for a message.
    
    Args:
        message: Message to sign
        private_key: RSA private key tuple (d, n)
        
    Returns:
        Digital signature for the message
    """
    key, n = private_key
    # use the hash of the message for signing
    message_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16)

    # sign the hash with private key
    return pow(message_hash, key, n)


def verify(message, signature, public_key):
    """Verify a digital signature.
    
    Args:
        message: Original message
        signature: Digital signature to verify
        public_key: RSA public key tuple (e, n)
        
    Returns:
        Boolean indicating if signature is valid
    """
    key, n = public_key

    # decrypt the signature with public key
    decrypted_hash = pow(signature, key, n)

    # calculate the hash of the original message
    actual_hash = int(hashlib.sha256(message.encode()).hexdigest(), 16)

    # verify they match
    return decrypted_hash == actual_hash
