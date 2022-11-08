from constants import BITS_FOR_P_AND_Q
from random_prime_number_generator import get_prime
from random import randint

def extended_euclidean_iterative(a: int, n: int):
    x = 0
    y = 1
    last_x = 1
    last_y = 0
    
    while n != 0:
        quo = a // n
        gcd = n
        a, n = n, a % n
        x, last_x = last_x - quo * x, x
        y, last_y = last_y - quo * y, y

    return gcd, last_x, last_y

def extended_euclidean(a: int, n: int):
    if a == 0:
        return n, 0, 1
             
    gcd, s1, t1 = extended_euclidean(n % a, a)
     
    # Update x and y using results of recursive call
    s = t1 - (n//a) * s1
    t = s1
     
    return gcd, s, t

def revocate_key(p: int, q: int):
    """returns n, phi, e, d"""
    n = p * q

    phi = (p - 1) * (q - 1)

    while True:
        e = randint(2, phi // 2)
        gcd, s, t = extended_euclidean_iterative(e, phi)
        if gcd == 1:
            break
    
    s = s % phi

    return n, phi, e, s

def generate_key():
    """returns p, q, n, phi, e, d"""
    p = get_prime(BITS_FOR_P_AND_Q)
    q = get_prime(BITS_FOR_P_AND_Q)

    return p, q, *revocate_key(p, q)
