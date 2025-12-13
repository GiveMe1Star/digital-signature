"""
Module chứa các hàm toán học cơ bản cho RSA
"""

def gcd(a, b):
    """Tính ước chung lớn nhất"""
    while b != 0:
        a, b = b, a % b
    return a


def extended_gcd(a, b):
    """
    Extended Euclidean Algorithm
    Trả về (gcd, x, y) sao cho a*x + b*y = gcd(a,b)
    """
    if a == 0:
        return b, 0, 1
    
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    
    return gcd_val, x, y


def mod_inverse(a, m):
    """Tính nghịch đảo modulo"""
    gcd_val, x, y = extended_gcd(a, m)
    
    if gcd_val != 1:
        raise ValueError("Nghịch đảo modulo không tồn tại")
    
    return (x % m + m) % m


def power_mod(base, exponent, modulus):
    """
    Tính (base^exponent) % modulus hiệu quả
    Sử dụng thuật toán "Square and Multiply"
    """
    if modulus == 1:
        return 0
    
    result = 1
    base = base % modulus
    
    while exponent > 0:
        if exponent % 2 == 1:
            result = (result * base) % modulus
        
        exponent = exponent >> 1
        base = (base * base) % modulus
    
    return result
