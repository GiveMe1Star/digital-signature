# Implement RSA Algorithm

import random
from utils.math_utils import gcd, mod_inverse, power_mod
from utils.prime_utils import generate_prime

class RSA:
    # Class implement thuật toán RSA
    def __init__(self, key_size=512):
        self.key_size = key_size
        self.public_key = None
        self.private_key = None
        self.n = None
    
    
    def generate_keypair(self, verbose=False):
        """
        Tạo cặp khóa RSA
        
        Returns:
            tuple: (public_key, private_key)
                public_key = (e, n)
                private_key = (d, n)
        """
        if verbose:
            print(f"Đang sinh khóa RSA {self.key_size}-bit...")
        
        # 1. Sinh 2 số nguyên tố p, q
        p = generate_prime(self.key_size // 2)
        q = generate_prime(self.key_size // 2)
        
        while p == q:
            q = generate_prime(self.key_size // 2)
        
        if verbose:
            print(f"  p = {p}")
            print(f"  q = {q}")
        
        # 2. Tính n = p * q
        n = p * q
        self.n = n
        
        if verbose:
            print(f"  n = {n}")
        
        # 3. Tính φ(n)
        phi_n = (p - 1) * (q - 1)
        
        # 4. Chọn e
        e = 65537
        if gcd(e, phi_n) != 1:
            e = 3
            while gcd(e, phi_n) != 1:
                e += 2
        
        if verbose:
            print(f"  e = {e}")
        
        # 5. Tính d
        d = mod_inverse(e, phi_n)
        
        if verbose:
            print(f"  d = {d}")
        
        # Lưu khóa
        self.public_key = (e, n)
        self.private_key = (d, n)
        
        if verbose:
            print("✓ Sinh khóa thành công!\n")
        
        return self.public_key, self.private_key
    
    
    def encrypt(self, plaintext, public_key=None):
        # Mã hóa: c = m^e mod n
        if public_key is None:
            public_key = self.public_key
        
        e, n = public_key
        
        if plaintext >= n:
            raise ValueError(f"Plaintext phải < n")
        
        return power_mod(plaintext, e, n)
    
    
    def decrypt(self, ciphertext, private_key=None):
        # Giải mã: m = c^d mod n
        if private_key is None:
            private_key = self.private_key
        
        d, n = private_key
        
        return power_mod(ciphertext, d, n)
