"""
Digital Signature System
Kết hợp SHA-256 và RSA để tạo chữ ký số
"""

from crypto.sha256 import SHA256  # Thay MD5 bằng SHA256
from crypto.rsa import RSA


class DigitalSignature:
    """
    Hệ thống chữ ký số
    
    Quy trình:
    1. Ký: signature = RSA_sign(SHA256(message), private_key)
    2. Xác minh: SHA256(message) == RSA_verify(signature, public_key)
    """
    
    def __init__(self, key_size=512):
        self.rsa = RSA(key_size=key_size)
        self.sha256 = SHA256()  # Thay self.md5 bằng self.sha256
        self.public_key = None
        self.private_key = None
    
    
    def generate_keys(self, verbose=False):
        """Sinh cặp khóa"""
        self.public_key, self.private_key = self.rsa.generate_keypair(verbose=verbose)
        return self.public_key, self.private_key
    
    
    def sign(self, message, private_key=None):
        """
        Ký message
        
        Args:
            message: str hoặc bytes - tin nhắn cần ký
            private_key: tuple (d, n) - khóa riêng (optional)
        
        Returns:
            int: chữ ký số
        """
        if private_key is None:
            private_key = self.private_key
        
        if private_key is None:
            raise ValueError("Chưa có private key. Hãy gọi generate_keys() trước.")
        
        # 1. Hash message bằng SHA-256
        hash_value = self.sha256.hash_int(message)
        
        # Debug logging (có thể bỏ khi production)
        print(f"SHA-256 Hash (int): {hash_value}")
        
        # 2. Mã hóa hash bằng private key
        d, n = private_key
        print(f"Private Key: (d={d}, n={n})")
        
        # Đảm bảo hash < n
        hash_value = hash_value % n
        print(f"Hash after mod n: {hash_value}")
        
        # Sign = hash^d mod n
        signature = self.rsa.decrypt(hash_value, private_key)
        
        return signature
    
    
    def verify(self, message, signature, public_key=None):
        """
        Xác minh chữ ký
        
        Args:
            message: str hoặc bytes - tin nhắn gốc
            signature: int - chữ ký cần xác minh
            public_key: tuple (e, n) - khóa công khai (optional)
        
        Returns:
            bool: True nếu chữ ký hợp lệ, False nếu không
        """
        if public_key is None:
            public_key = self.public_key
        
        if public_key is None:
            raise ValueError("Chưa có public key.")
        
        # 1. Hash message bằng SHA-256
        hash_value = self.sha256.hash_int(message)
        
        # 2. Giải mã signature bằng public key
        e, n = public_key
        hash_value = hash_value % n
        
        # Decrypt signature: hash' = signature^e mod n
        decrypted_hash = self.rsa.encrypt(signature, public_key)
        
        # 3. So sánh
        return hash_value == decrypted_hash
    
    
    def get_hash(self, message):
        """
        Lấy hash SHA-256 của message (để hiển thị)
        
        Returns:
            str: hash hex string
        """
        return self.sha256.hash(message)
    
    
    def get_public_key(self):
        """Lấy public key"""
        return self.public_key
    
    
    def get_private_key(self):
        """Lấy private key (chỉ dùng cho demo)"""
        return self.private_key
