"""
Digital Signature System
Kết hợp MD5 và RSA để tạo chữ ký số
"""

from crypto.md5 import MD5
from crypto.rsa import RSA


class DigitalSignature:
    """
    Hệ thống chữ ký số
    
    Quy trình:
    1. Ký: signature = RSA_encrypt(MD5(message), private_key)
    2. Xác minh: MD5(message) == RSA_decrypt(signature, public_key)
    """
    
    def __init__(self, key_size=512):
        self.rsa = RSA(key_size=key_size)
        self.md5 = MD5()
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
        
        # 1. Hash message
        hash_value = self.md5.hash_int(message)
        
        # 2. Mã hóa hash bằng private key
        d, n = private_key
        
        # Đảm bảo hash < n
        hash_value = hash_value % n
        
        signature = self.rsa.decrypt(hash_value, private_key)  # Dùng decrypt vì ký bằng private key
        
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
        
        # 1. Hash message
        hash_value = self.md5.hash_int(message)
        
        # 2. Giải mã signature bằng public key
        e, n = public_key
        hash_value = hash_value % n
        
        decrypted_hash = self.rsa.encrypt(signature, public_key)  # Dùng encrypt vì verify bằng public key
        
        # 3. So sánh
        return hash_value == decrypted_hash
    
    
    def get_public_key(self):
        """Lấy public key"""
        return self.public_key
    
    
    def get_private_key(self):
        """Lấy private key (chỉ dùng cho demo)"""
        return self.private_key
