from crypto.sha256 import SHA256
from crypto.rsa import RSA

# SHA-256 DigestInfo header theo chuẩn PKCS#1 v1.5
# OID: 2.16.840.1.101.3.4.2.1 (SHA-256)
SHA256_DIGEST_INFO = bytes([
    0x30, 0x31,                         # SEQUENCE, 49 bytes
    0x30, 0x0d,                         # SEQUENCE, 13 bytes
    0x06, 0x09,                         # OID, 9 bytes
    0x60, 0x86, 0x48, 0x01, 0x65,       # 2.16.840.1.101
    0x03, 0x04, 0x02, 0x01,             # .3.4.2.1 (SHA-256)
    0x05, 0x00,                         # NULL
    0x04, 0x20                          # OCTET STRING, 32 bytes (hash follows)
])

class DigitalSignature:
    def __init__(self, key_size=512):
        self.rsa = RSA(key_size=key_size)
        self.sha256 = SHA256()
        self.public_key = None
        self.private_key = None
        self.key_size = key_size
    
    def _pkcs1_v15_pad(self, hash_bytes: bytes, key_size_bytes: int) -> int:
        # DigestInfo = ASN.1 header + hash
        digest_info = SHA256_DIGEST_INFO + hash_bytes
        
        # Tính độ dài padding string (PS)
        # key_size_bytes - 3 (0x00, 0x01, 0x00) - len(DigestInfo)
        ps_len = key_size_bytes - 3 - len(digest_info)
        
        if ps_len < 8:
            raise ValueError(f"Key quá ngắn cho PKCS#1 v1.5 padding. Cần ít nhất {len(digest_info) + 11} bytes")
        
        # PS = 0xFF * ps_len
        ps = b'\xff' * ps_len
        
        # EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo
        em = b'\x00\x01' + ps + b'\x00' + digest_info
        
        return int.from_bytes(em, 'big')
    
    def _pkcs1_v15_unpad(self, signature_int: int, key_size_bytes: int) -> bytes:
        try:
            # Chuyển int thành bytes
            em = signature_int.to_bytes(key_size_bytes, 'big')
            
            # Kiểm tra header: 0x00 0x01
            if em[0:2] != b'\x00\x01':
                return None
            
            # Tìm separator 0x00 sau PS
            sep_idx = em.find(b'\x00', 2)
            if sep_idx == -1 or sep_idx < 10:  # PS tối thiểu 8 bytes
                return None
            
            # Kiểm tra PS chỉ chứa 0xFF
            ps = em[2:sep_idx]
            if not all(b == 0xff for b in ps):
                return None
            
            # Lấy phần DigestInfo + Hash
            digest_info_and_hash = em[sep_idx + 1:]
            
            # Kiểm tra DigestInfo header
            if not digest_info_and_hash.startswith(SHA256_DIGEST_INFO):
                return None
            
            # Trích xuất hash (32 bytes cuối)
            hash_value = digest_info_and_hash[len(SHA256_DIGEST_INFO):]
            
            if len(hash_value) != 32:
                return None
            
            return hash_value
            
        except Exception:
            return None
    
    # Sinh cặp khóa
    def generate_keys(self, verbose=False):
        self.public_key, self.private_key = self.rsa.generate_keypair(verbose=verbose)
        return self.public_key, self.private_key
    
    # Ký message bằng private key (PKCS#1 v1.5)
    def sign(self, message, private_key=None):
        if private_key is None:
            private_key = self.private_key
        
        if private_key is None:
            raise ValueError("Chưa có private key. Hãy gọi generate_keys() trước.")
        
        d, n = private_key
        key_size_bytes = (n.bit_length() + 7) // 8
        
        # 1. Hash message bằng SHA-256
        hash_hex = self.sha256.hash(message)
        hash_bytes = bytes.fromhex(hash_hex)
        
        print(f"SHA-256 Hash: {hash_hex}")
        
        # 2. Tạo PKCS#1 v1.5 padded message
        padded_message = self._pkcs1_v15_pad(hash_bytes, key_size_bytes)
        
        print(f"PKCS#1 v1.5 Padded (int): {padded_message}")
        
        # 3. Sign: signature = padded_message^d mod n
        signature = self.rsa.decrypt(padded_message, private_key)
        
        return signature
    
    # Xác minh chữ ký (PKCS#1 v1.5)
    def verify(self, message, signature, public_key=None):
        if public_key is None:
            public_key = self.public_key
        
        if public_key is None:
            raise ValueError("Chưa có public key.")
        
        e, n = public_key
        key_size_bytes = (n.bit_length() + 7) // 8
        
        # 1. Decrypt signature: decrypted = signature^e mod n
        decrypted = self.rsa.encrypt(signature, public_key)
        
        # 2. Unpad và lấy hash từ PKCS#1 v1.5
        extracted_hash = self._pkcs1_v15_unpad(decrypted, key_size_bytes)
        
        if extracted_hash is None:
            print("PKCS#1 v1.5 padding không hợp lệ!")
            return False
        
        # 3. Hash message và so sánh
        hash_hex = self.sha256.hash(message)
        expected_hash = bytes.fromhex(hash_hex)
        
        return extracted_hash == expected_hash
    
    # Lấy hash của message (dạng hex)
    def get_hash(self, message):
        return self.sha256.hash(message)
    
    # Lấy public key
    def get_public_key(self):
        return self.public_key
    
    # Lấy private key 
    def get_private_key(self):
        return self.private_key
