"""
Implement MD5 Hash Algorithm từ đầu
Theo chuẩn RFC 1321
"""

import struct
import math


class MD5:
    """Class implement thuật toán MD5"""
    
    def __init__(self):
        # Các hằng số khởi tạo (theo RFC 1321)
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476
        
        # Bảng sin (K[i] = floor(2^32 * abs(sin(i+1))))
        self.K = [int(abs(math.sin(i + 1)) * (2 ** 32)) & 0xFFFFFFFF for i in range(64)]
        
        # Số bit dịch cho mỗi vòng
        self.shift_amounts = [
            7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
            5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
            4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
            6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
        ]
    
    
    def _left_rotate(self, x, amount):
        """Dịch trái x đi amount bit (32-bit)"""
        x &= 0xFFFFFFFF
        return ((x << amount) | (x >> (32 - amount))) & 0xFFFFFFFF
    
    
    def _padding(self, message):
        """
        Padding message theo chuẩn MD5:
        - Thêm bit '1'
        - Thêm các bit '0' cho đến khi length ≡ 448 (mod 512)
        - Thêm 64-bit biểu diễn độ dài message gốc
        """
        msg_len = len(message)
        message += b'\x80'  # Thêm bit '1' (10000000)
        
        # Thêm '0' cho đến khi (length % 64) == 56
        while len(message) % 64 != 56:
            message += b'\x00'
        
        # Thêm độ dài gốc (64-bit, little-endian)
        message += struct.pack('<Q', msg_len * 8)
        
        return message
    
    
    def _process_chunk(self, chunk):
        """Xử lý 1 block 512-bit"""
        # Chia chunk thành 16 từ 32-bit (little-endian)
        X = list(struct.unpack('<16I', chunk))
        
        # Khởi tạo giá trị cho vòng lặp
        A, B, C, D = self.A, self.B, self.C, self.D
        
        # 64 vòng lặp
        for i in range(64):
            if i < 16:
                # Round 1: F(X,Y,Z) = (X & Y) | (~X & Z)
                F = (B & C) | (~B & D)
                g = i
            elif i < 32:
                # Round 2: G(X,Y,Z) = (X & Z) | (Y & ~Z)
                F = (D & B) | (~D & C)
                g = (5 * i + 1) % 16
            elif i < 48:
                # Round 3: H(X,Y,Z) = X ^ Y ^ Z
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            else:
                # Round 4: I(X,Y,Z) = Y ^ (X | ~Z)
                F = C ^ (B | ~D)
                g = (7 * i) % 16
            
            F = (F + A + self.K[i] + X[g]) & 0xFFFFFFFF
            A, B, C, D = D, (B + self._left_rotate(F, self.shift_amounts[i])) & 0xFFFFFFFF, B, C
        
        # Cộng kết quả vào buffer
        self.A = (self.A + A) & 0xFFFFFFFF
        self.B = (self.B + B) & 0xFFFFFFFF
        self.C = (self.C + C) & 0xFFFFFFFF
        self.D = (self.D + D) & 0xFFFFFFFF
    
    
    def hash(self, message):
        """
        Hash message và trả về MD5 digest
        
        Args:
            message: bytes hoặc string
        
        Returns:
            str: MD5 hash dạng hex (32 ký tự)
        """
        # Convert string to bytes
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Reset giá trị ban đầu
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476
        
        # Padding
        padded_message = self._padding(message)
        
        # Xử lý từng chunk 512-bit (64 bytes)
        for i in range(0, len(padded_message), 64):
            chunk = padded_message[i:i+64]
            self._process_chunk(chunk)
        
        # Kết hợp A, B, C, D thành digest (little-endian)
        digest = struct.pack('<4I', self.A, self.B, self.C, self.D)
        
        # Trả về dạng hex
        return digest.hex()
    
    
    def hash_int(self, message):
        """
        Hash message và trả về dạng số nguyên
        Dùng cho RSA signature
        """
        hash_hex = self.hash(message)
        return int(hash_hex, 16)


# Test
if __name__ == "__main__":
    md5 = MD5()
    
    # Test cases chuẩn
    test_cases = [
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("a", "0cc175b9c0f1b6a831c399e269772661"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        ("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b"),
    ]
    
    print("=== MD5 Test Cases ===\n")
    for message, expected in test_cases:
        result = md5.hash(message)
        status = "✓" if result == expected else "✗"
        print(f"{status} '{message}'")
        print(f"  Expected: {expected}")
        print(f"  Got:      {result}")
        print()
