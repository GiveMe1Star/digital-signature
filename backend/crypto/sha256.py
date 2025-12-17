"""
Implement SHA-256 Hash Algorithm từ đầu
Theo chuẩn FIPS 180-4 (Federal Information Processing Standards)
"""

import struct


class SHA256:
    """Class implement thuật toán SHA-256"""
    
    def __init__(self):
        # Các hằng số khởi tạo (first 32 bits of fractional parts of square roots of first 8 primes)
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
        # Các hằng số K (first 32 bits of fractional parts of cube roots of first 64 primes)
        self.k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]
    
    
    def _right_rotate(self, value, shift):
        """Dịch phải value đi shift bit (32-bit)"""
        return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF
    
    
    def _padding(self, message):
        """
        Padding message theo chuẩn SHA-256:
        - Thêm bit '1'
        - Thêm các bit '0' cho đến khi length ≡ 448 (mod 512)
        - Thêm 64-bit biểu diễn độ dài message gốc (big-endian)
        """
        msg_len = len(message)
        message += b'\x80'  # Thêm bit '1' (10000000)
        
        # Thêm '0' cho đến khi (length % 64) == 56
        while len(message) % 64 != 56:
            message += b'\x00'
        
        # Thêm độ dài gốc (64-bit, big-endian)
        # SHA-256 dùng big-endian, khác với MD5 (little-endian)
        message += struct.pack('>Q', msg_len * 8)
        
        return message
    
    
    def _process_chunk(self, chunk):
        """Xử lý 1 block 512-bit"""
        # Chia chunk thành 16 từ 32-bit (big-endian)
        w = list(struct.unpack('>16I', chunk))
        
        # Mở rộng thành 64 từ
        for i in range(16, 64):
            s0 = self._right_rotate(w[i-15], 7) ^ self._right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = self._right_rotate(w[i-2], 17) ^ self._right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w.append((w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF)
        
        # Khởi tạo working variables
        a, b, c, d, e, f, g, h = self.h
        
        # 64 vòng lặp chính
        for i in range(64):
            # Tính các giá trị tạm
            S1 = self._right_rotate(e, 6) ^ self._right_rotate(e, 11) ^ self._right_rotate(e, 25)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + self.k[i] + w[i]) & 0xFFFFFFFF
            
            S0 = self._right_rotate(a, 2) ^ self._right_rotate(a, 13) ^ self._right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
            
            # Cập nhật working variables
            h = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
        
        # Cộng kết quả vào hash values
        self.h[0] = (self.h[0] + a) & 0xFFFFFFFF
        self.h[1] = (self.h[1] + b) & 0xFFFFFFFF
        self.h[2] = (self.h[2] + c) & 0xFFFFFFFF
        self.h[3] = (self.h[3] + d) & 0xFFFFFFFF
        self.h[4] = (self.h[4] + e) & 0xFFFFFFFF
        self.h[5] = (self.h[5] + f) & 0xFFFFFFFF
        self.h[6] = (self.h[6] + g) & 0xFFFFFFFF
        self.h[7] = (self.h[7] + h) & 0xFFFFFFFF
    
    
    def hash(self, message):
        """
        Hash message và trả về SHA-256 digest
        
        Args:
            message: bytes hoặc string
        
        Returns:
            str: SHA-256 hash dạng hex (64 ký tự)
        """
        # Convert string to bytes
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        # Reset giá trị ban đầu
        self.h = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        ]
        
        # Padding
        padded_message = self._padding(message)
        
        # Xử lý từng chunk 512-bit (64 bytes)
        for i in range(0, len(padded_message), 64):
            chunk = padded_message[i:i+64]
            self._process_chunk(chunk)
        
        # Kết hợp các hash values thành digest (big-endian)
        digest = struct.pack('>8I', *self.h)
        
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
    sha256 = SHA256()
    
    # Test cases chuẩn (theo NIST)
    test_cases = [
        ("", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        ("a", "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"),
        ("abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        ("message digest", "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650"),
        ("abcdefghijklmnopqrstuvwxyz", "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73"),
        ("The quick brown fox jumps over the lazy dog", "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
    ]
    
    print("=" * 80)
    print("SHA-256 Test Cases (NIST Standard)")
    print("=" * 80)
    print()
    
    for message, expected in test_cases:
        result = sha256.hash(message)
        status = "✓" if result == expected else "✗"
        
        print(f"{status} Input: '{message}'")
        print(f"  Expected: {expected}")
        print(f"  Got:      {result}")
        
        if result == expected:
            print(f"  Status: PASS")
        else:
            print(f"  Status: FAIL")
        print()
    
    print("=" * 80)
    print("All tests completed!")
    print("=" * 80)
