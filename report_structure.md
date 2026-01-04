# ĐỀ CƯƠNG BÁO CÁO: TÌM HIỂU VÀ CÀI ĐẶT CHỮ KÝ SỐ (RSA & SHA-256)

**Độ dài dự kiến:** 30 - 40 trang  
**Mục tiêu:** Cung cấp cơ sở lý thuyết và minh họa quá trình tự cài đặt các thuật toán cốt lõi.

---

## MỤC LỤC

### LỜI CẢM ƠN
### DANH MỤC HÌNH ẢNH
### DANH MỤC BẢNG BIỂU

---

### CHƯƠNG 1: MỞ ĐẦU (Dự kiến: 2-3 trang)
**1.1. Lý do chọn đề tài**
   - Tầm quan trọng của bảo mật và xác thực trong kỷ nguyên số.
   - Vai trò của chữ ký số trong giao dịch điện tử.

**1.2. Mục tiêu đề tài**
   - Tìm hiểu sâu về thuật toán mã hóa công khai RSA.
   - Tìm hiểu về hàm băm an toàn SHA-256.
   - Tự cài đặt các thuật toán từ con số 0 (from scratch) để hiểu rõ bản chất.
   - Xây dựng ứng dụng demo ký và xác thực thông điệp/văn bản.

**1.3. Phạm vi nghiên cứu**
   - *Lý thuyết:* Toán học số nguyên lớn, thuật toán kiểm tra số nguyên tố (Miller-Rabin), hàm băm.
   - *Thực nghiệm:* Cài đặt bằng ngôn ngữ Python. Giới hạn ở việc ký chuỗi văn bản (message signing), **không** bao gồm xử lý định dạng file phức tạp như PDF/Word (theo yêu cầu).

**1.4. Bố cục báo cáo**

---

### CHƯƠNG 2: CƠ SỞ LÝ THUYẾT (Dự kiến: 10-15 trang)
**2.1. Tổng quan về Mật mã học**
   - Mã hóa đối xứng (Symmetric Key) và những hạn chế.
   - Mã hóa bất đối xứng (Asymmetric Key/Public Key).

**2.2. Hệ mật RSA (Rivest–Shamir–Adleman)**
   - 2.2.1. Cơ sở toán học:
     - Số nguyên tố (Prime numbers).
     - Định lý Fermat nhỏ và Euler.
     - Hàm Phi Euler $\phi(n)$.
     - Thuật toán Euclid mở rộng (tìm nghịch đảo modulo).
   - 2.2.2. Quy trình tạo khóa (Key Generation):
     - Chọn $p, q$ -> Tính $n, \phi(n), e, d$.
   - 2.2.3. Quy trình Mã hóa và Giải mã.

**2.3. Hàm băm SHA-256 (Secure Hash Algorithm)**
   - 2.3.1. Vai trò của hàm băm trong chữ ký số (tính toàn vẹn).
   - 2.3.2. Cấu trúc Merkle–Damgård (nếu áp dụng) hoặc cấu trúc khối của SHA-2.
   - 2.3.3. Quy trình xử lý (Padding, Message Schedule, Compression Function).

**2.4. Cơ chế Chữ ký số (Digital Signature)**
   - Định nghĩa.
   - Quy trình Ký (Signing): $S = H(M)^d \mod n$.
   - Quy trình Xác thực (Verifying): $H' = S^e \mod n$ so sánh với $H(M)$.

---

### CHƯƠNG 3: PHÂN TÍCH THIẾT KẾ HỆ THỐNG (Dự kiến: 5-8 trang)
**3.1. Yêu cầu chức năng**
   - Sinh cặp khóa (Public/Private Key) với độ dài tùy chọn (1024/2048 bits).
   - Ký số lên một thông điệp đầu vào.
   - Xác thực chữ ký từ thông điệp và khóa công khai.

**3.3. Sơ đồ hoạt động (Flowchart)**
   - Sơ đồ quy trình tạo khóa.
   - Sơ đồ quy trình ký và xác thực.

---

### CHƯƠNG 4: CÀI ĐẶT VÀ THỰC NGHIỆM (Dự kiến: 8-10 trang)
**4.1. Môi trường cài đặt**
   - Ngôn ngữ: Python 3.x.
   - Lý do chọn Python: Hỗ trợ xử lý số nguyên lớn tự nhiên, code rõ ràng dễ hiểu.

**4.2. Chi tiết cài đặt (Highlight code snippets quan trọng)**
   - *Snippet 1:* Hàm kiểm tra số nguyên tố Miller-Rabin.
   - *Snippet 2:* Hàm tính nghịch đảo modulo (tính khóa bí mật $d$).
   - *Snippet 3:* Logic vòng lặp chính của SHA-256.
   - *Snippet 4:* Hàm `sign(message, private_key)` và `verify(message, signature, public_key)`.

**4.3. Kịch bản kiểm thử (Demo)**
   - **Test case 1:** Sinh khóa thành công, hiển thị các tham số $n, e, d$.
   - **Test case 2:** Ký một chuỗi văn bản "Hello World". Thay đổi 1 ký tự trong văn bản và xác thực -> Kết quả phải là "Invalid".
   - **Test case 3:** Dùng sai Public Key để xác thực -> Kết quả phải là "Invalid".
   - **Test case 4:** Kiểm tra tính đúng đắn với các công cụ online (nếu có so sánh được).

**4.4. Đánh giá**
   - Độ chính xác: So sánh hash SHA-256 tự viết với thư viện chuẩn `hashlib`.
   - Hiệu năng: Thời gian sinh khóa, thời gian ký (nhanh/chậm tùy thuộc độ dài bit).

---

### CHƯƠNG 5: KẾT LUẬN VÀ HƯỚNG PHÁT TRIỂN (Dự kiến: 2 trang)
**5.1. Kết luận**
   - Đã cài đặt thành công thuật toán RSA và SHA-256 từ cơ bản.
   - Hiểu rõ cơ chế hoạt động bên trong của chữ ký số.

**5.2. Hạn chế**
   - Tốc độ chưa tối ưu bằng các thư viện C/C++ chuyên dụng (như OpenSSL).
   - Chưa xử lý các tấn công kênh phụ (Side-channel attacks).

**5.3. Hướng phát triển**
   - Tối ưu hóa thuật toán nhân số lớn.
   - Mở rộng hỗ trợ ký file (PDF, Word) và hình ảnh (đã lược bỏ trong báo cáo này nhưng là hướng đi tiếp theo).
   - Xây dựng giao diện người dùng (GUI/Web) thân thiện hơn.

---

### TÀI LIỆU THAM KHẢO
1. *Tiêu chuẩn FIPS 180-4 (Secure Hash Standard).*
2. *PKCS #1: RSA Cryptography Specifications.*
3. *Giáo trình An toàn thông tin / Mật mã học.*

---
