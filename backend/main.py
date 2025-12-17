from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from typing import Optional
from datetime import datetime
import uuid
import base64
import sys
import os

# Add backend to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from models import KeyEntry, VerifyResponse, DirectoryResponse, key_directory
from signature.digital_signature import DigitalSignature


# APP SETUP
app = FastAPI(
    title="Digital Signature API",
    description="RSA Digital Signature System - Custom RSA + SHA-256 Implementation (No crypto library)",
    version="3.0.0"  # Tăng version
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# HELPER FUNCTIONS
def key_to_str(key: tuple) -> str:
    """Convert key tuple (e/d, n) thành string 'exponent:modulus'"""
    return f"{key[0]}:{key[1]}"


def str_to_key(s: str) -> tuple:
    """Parse key string thành tuple"""
    try:
        parts = s.strip().split(':')
        return (int(parts[0]), int(parts[1]))
    except Exception as e:
        raise ValueError(f"Invalid key format: {e}")


# API ENDPOINTS
@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "ok",
        "message": "Digital Signature API - Custom RSA + SHA-256",
        "version": "3.0.0",
        "technology": {
            "hash": "SHA-256 (Custom implementation)",
            "encryption": "RSA (Custom implementation)",
            "no_external_crypto": True
        },
        "endpoints": {
            "generate_keys": "POST /generate-keys",
            "sign": "POST /sign",
            "verify": "POST /verify",
            "directory": "GET /directory",
            "register": "POST /register"
        }
    }


@app.post("/generate-keys")
async def generate_keys(
    name: str = Form(...),
    department: str = Form(...),
    key_size: int = Form(1024)
):
    """
    Sinh cặp khóa RSA mới
    
    - Tạo public/private key pair
    - Đăng ký public key vào directory
    - Trả về private key để download
    """
    try:
        # Validate key size
        if key_size not in [512, 1024, 2048]:
            raise HTTPException(status_code=400, detail="Key size must be 512, 1024, or 2048")
        
        print(f"🔑 Generating {key_size}-bit RSA keys for {name}...")
        
        # Sinh khóa
        ds = DigitalSignature(key_size=key_size)
        public_key, private_key = ds.generate_keys(verbose=False)
        
        # Tạo key ID
        key_id = str(uuid.uuid4())[:8]
        
        # Lưu public key vào directory
        key_directory[key_id] = KeyEntry(
            id=key_id,
            name=name,
            department=department,
            public_key=key_to_str(public_key),
            created_at=datetime.now().isoformat()
        )
        
        print(f"✓ Keys generated. Key ID: {key_id}")
        
        # Trả về private key
        private_key_str = key_to_str(private_key)
        
        return Response(
            content=private_key_str.encode('utf-8'),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename={name.replace(' ', '_')}_private.key",
                "X-Key-ID": key_id
            }
        )
        
    except Exception as e:
        print(f"✗ Key generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Key generation failed: {str(e)}")


@app.post("/sign")
async def sign_file(
    file: UploadFile = File(...),
    private_key: UploadFile = File(...)
):
    """
    Ký file với private key
    
    - Đọc file và private key
    - Hash file bằng SHA-256
    - Ký hash bằng RSA
    - Trả về file chữ ký (.sig)
    """
    try:
        print(f"📝 Signing file: {file.filename}")
        
        # Đọc file data
        file_data = await file.read()
        
        # Đọc private key
        key_data = await private_key.read()
        priv_key = str_to_key(key_data.decode('utf-8'))
        
        # Tạo digital signature instance
        ds = DigitalSignature(key_size=512)
        
        # Lấy hash để log
        file_hash = ds.get_hash(file_data)
        print(f"  SHA-256 Hash: {file_hash}")
        
        # Ký file
        signature = ds.sign(file_data, private_key=priv_key)
        print(f"  Signature: {signature}")
        
        # Convert signature (int) thành bytes
        signature_bytes = str(signature).encode('utf-8')
        
        # Encode base64
        signature_b64 = base64.b64encode(signature_bytes)
        
        print(f"✓ File signed successfully")
        
        # Trả về file chữ ký
        return Response(
            content=signature_b64,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename={file.filename}.sig"
            }
        )
        
    except ValueError as e:
        print(f"✗ Signing failed: {e}")
        raise HTTPException(status_code=400, detail=f"Invalid key: {str(e)}")
    except Exception as e:
        print(f"✗ Signing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Signing failed: {str(e)}")


@app.post("/verify", response_model=VerifyResponse)
async def verify_file(
    file: UploadFile = File(...),
    signature: UploadFile = File(...),
    key_id: Optional[str] = Form(None),
    public_key_file: Optional[UploadFile] = File(None)
):
    """
    Xác minh chữ ký của file
    
    Đảm bảo 3 tính chất:
    1. Toàn vẹn (Integrity): File không bị sửa đổi
    2. Xác thực (Authentication): Đúng người ký
    3. Chống chối bỏ (Non-repudiation): Không thể phủ nhận
    """
    try:
        print(f"🔍 Verifying signature for: {file.filename}")
        
        # Đọc file data
        file_data = await file.read()
        
        # Đọc signature
        sig_data = await signature.read()
        sig_bytes = base64.b64decode(sig_data)
        sig_int = int(sig_bytes.decode('utf-8'))
        
        # Lấy public key
        if key_id and key_id in key_directory:
            entry = key_directory[key_id]
            pub_key = str_to_key(entry.public_key)
            signer = f"{entry.name} ({entry.department})"
            print(f"  Signer: {signer}")
        elif public_key_file:
            key_data = await public_key_file.read()
            pub_key = str_to_key(key_data.decode('utf-8'))
            signer = "Uploaded Key"
        else:
            raise HTTPException(
                status_code=400,
                detail="Must provide either key_id or public_key_file"
            )
        
        # Tạo DS instance
        ds = DigitalSignature(key_size=512)
        
        # Log hash
        file_hash = ds.get_hash(file_data)
        print(f"  SHA-256 Hash: {file_hash}")
        
        # ===== PHẦN NÀY BỊ THIẾU - THÊM VÀO =====
        # Verify signature
        valid = ds.verify(file_data, sig_int, public_key=pub_key)
        
        print(f"  Result: {'✓ VALID' if valid else '✗ INVALID'}")
        # ========================================
        
        return VerifyResponse(
            valid=valid,
            message=(
                "✓ CHỮ KÝ HỢP LỆ\n"
                "• Tài liệu KHÔNG bị sửa đổi (Toàn vẹn)\n"
                "• Người ký XÁC THỰC đúng (Xác thực)\n"
                "• Không thể phủ nhận đã ký (Chống chối bỏ)"
            ) if valid else (
                "✗ CHỮ KÝ KHÔNG HỢP LỆ\n"
                "• Tài liệu có thể đã bị SỬA ĐỔI\n"
                "• HOẶC sai người ký\n"
                "⚠️ CẢNH BÁO: Không sử dụng tài liệu này!"
            ),
            signer=signer if valid else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"✗ Verification failed: {e}")
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@app.get("/directory", response_model=DirectoryResponse)
async def get_directory():
    """Lấy danh sách tất cả public keys đã đăng ký"""
    entries = [entry for entry in key_directory.values()]
    return DirectoryResponse(entries=entries)


@app.post("/register")
async def register_key(
    name: str = Form(...),
    department: str = Form(...),
    public_key: UploadFile = File(...)
):
    """
    Đăng ký public key vào directory
    
    - Upload public key file
    - Validate format
    - Lưu vào directory
    """
    try:
        # Đọc public key
        key_data = await public_key.read()
        pub_key_str = key_data.decode('utf-8')
        
        # Validate key format
        str_to_key(pub_key_str)
        
        # Tạo key ID
        key_id = str(uuid.uuid4())[:8]
        
        # Lưu vào directory
        key_directory[key_id] = KeyEntry(
            id=key_id,
            name=name,
            department=department,
            public_key=pub_key_str,
            created_at=datetime.now().isoformat()
        )
        
        print(f"✓ Public key registered: {name} (ID: {key_id})")
        
        return {
            "message": "Public key registered successfully",
            "key_id": key_id
        }
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid public key: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@app.delete("/directory/{key_id}")
async def delete_key(key_id: str):
    """Xóa public key khỏi directory"""
    if key_id not in key_directory:
        raise HTTPException(status_code=404, detail="Key not found")
    
    del key_directory[key_id]
    
    print(f"✓ Key deleted: {key_id}")
    
    return {"message": "Key deleted successfully"}


# RUN SERVER
if __name__ == "__main__":
    import uvicorn
    print("=" * 70)
    print("🚀 Starting Digital Signature API Server")
    print("=" * 70)
    print("📝 Technology: Custom RSA + SHA-256 (No external crypto library)")
    print("🌐 Server: http://localhost:8000")
    print("📚 API Docs: http://localhost:8000/docs")
    print("=" * 70)
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
