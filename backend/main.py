"""
Digital Signature API - FastAPI Server
Hệ thống chữ ký số cho doanh nghiệp
"""

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


# ==================== APP SETUP ====================

app = FastAPI(
    title="Digital Signature API",
    description="RSA Digital Signature System - Custom Implementation (No crypto library)",
    version="2.0.0"
)

# CORS middleware cho frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Production: chỉ định domain cụ thể
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==================== HELPER FUNCTIONS ====================

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


# ==================== API ENDPOINTS ====================

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "status": "ok",
        "message": "Digital Signature API (Custom RSA + MD5)",
        "version": "2.0.0",
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
    key_size: int = Form(1024)  # 512, 1024, hoặc 2048
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
        
        # Trả về private key để download
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
        raise HTTPException(status_code=500, detail=f"Key generation failed: {str(e)}")


@app.post("/sign")
async def sign_file(
    file: UploadFile = File(...),
    private_key: UploadFile = File(...)
):
    """
    Ký file với private key
    
    - Đọc file và private key
    - Tạo chữ ký số (MD5 hash + RSA)
    - Trả về file chữ ký (.sig)
    """
    try:
        # Đọc file data
        file_data = await file.read()
        
        # Đọc private key
        key_data = await private_key.read()
        priv_key = str_to_key(key_data.decode('utf-8'))
        
        # Tạo digital signature instance
        ds = DigitalSignature(key_size=512)  # Key size không quan trọng ở đây
        
        # Ký file
        signature = ds.sign(file_data, private_key=priv_key)
        
        # Convert signature (int) thành bytes
        signature_bytes = str(signature).encode('utf-8')
        
        # Encode base64 để an toàn
        signature_b64 = base64.b64encode(signature_bytes)
        
        # Trả về file chữ ký
        return Response(
            content=signature_b64,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename={file.filename}.sig"
            }
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid key: {str(e)}")
    except Exception as e:
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
    
    - Cần: file gốc, file chữ ký, và public key (từ directory hoặc upload)
    - Verify signature với public key
    - Trả về kết quả xác minh
    """
    try:
        # Đọc file data
        file_data = await file.read()
        
        # Đọc signature
        sig_data = await signature.read()
        sig_bytes = base64.b64decode(sig_data)
        sig_int = int(sig_bytes.decode('utf-8'))
        
        # Lấy public key
        if key_id and key_id in key_directory:
            # Từ directory
            entry = key_directory[key_id]
            pub_key = str_to_key(entry.public_key)
            signer = f"{entry.name} ({entry.department})"
        elif public_key_file:
            # Từ file upload
            key_data = await public_key_file.read()
            pub_key = str_to_key(key_data.decode('utf-8'))
            signer = "Uploaded Key"
        else:
            raise HTTPException(
                status_code=400,
                detail="Must provide either key_id or public_key_file"
            )
        
        # Verify
        ds = DigitalSignature(key_size=512)
        valid = ds.verify(file_data, sig_int, public_key=pub_key)
        
        return VerifyResponse(
            valid=valid,
            message="✓ Signature is VALID - Document is authentic" if valid 
                   else "✗ Signature is INVALID - Document may be tampered",
            signer=signer if valid else None
        )
        
    except HTTPException:
        raise
    except Exception as e:
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
    Đăng ký public key có sẵn vào directory
    
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
    
    return {"message": "Key deleted successfully"}


# ==================== RUN SERVER ====================

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting Digital Signature API Server...")
    print("📝 API Documentation: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
