import base64
import hashlib
import os
from uuid import uuid4
import boto3
from botocore.client import Config
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from fastapi import HTTPException
from app.config import settings

def _key() -> bytes:
    if not settings.evidence_encryption_key:
        raise HTTPException(503,"Evidence encryption key is not configured")
    try:
        key=base64.urlsafe_b64decode(settings.evidence_encryption_key + "=" * (-len(settings.evidence_encryption_key)%4))
    except Exception as exc:
        raise HTTPException(500,"Evidence encryption key is invalid") from exc
    if len(key)!=32: raise HTTPException(500,"Evidence key must decode to 32 bytes")
    return key

def client():
    return boto3.client("s3",endpoint_url=settings.s3_endpoint_url,region_name=settings.s3_region,
        aws_access_key_id=settings.s3_access_key,aws_secret_access_key=settings.s3_secret_key,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}))

def put_encrypted(plain:bytes,content_type:str)->tuple[str,str]:
    nonce=os.urandom(12);cipher=AESGCM(_key()).encrypt(nonce,plain,b"fieldnote-evidence-v1")
    key=f"evidence/{uuid4()}";s3=client()
    try:
        s3.head_bucket(Bucket=settings.s3_bucket)
    except Exception:
        try:
            s3.create_bucket(Bucket=settings.s3_bucket)
        except Exception as exc:
            raise HTTPException(503,"Encrypted object storage is unavailable") from exc
    try:
        s3.put_object(Bucket=settings.s3_bucket,Key=key,Body=nonce+cipher,ContentType="application/octet-stream",Metadata={"content-type":content_type,"encryption":"AES-256-GCM-v1"})
    except Exception as exc:
        raise HTTPException(503,"Encrypted object storage is unavailable") from exc
    return key,hashlib.sha256(plain).hexdigest()

def get_decrypted(key:str)->bytes:
    try:
        body=client().get_object(Bucket=settings.s3_bucket,Key=key)["Body"].read()
        return AESGCM(_key()).decrypt(body[:12],body[12:],b"fieldnote-evidence-v1")
    except Exception as exc:
        raise HTTPException(503,"Evidence object unavailable or decryption failed") from exc

def delete_encrypted(key:str)->None:
    try: client().delete_object(Bucket=settings.s3_bucket,Key=key)
    except Exception:
        # The object remains encrypted at rest if temporary-secret cleanup fails.
        pass
