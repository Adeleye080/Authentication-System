import os

# from fastapi import Request
import asyncio
from pathlib import Path
import uuid, base64
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from api.utils.settings import settings
import logging

logger = logging.getLogger(__name__)

KEYS_DIR = Path(__file__).resolve().parents[2] / "keys"


async def generate_keypair():
    """Generate a new RSA keypair (private in memory, public saved to file/volume)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    public_key = private_key.public_key()
    kid = f"key-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6]}"

    # Save public key in PEM format
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    os.makedirs(KEYS_DIR, exist_ok=True)
    file_path = os.path.join(KEYS_DIR, f"{kid}.pem")
    with open(file_path, "wb") as f:
        f.write(public_pem)

    return private_key, kid


async def load_public_keys():
    """Load all public keys from volume."""
    keys = {}
    if not os.path.exists(KEYS_DIR):
        return keys

    for fname in os.listdir(KEYS_DIR):
        if fname.endswith(".pem"):
            kid = fname.replace(".pem", "")
            with open(os.path.join(KEYS_DIR, fname), "rb") as f:
                keys[kid] = f.read()
    return keys


# synchronous
def prune_old_keys():
    """
    Remove old public keys after TTL expires (to prevent JWKS bloat).
    Multiply TTL time by 2 to ensure user sessions are uninterrupted.
    """
    ttl_minutes = settings.APP_SERVICE_KEYPAIR_ROTATION_MINUTES * 2
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=ttl_minutes)

    removed_keys_count = 0

    for fname in os.listdir(KEYS_DIR):
        if fname.endswith(".pem"):
            fpath = os.path.join(KEYS_DIR, fname)
            created = datetime.fromtimestamp(os.path.getctime(fpath), tz=timezone.utc)
            if created < cutoff:
                os.remove(fpath)
                removed_keys_count += 1

    logger.info(f"Pruned {removed_keys_count} service apps key")


async def pem_to_jwk(pem_bytes: bytes, kid: str):
    public_key = serialization.load_pem_public_key(pem_bytes, backend=default_backend())
    numbers = public_key.public_numbers()

    n = base64.urlsafe_b64encode(
        numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    ).rstrip(b"=")
    e = base64.urlsafe_b64encode(
        numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    ).rstrip(b"=")

    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "RS256",
        "n": n.decode("utf-8"),
        "e": e.decode("utf-8"),
    }


async def rotate_service_signing_key(app):
    """ """

    private_key, current_kid = await generate_keypair()
    app.state.app_service_private_key = private_key
    app.state.app_service_current_kid = current_kid

    return current_kid


async def rotation_worker(app):
    """Rotate keys automatically."""

    await asyncio.sleep(settings.APP_SERVICE_KEYPAIR_ROTATION_MINUTES * 3600)
    kid = await rotate_service_signing_key(app)
    logger.info(f"[KEY ROTATION] Rotated signing key -> {kid}")
