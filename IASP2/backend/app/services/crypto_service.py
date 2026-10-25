import os
import hmac
import hashlib
from typing import Tuple, Dict, Any, Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519, x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF, HKDFExpand
from cryptography.exceptions import InvalidSignature, InvalidTag

class CryptoService:
    @staticmethod
    def generate_random_bytes(num_bytes: int = 32) -> bytes:
        """Generate cryptographically secure random bytes."""
        return os.urandom(num_bytes)

    # -------------------------------------------------------------
    # Symmetric AEAD (AES-GCM)
    # -------------------------------------------------------------
    @staticmethod
    def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> Dict[str, bytes]:
        """
        Encrypt plaintext with AES-GCM (128 or 256 bit key based on length).
        Generates a fresh 12-byte (96-bit) nonce per invocation.
        Returns nonce, ciphertext (without tag appended), and authentication tag.
        """
        if len(key) not in (16, 24, 32):
            # Normalise to 32 bytes (AES-256)
            key = hashlib.sha256(key).digest()

        nonce = os.urandom(12)  # Standard 96-bit nonce for AES-GCM
        aesgcm = AESGCM(key)
        # In cryptography library, encrypt returns ciphertext + 16-byte tag
        ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
        ciphertext = ct_with_tag[:-16]
        tag = ct_with_tag[-16:]

        return {
            "nonce": nonce,
            "ciphertext": ciphertext,
            "tag": tag,
            "ct_with_tag": ct_with_tag
        }

    @staticmethod
    def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Decrypt ciphertext and verify tag.
        Raises ValueError if authentication fails.
        """
        if len(key) not in (16, 24, 32):
            key = hashlib.sha256(key).digest()

        aesgcm = AESGCM(key)
        ct_with_tag = ciphertext + tag
        try:
            return aesgcm.decrypt(nonce, ct_with_tag, associated_data)
        except InvalidTag:
            raise ValueError("Authentication tag verification failed! Ciphertext or tag was modified or invalid key was used.")

    # -------------------------------------------------------------
    # RSA Educational Operations
    # -------------------------------------------------------------
    @staticmethod
    def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Generate RSA keypair."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size
        )
        return private_key, private_key.public_key()

    @staticmethod
    def rsa_oaep_encrypt(public_key: rsa.RSAPublicKey, plaintext: bytes) -> bytes:
        """
        Demonstration RSA encryption using OAEP with SHA-256.
        Educational Note: TLS 1.2 historically used PKCS#1 v1.5, which had oracle vulnerabilities.
        We demonstrate using modern RSA-OAEP for safety.
        """
        return public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def rsa_oaep_decrypt(private_key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
        """Decrypt RSA-OAEP ciphertext."""
        return private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    # -------------------------------------------------------------
    # Diffie-Hellman / ECDH (X25519)
    # -------------------------------------------------------------
    @staticmethod
    def generate_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
        """Generate ephemeral X25519 keypair for modern DH/ECDH."""
        priv = x25519.X25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def compute_x25519_shared_secret(private_key: x25519.X25519PrivateKey, peer_public_key: x25519.X25519PublicKey) -> bytes:
        """Derive shared secret from X25519 keys."""
        return private_key.exchange(peer_public_key)

    # -------------------------------------------------------------
    # TLS 1.2 PRF (RFC 5246)
    # -------------------------------------------------------------
    @staticmethod
    def tls12_p_hash(secret: bytes, seed: bytes, output_len: int, hash_func=hashlib.sha256) -> bytes:
        """
        TLS 1.2 P_hash data expansion function using HMAC-SHA256.
        P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                               HMAC_hash(secret, A(2) + seed) + ...
        where A(0) = seed, A(i) = HMAC_hash(secret, A(i-1))
        """
        result = bytearray()
        a = seed
        while len(result) < output_len:
            a = hmac.new(secret, a, hash_func).digest()
            chunk = hmac.new(secret, a + seed, hash_func).digest()
            result.extend(chunk)
        return bytes(result[:output_len])

    @classmethod
    def tls12_prf(cls, secret: bytes, label: str, seed: bytes, output_len: int) -> bytes:
        """
        TLS 1.2 PRF: PRF(secret, label, seed) = P_SHA256(secret, label + seed)
        """
        label_bytes = label.encode('ascii')
        return cls.tls12_p_hash(secret, label_bytes + seed, output_len, hashlib.sha256)

    # -------------------------------------------------------------
    # TLS 1.3 Key Schedule (RFC 8446 HKDF)
    # -------------------------------------------------------------
    @staticmethod
    def hkdf_extract(salt: Optional[bytes], ikm: bytes) -> bytes:
        """HKDF-Extract(salt, IKM) -> PRK"""
        if salt is None or len(salt) == 0:
            salt = b"\x00" * 32
        return hmac.new(salt, ikm, hashlib.sha256).digest()

    @staticmethod
    def hkdf_expand_label(secret: bytes, label: str, context: bytes, length: int) -> bytes:
        """
        HKDF-Expand-Label(Secret, Label, Context, Length)
        RFC 8446 Section 7.1
        """
        full_label = b"tls13 " + label.encode('ascii')
        hkdf_label = (
            length.to_bytes(2, 'big') +
            len(full_label).to_bytes(1, 'big') +
            full_label +
            len(context).to_bytes(1, 'big') +
            context
        )
        hkdf = HKDFExpand(
            algorithm=hashes.SHA256(),
            length=length,
            info=hkdf_label
        )
        return hkdf.derive(secret)

    # -------------------------------------------------------------
    # SSH Key Derivation (RFC 4253 Section 7.2)
    # -------------------------------------------------------------
    @staticmethod
    def ssh_kdf(shared_secret_k: bytes, exchange_hash_h: bytes, key_char: str, session_id: bytes, length: int = 32) -> bytes:
        """
        SSH KDF:
        Initial key material: HASH(K || H || X || session_id)
        Where X is 'A' (client IV), 'B' (server IV), 'C' (client enc), 'D' (server enc),
        'E' (client MAC), 'F' (server MAC).
        """
        # In SSH mpint format, shared secret K has length prefix if raw, but here we hash K || H || X || session_id
        data = shared_secret_k + exchange_hash_h + key_char.encode('ascii') + session_id
        k1 = hashlib.sha256(data).digest()
        result = bytearray(k1)
        while len(result) < length:
            # Expansion if length > 32 bytes: HASH(K || H || result)
            next_chunk = hashlib.sha256(shared_secret_k + exchange_hash_h + bytes(result)).digest()
            result.extend(next_chunk)
        return bytes(result[:length])

    # -------------------------------------------------------------
    # Ed25519 Host Key Operations (Modern SSH)
    # -------------------------------------------------------------
    @staticmethod
    def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
        """Generate Ed25519 keypair for SSH host keys and user authentication."""
        priv = ed25519.Ed25519PrivateKey.generate()
        return priv, priv.public_key()

    @staticmethod
    def ed25519_sign(private_key: ed25519.Ed25519PrivateKey, message: bytes) -> bytes:
        """Sign message with Ed25519."""
        return private_key.sign(message)

    @staticmethod
    def ed25519_verify(public_key: ed25519.Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
        """Verify Ed25519 signature."""
        try:
            public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False
