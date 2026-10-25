import pytest
from app.services.crypto_service import CryptoService
from app.services.certificate_service import CertificateService

def test_aes_gcm_roundtrip():
    key = CryptoService.generate_random_bytes(32)
    plaintext = b"SecureTunnel Confidential Message"
    
    enc = CryptoService.aes_gcm_encrypt(key, plaintext)
    assert "nonce" in enc
    assert "ciphertext" in enc
    assert "tag" in enc
    assert len(enc["nonce"]) == 12
    assert len(enc["tag"]) == 16

    decrypted = CryptoService.aes_gcm_decrypt(key, enc["nonce"], enc["ciphertext"], enc["tag"])
    assert decrypted == plaintext

def test_aes_gcm_tampering_detection():
    key = CryptoService.generate_random_bytes(32)
    plaintext = b"Tamper Verification Test"
    enc = CryptoService.aes_gcm_encrypt(key, plaintext)

    # Tamper with 1 byte of ciphertext
    tampered_ct = bytearray(enc["ciphertext"])
    tampered_ct[0] ^= 0x01

    with pytest.raises(ValueError, match="Authentication tag verification failed"):
        CryptoService.aes_gcm_decrypt(key, enc["nonce"], bytes(tampered_ct), enc["tag"])

def test_rsa_roundtrip():
    priv, pub = CryptoService.generate_rsa_keypair(key_size=2048)
    secret = b"48-byte-pre-master-secret-tls-test"

    ciphertext = CryptoService.rsa_oaep_encrypt(pub, secret)
    assert len(ciphertext) == 256  # 2048 bits / 8
    assert ciphertext != secret

    decrypted = CryptoService.rsa_oaep_decrypt(priv, ciphertext)
    assert decrypted == secret

def test_x25519_key_exchange():
    c_priv, c_pub = CryptoService.generate_x25519_keypair()
    s_priv, s_pub = CryptoService.generate_x25519_keypair()

    client_shared = CryptoService.compute_x25519_shared_secret(c_priv, s_pub)
    server_shared = CryptoService.compute_x25519_shared_secret(s_priv, c_pub)

    assert client_shared == server_shared
    assert len(client_shared) == 32

def test_ed25519_signature():
    priv, pub = CryptoService.generate_ed25519_keypair()
    message = b"SSH Exchange Hash H to be authenticated"

    sig = CryptoService.ed25519_sign(priv, message)
    assert CryptoService.ed25519_verify(pub, sig, message) is True
    assert CryptoService.ed25519_verify(pub, sig, b"Different message") is False

def test_certificate_signature_verification():
    cert, priv, pem = CertificateService.generate_demo_certificate()
    info = CertificateService.parse_certificate_info(cert)

    assert info["is_self_signed"] is True
    assert "demo-server" in info["subject"]["common_name"]

    verification = CertificateService.verify_certificate_signature(cert, priv.public_key())
    assert verification["signature_valid"] is True
    assert verification["dates_valid"] is True
    assert verification["overall_valid"] is True
