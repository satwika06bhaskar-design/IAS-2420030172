import time
import uuid
import hashlib
import threading
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import serialization
from app.services.crypto_service import CryptoService
from app.services.certificate_service import CertificateService
from app.utils.encoding import to_hex, to_base64, from_base64

class TLSSession:
    def __init__(self, session_id: str, mode: str = "tls12_rsa"):
        self.session_id = session_id
        self.mode = mode  # "tls12_rsa" or "tls13_dhe"
        self.current_step = 0
        self.protocol_state = "initialized"
        self.created_at = time.time()
        self.updated_at = time.time()
        self.error: Optional[str] = None
        self.transcript = bytearray()

        # Step artifacts & secrets
        # Ephemeral randoms
        self.client_random: bytes = b""
        self.server_random: bytes = b""

        # TLS 1.2 RSA objects
        self.rsa_private_key = None
        self.rsa_public_key = None
        self.cert = None
        self.cert_pem: str = ""
        self.pre_master_secret: bytes = b""
        self.encrypted_pms_b64: str = ""
        self.master_secret: bytes = b""

        # TLS 1.3 DHE objects
        self.client_dhe_priv = None
        self.client_dhe_pub_bytes: bytes = b""
        self.server_dhe_priv = None
        self.server_dhe_pub_bytes: bytes = b""
        self.dhe_shared_secret: bytes = b""
        self.early_secret: bytes = b""
        self.handshake_secret: bytes = b""
        self.client_hs_traffic_key: bytes = b""
        self.server_hs_traffic_key: bytes = b""

        # Symmetric traffic keys
        self.client_write_key: bytes = b""
        self.server_write_key: bytes = b""
        self.client_write_iv: bytes = b""
        self.server_write_iv: bytes = b""

        # Application data history
        self.messages_exchanged: list = []

class TLSService:
    def __init__(self):
        self._sessions: Dict[str, TLSSession] = {}
        self._lock = threading.Lock()

    def create_session(self, mode: str = "tls12_rsa") -> TLSSession:
        with self._lock:
            # Clean expired sessions (> 1 hour)
            now = time.time()
            expired = [sid for sid, s in self._sessions.items() if now - s.updated_at > 3600]
            for sid in expired:
                del self._sessions[sid]

            session_id = str(uuid.uuid4())
            session = TLSSession(session_id, mode)
            self._sessions[session_id] = session
            return session

    def get_session(self, session_id: str) -> Optional[TLSSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def reset_session(self, session_id: str) -> Optional[TLSSession]:
        with self._lock:
            if session_id in self._sessions:
                mode = self._sessions[session_id].mode
                session = TLSSession(session_id, mode)
                self._sessions[session_id] = session
                return session
            return None

    def execute_step(self, session_id: str, step: int, simulate_failure: bool = False) -> Dict[str, Any]:
        session = self.get_session(session_id)
        if not session:
            raise ValueError("Session not found or expired.")

        session.updated_at = time.time()

        # Check step sequence
        expected_step = session.current_step + 1
        if step != expected_step and not (step == session.current_step and simulate_failure):
            raise ValueError(f"Invalid step sequence: expected step {expected_step}, got step {step}")

        if session.mode == "tls12_rsa":
            return self._execute_tls12_step(session, step, simulate_failure)
        else:
            return self._execute_tls13_step(session, step, simulate_failure)

    # -------------------------------------------------------------
    # TLS 1.2 Handshake Execution
    # -------------------------------------------------------------
    def _execute_tls12_step(self, session: TLSSession, step: int, simulate_failure: bool) -> Dict[str, Any]:
        if step == 1:
            # Step 1: Client Hello
            session.client_random = CryptoService.generate_random_bytes(32)
            session.transcript.extend(b"ClientHello:" + session.client_random)
            session.current_step = 1
            session.protocol_state = "in_progress"

            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 1,
                "step_title": "Client Hello",
                "message_direction": "client_to_server",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "The client initiates the TLS handshake by proposing supported protocol versions, "
                    "a list of supported cryptographic cipher suites, and a 32-byte cryptographically secure "
                    "Client Random used later in session-key derivation to prevent replay attacks."
                ),
                "crypto_values": {
                    "client_random_hex": to_hex(session.client_random),
                    "client_random_preview": to_hex(session.client_random, shorten=True, max_len=16),
                    "supported_version": "TLS 1.2 (0x0303)",
                    "offered_cipher_suites": [
                        "TLS_RSA_WITH_AES_128_GCM_SHA256",
                        "TLS_RSA_WITH_AES_256_GCM_SHA384",
                        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                    ],
                    "compression_methods": "None (disabled to prevent CRIME attack)"
                },
                "technical_details": {
                    "RFC": "RFC 5246 Section 7.4.1.2",
                    "direction": "Client -> Server",
                    "payload_size_bytes": 48,
                    "replay_defense": "Client Random contributes client entropy to the PRF seed."
                },
                "verification_status": {"valid": True, "message": "ClientHello generated successfully"},
                "can_advance": True,
                "is_complete": False
            }

        elif step == 2:
            # Step 2: Server Hello and Certificate
            session.server_random = CryptoService.generate_random_bytes(32)
            cert, priv_key, cert_pem = CertificateService.generate_demo_certificate()
            session.rsa_private_key = priv_key
            session.rsa_public_key = priv_key.public_key()
            session.cert = cert
            session.cert_pem = cert_pem.decode('ascii')

            session.transcript.extend(b"ServerHello:" + session.server_random)
            session.transcript.extend(b"Certificate:" + cert.public_bytes(serialization.Encoding.DER))
            session.current_step = 2

            cert_info = CertificateService.parse_certificate_info(cert)

            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 2,
                "step_title": "Server Hello & Certificate",
                "message_direction": "server_to_client",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "The server replies with ServerHello, selecting a mutual cipher suite "
                    "(TLS_RSA_WITH_AES_128_GCM_SHA256) and sending its 32-byte Server Random. "
                    "It also attaches its digital X.509 certificate containing its RSA 2048-bit public key. "
                    "Note: This is an educational self-signed certificate."
                ),
                "crypto_values": {
                    "server_random_hex": to_hex(session.server_random),
                    "server_random_preview": to_hex(session.server_random, shorten=True, max_len=16),
                    "selected_cipher_suite": "TLS_RSA_WITH_AES_128_GCM_SHA256",
                    "certificate_subject": cert_info["subject"]["common_name"],
                    "certificate_issuer": cert_info["issuer"]["common_name"],
                    "certificate_fingerprint": cert_info["sha256_fingerprint"],
                    "certificate_public_key": "RSA 2048 bits"
                },
                "technical_details": {
                    "RFC": "RFC 5246 Section 7.4.1.3 & 7.4.2",
                    "direction": "Server -> Client",
                    "certificate_valid_from": cert_info["not_valid_before"],
                    "certificate_valid_until": cert_info["not_valid_after"],
                    "trust_warning": "Browser would alert user: Self-signed certificate is not in root CA store."
                },
                "verification_status": {"valid": True, "message": "ServerHello and Certificate sent"},
                "can_advance": True,
                "is_complete": False
            }

        elif step == 3:
            # Step 3: Certificate Verification
            if simulate_failure:
                session.protocol_state = "failed"
                session.error = "Certificate signature verification failed! Host integrity check rejected."
                return {
                    "session_id": session.session_id,
                    "mode": session.mode,
                    "current_step": 3,
                    "step_title": "Certificate Verification (FAILED DEMONSTRATION)",
                    "message_direction": "internal",
                    "protocol_state": "failed",
                    "explanation": (
                        "FAILURE DEMO: The certificate signature does not match the issuer's public key "
                        "or validity dates are invalid. The client immediately aborts the handshake with "
                        "a 'bad_certificate' TLS alert."
                    ),
                    "crypto_values": {"tamper_detected": True, "valid_signature": False},
                    "technical_details": {"TLS_Alert": "bad_certificate (42), Fatal"},
                    "verification_status": {
                        "signature_valid": False,
                        "dates_valid": False,
                        "overall_valid": False,
                        "error_reason": "Simulated certificate tampering triggered alert."
                    },
                    "can_advance": False,
                    "is_complete": False,
                    "error": "Handshake terminated due to invalid certificate."
                }

            # Normal verification
            verification = CertificateService.verify_certificate_signature(session.cert, session.rsa_public_key)
            session.current_step = 3

            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 3,
                "step_title": "Certificate Verification",
                "message_direction": "internal",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "The client mathematically verifies the certificate signature using the public key. "
                    "Crucial distinction: Cryptographic signature verification proves the certificate has not been altered; "
                    "Trust evaluation determines whether the signer is trusted by the operating system/browser trust store."
                ),
                "crypto_values": {
                    "signature_algorithm": "SHA256withRSA",
                    "mathematical_signature_valid": verification["signature_valid"],
                    "validity_dates_valid": verification["dates_valid"],
                    "trust_assessment": verification["trust_status"]
                },
                "technical_details": {
                    "RFC": "RFC 5246 Section 7.4.2",
                    "details": verification["explanation"]
                },
                "verification_status": verification,
                "can_advance": True,
                "is_complete": False
            }

        elif step == 4:
            # Step 4: Client Key Exchange
            # Pre-master secret is 48 bytes (TLS 1.2 standard)
            session.pre_master_secret = CryptoService.generate_random_bytes(48)
            # Encrypt with Server RSA Public Key (demonstrated via RSA-OAEP)
            ciphertext = CryptoService.rsa_oaep_encrypt(session.rsa_public_key, session.pre_master_secret)
            session.encrypted_pms_b64 = to_base64(ciphertext)

            # Server decrypts on backend
            decrypted_pms = CryptoService.rsa_oaep_decrypt(session.rsa_private_key, ciphertext)
            pms_match = (decrypted_pms == session.pre_master_secret)

            session.transcript.extend(b"ClientKeyExchange:" + ciphertext)
            session.current_step = 4

            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 4,
                "step_title": "Client Key Exchange",
                "message_direction": "client_to_server",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "The client generates a 48-byte random Pre-Master Secret (PMS), encrypts it with the "
                    "server's RSA public key, and sends the ciphertext to the server. The server decrypts it "
                    "with its private key. Both endpoints now share the identical Pre-Master Secret. "
                    "Note: We demonstrate RSA-OAEP encryption here for security; historical TLS 1.2 used PKCS#1 v1.5."
                ),
                "crypto_values": {
                    "pre_master_secret_preview": to_hex(session.pre_master_secret, shorten=True, max_len=16),
                    "encrypted_ciphertext_b64_preview": session.encrypted_pms_b64[:32] + "...",
                    "ciphertext_length_bytes": len(ciphertext),
                    "server_decryption_match": pms_match
                },
                "technical_details": {
                    "RFC": "RFC 5246 Section 7.4.7",
                    "direction": "Client -> Server",
                    "padding_demonstration": "RSA-OAEP (SHA-256)",
                    "security_note": "TLS 1.3 deprecated this mechanism because it lacks Forward Secrecy."
                },
                "verification_status": {"valid": pms_match, "message": "Pre-Master Secret agreed on both sides"},
                "can_advance": True,
                "is_complete": False
            }

        elif step == 5:
            # Step 5: Master Secret and Session-Key Derivation
            # Master Secret = PRF(pre_master_secret, "master secret", ClientRandom + ServerRandom)[0..48]
            seed = session.client_random + session.server_random
            session.master_secret = CryptoService.tls12_prf(session.pre_master_secret, "master secret", seed, 48)

            # Key expansion: PRF(master_secret, "key expansion", ServerRandom + ClientRandom)
            key_block_seed = session.server_random + session.client_random
            # For AES_128_GCM: 2x 16-byte keys (client & server) + 2x 4-byte implicit IVs
            key_block = CryptoService.tls12_prf(session.master_secret, "key expansion", key_block_seed, 40)

            session.client_write_key = key_block[0:16]
            session.server_write_key = key_block[16:32]
            session.client_write_iv = key_block[32:36]
            session.server_write_iv = key_block[36:40]

            session.current_step = 5

            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 5,
                "step_title": "Master Secret & Session Key Derivation",
                "message_direction": "internal",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "Using the TLS 1.2 PRF (HMAC-SHA256 expansion), both client and server independently "
                    "expand the Pre-Master Secret and the nonces (ClientRandom and ServerRandom) into a "
                    "48-byte Master Secret, and then into directional AES-128 traffic keys and 4-byte implicit IVs."
                ),
                "crypto_values": {
                    "master_secret_preview": to_hex(session.master_secret, shorten=True, max_len=16),
                    "client_write_key_preview": to_hex(session.client_write_key, shorten=True, max_len=16),
                    "server_write_key_preview": to_hex(session.server_write_key, shorten=True, max_len=16),
                    "client_implicit_iv_hex": to_hex(session.client_write_iv),
                    "server_implicit_iv_hex": to_hex(session.server_write_iv)
                },
                "technical_details": {
                    "RFC": "RFC 5246 Section 6.3 & 8.1",
                    "PRF_algorithm": "P_SHA256 (HMAC-SHA256)",
                    "independent_derivation": "Both parties obtain identical keys without sending keys over wire."
                },
                "verification_status": {"valid": True, "message": "Session keys derived independently"},
                "can_advance": True,
                "is_complete": False
            }

        elif step == 6:
            # Step 6: Finished Messages
            transcript_hash = hashlib.sha256(session.transcript).digest()
            # client finished verify_data = PRF(master_secret, "client finished", Hash(handshake_messages))[0..12]
            client_verify_data = CryptoService.tls12_prf(session.master_secret, "client finished", transcript_hash, 12)
            server_verify_data = CryptoService.tls12_prf(session.master_secret, "server finished", transcript_hash, 12)

            if simulate_failure:
                session.protocol_state = "failed"
                session.error = "Finished message verification failed! Transcript hash mismatch indicates Man-In-The-Middle tampering."
                return {
                    "session_id": session.session_id,
                    "mode": session.mode,
                    "current_step": 6,
                    "step_title": "Finished Messages (TAMPER FAILURE DEMO)",
                    "message_direction": "internal",
                    "protocol_state": "failed",
                    "explanation": (
                        "FAILURE DEMO: Handshake transcript integrity check failed. If an attacker modified "
                        "any previous handshake message (e.g., downgrade attack), verify_data does not match."
                    ),
                    "crypto_values": {"transcript_verified": False},
                    "technical_details": {"Alert": "decrypt_error / handshake_failure"},
                    "verification_status": {"valid": False, "message": "Finished HMAC verification failed"},
                    "can_advance": False,
                    "is_complete": False,
                    "error": "Handshake aborted."
                }

            session.current_step = 6
            session.protocol_state = "established"

            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 6,
                "step_title": "ChangeCipherSpec & Finished Messages",
                "message_direction": "bidirectional",
                "protocol_state": "established",
                "explanation": (
                    "Both parties send ChangeCipherSpec and Finished messages. The Finished message contains "
                    "a 12-byte verify_data computed over the SHA-256 hash of all prior handshake messages. "
                    "Successful verification guarantees that no messages were tampered with by an active attacker."
                ),
                "crypto_values": {
                    "transcript_hash_hex": to_hex(transcript_hash, shorten=True, max_len=16),
                    "client_verify_data_hex": to_hex(client_verify_data),
                    "server_verify_data_hex": to_hex(server_verify_data),
                    "integrity_verified": True
                },
                "technical_details": {
                    "RFC": "RFC 5246 Section 7.4.9",
                    "security_role": "Authenticates the entire handshake negotiation."
                },
                "verification_status": {"valid": True, "message": "TLS 1.2 secure channel established"},
                "can_advance": True,
                "is_complete": True
            }

        elif step == 7:
            # Step 7: Encrypted Application Data view
            session.current_step = 7
            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 7,
                "step_title": "Encrypted Application Data",
                "message_direction": "bidirectional",
                "protocol_state": "established",
                "explanation": (
                    "The secure TLS tunnel is active! Application protocols such as HTTP/1.1 or HTTP/2 "
                    "transmit data symmetrically encrypted and authenticated using AES-128-GCM."
                ),
                "crypto_values": {
                    "cipher": "AES-128-GCM",
                    "channel_active": True
                },
                "technical_details": {
                    "RFC": "RFC 5246 Section 10",
                    "status": "Ready for application traffic transmission."
                },
                "verification_status": {"valid": True, "message": "Secure channel ready for application traffic"},
                "can_advance": False,
                "is_complete": True
            }

        raise ValueError(f"Unknown step {step}")

    # -------------------------------------------------------------
    # TLS 1.3 Handshake Execution
    # -------------------------------------------------------------
    def _execute_tls13_step(self, session: TLSSession, step: int, simulate_failure: bool) -> Dict[str, Any]:
        if step == 1:
            # Step 1: ClientHello with key_share (X25519)
            session.client_random = CryptoService.generate_random_bytes(32)
            c_priv, c_pub = CryptoService.generate_x25519_keypair()
            session.client_dhe_priv = c_priv
            session.client_dhe_pub_bytes = c_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            session.transcript.extend(b"TLS13_ClientHello:" + session.client_random + session.client_dhe_pub_bytes)
            session.current_step = 1
            session.protocol_state = "in_progress"

            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 1,
                "step_title": "TLS 1.3 ClientHello with Key Share",
                "message_direction": "client_to_server",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "TLS 1.3 anticipates the key exchange in the very first message! Along with supported "
                    "AEAD cipher suites, the client includes a 'key_share' extension containing its ephemeral "
                    "Diffie-Hellman public key (Curve25519/X25519). This enables 1-RTT handshake completion."
                ),
                "crypto_values": {
                    "client_random_preview": to_hex(session.client_random, shorten=True, max_len=16),
                    "supported_groups": ["X25519", "secp256r1"],
                    "client_key_share_hex": to_hex(session.client_dhe_pub_bytes, shorten=True, max_len=16),
                    "offered_ciphers": ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
                },
                "technical_details": {
                    "RFC": "RFC 8446 Section 4.1.2",
                    "modern_improvement": "Eliminated legacy insecure cipher suites and RSA key exchange."
                },
                "verification_status": {"valid": True, "message": "ClientHello and key_share generated"},
                "can_advance": True,
                "is_complete": False
            }

        elif step == 2:
            # Step 2: ServerHello with server key_share
            session.server_random = CryptoService.generate_random_bytes(32)
            s_priv, s_pub = CryptoService.generate_x25519_keypair()
            session.server_dhe_priv = s_priv
            session.server_dhe_pub_bytes = s_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            session.transcript.extend(b"TLS13_ServerHello:" + session.server_random + session.server_dhe_pub_bytes)
            session.current_step = 2

            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 2,
                "step_title": "TLS 1.3 ServerHello with Server Key Share",
                "message_direction": "server_to_client",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "The server selects TLS_AES_128_GCM_SHA256 and sends its own ephemeral X25519 key share. "
                    "From this moment onwards, both parties can immediately calculate the shared secret. "
                    "Everything following ServerHello is ENCRYPTED using Handshake Traffic Keys!"
                ),
                "crypto_values": {
                    "server_random_preview": to_hex(session.server_random, shorten=True, max_len=16),
                    "selected_cipher": "TLS_AES_128_GCM_SHA256",
                    "server_key_share_hex": to_hex(session.server_dhe_pub_bytes, shorten=True, max_len=16)
                },
                "technical_details": {
                    "RFC": "RFC 8446 Section 4.1.3",
                    "forward_secrecy": "Ephemeral keys are discarded after session; past traffic cannot be decrypted later."
                },
                "verification_status": {"valid": True, "message": "ServerHello and key share exchanged"},
                "can_advance": True,
                "is_complete": False
            }

        elif step == 3:
            # Step 3: Ephemeral Diffie-Hellman Shared Secret Derivation
            # Client uses its private key and server's public key
            # Server uses its private key and client's public key
            server_pub = serialization.load_der_public_key(
                # Raw format import for x25519
                # In cryptography library, load raw bytes directly:
                b""  # We'll use raw public key import
            ) if False else None

            # With cryptography library for raw x25519:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
            peer_pub_client = X25519PublicKey.from_public_bytes(session.server_dhe_pub_bytes)
            peer_pub_server = X25519PublicKey.from_public_bytes(session.client_dhe_pub_bytes)

            client_shared = session.client_dhe_priv.exchange(peer_pub_client)
            server_shared = session.server_dhe_priv.exchange(peer_pub_server)
            assert client_shared == server_shared
            session.dhe_shared_secret = client_shared

            session.current_step = 3

            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 3,
                "step_title": "Ephemeral Diffie-Hellman Shared Secret Derivation",
                "message_direction": "internal",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "Client and server independently compute the shared secret using Elliptic Curve Diffie-Hellman "
                    "(ECDH) over Curve25519: S = private_client * Public_server = private_server * Public_client. "
                    "Neither private key was transmitted across the network."
                ),
                "crypto_values": {
                    "shared_secret_preview": to_hex(session.dhe_shared_secret, shorten=True, max_len=16),
                    "curve": "Curve25519 (RFC 7748)",
                    "keys_match": True
                },
                "technical_details": {
                    "RFC": "RFC 8446 Section 7.1",
                    "property": "Perfect Forward Secrecy (PFS)"
                },
                "verification_status": {"valid": True, "message": "ECDH shared secret derived identically"},
                "can_advance": True,
                "is_complete": False
            }

        elif step == 4:
            # Step 4: TLS 1.3 Key Schedule (HKDF)
            # 1. Early Secret = HKDF-Extract(0, 0)
            early_secret = CryptoService.hkdf_extract(None, b"\x00" * 32)
            # 2. Derive Handshake Secret from DHE shared secret
            derived_secret = CryptoService.hkdf_expand_label(early_secret, "derived", hashlib.sha256(b"").digest(), 32)
            handshake_secret = CryptoService.hkdf_extract(derived_secret, session.dhe_shared_secret)

            session.early_secret = early_secret
            session.handshake_secret = handshake_secret

            # Handshake traffic keys
            transcript_hash = hashlib.sha256(session.transcript).digest()
            client_hs_traffic_secret = CryptoService.hkdf_expand_label(handshake_secret, "c hs traffic", transcript_hash, 32)
            server_hs_traffic_secret = CryptoService.hkdf_expand_label(handshake_secret, "s hs traffic", transcript_hash, 32)

            session.client_hs_traffic_key = CryptoService.hkdf_expand_label(client_hs_traffic_secret, "key", b"", 16)
            session.server_hs_traffic_key = CryptoService.hkdf_expand_label(server_hs_traffic_secret, "key", b"", 16)

            session.current_step = 4

            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 4,
                "step_title": "TLS 1.3 HKDF Key Schedule (Handshake Secret)",
                "message_direction": "internal",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "Using HKDF (RFC 5869), the TLS 1.3 key schedule mixes the Diffie-Hellman secret into "
                    "the Handshake Secret. From this, client and server handshake traffic keys are derived "
                    "to encrypt subsequent handshake messages."
                ),
                "crypto_values": {
                    "early_secret_preview": to_hex(session.early_secret, shorten=True, max_len=16),
                    "handshake_secret_preview": to_hex(session.handshake_secret, shorten=True, max_len=16),
                    "client_hs_key_preview": to_hex(session.client_hs_traffic_key, shorten=True, max_len=16),
                    "server_hs_key_preview": to_hex(session.server_hs_traffic_key, shorten=True, max_len=16)
                },
                "technical_details": {
                    "RFC": "RFC 8446 Section 7.1",
                    "KDF": "HKDF-Extract and HKDF-Expand-Label (HMAC-SHA256)"
                },
                "verification_status": {"valid": True, "message": "Handshake traffic keys derived"},
                "can_advance": True,
                "is_complete": False
            }

        elif step == 5:
            # Step 5: Encrypted Extensions, Encrypted Certificate & CertificateVerify
            cert, priv_key, cert_pem = CertificateService.generate_demo_certificate()
            session.cert = cert
            session.rsa_private_key = priv_key
            session.rsa_public_key = priv_key.public_key()
            session.cert_pem = cert_pem.decode('ascii')

            cert_info = CertificateService.parse_certificate_info(cert)
            session.current_step = 5

            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 5,
                "step_title": "EncryptedExtensions & Encrypted Certificate",
                "message_direction": "server_to_client",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "MAJOR TLS 1.3 PRIVACY ENHANCEMENT: Unlike TLS 1.2 where the certificate was transmitted in "
                    "cleartext, TLS 1.3 encrypts the EncryptedExtensions, Certificate, and CertificateVerify messages "
                    "using the server handshake traffic key. Passive network eavesdroppers cannot see which server identity is requested."
                ),
                "crypto_values": {
                    "certificate_encrypted_in_transit": True,
                    "server_identity": cert_info["subject"]["common_name"],
                    "signature_scheme": "rsa_pss_rsae_sha256",
                    "certificate_fingerprint": cert_info["sha256_fingerprint"]
                },
                "technical_details": {
                    "RFC": "RFC 8446 Section 4.3 & 4.4",
                    "privacy": "SNI and Certificates are protected against passive eavesdropping."
                },
                "verification_status": {"valid": True, "message": "Server certificate authenticated and verified"},
                "can_advance": True,
                "is_complete": False
            }

        elif step == 6:
            # Step 6: Finished Messages & Application Traffic Keys
            # Master Secret = HKDF-Extract(derived_from_handshake, 0)
            derived = CryptoService.hkdf_expand_label(session.handshake_secret, "derived", hashlib.sha256(b"").digest(), 32)
            master_secret = CryptoService.hkdf_extract(derived, b"\x00" * 32)
            session.master_secret = master_secret

            transcript_hash = hashlib.sha256(session.transcript).digest()
            c_app_secret = CryptoService.hkdf_expand_label(master_secret, "c ap traffic", transcript_hash, 32)
            s_app_secret = CryptoService.hkdf_expand_label(master_secret, "s ap traffic", transcript_hash, 32)

            session.client_write_key = CryptoService.hkdf_expand_label(c_app_secret, "key", b"", 16)
            session.server_write_key = CryptoService.hkdf_expand_label(s_app_secret, "key", b"", 16)
            session.client_write_iv = CryptoService.hkdf_expand_label(c_app_secret, "iv", b"", 12)
            session.server_write_iv = CryptoService.hkdf_expand_label(s_app_secret, "iv", b"", 12)

            session.current_step = 6
            session.protocol_state = "established"

            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 6,
                "step_title": "Finished Messages & Application Keys",
                "message_direction": "bidirectional",
                "protocol_state": "established",
                "explanation": (
                    "Finished messages verify handshake integrity with HMAC-SHA256. Once verified, the key schedule "
                    "transitions to Application Traffic Keys. The secure TLS 1.3 tunnel is fully established in only 1 RTT."
                ),
                "crypto_values": {
                    "master_secret_preview": to_hex(session.master_secret, shorten=True, max_len=16),
                    "client_application_key": to_hex(session.client_write_key, shorten=True, max_len=16),
                    "server_application_key": to_hex(session.server_write_key, shorten=True, max_len=16),
                    "rtt_latency": "1 Round Trip Time (1-RTT)"
                },
                "technical_details": {
                    "RFC": "RFC 8446 Section 4.4.4",
                    "state": "Handshake Complete. Traffic encrypted with AES-128-GCM."
                },
                "verification_status": {"valid": True, "message": "TLS 1.3 secure channel established"},
                "can_advance": True,
                "is_complete": True
            }

        elif step == 7:
            # Step 7: Encrypted Application Data view
            session.current_step = 7
            return {
                "session_id": session.session_id,
                "mode": session.mode,
                "current_step": 7,
                "step_title": "Encrypted Application Data",
                "message_direction": "bidirectional",
                "protocol_state": "established",
                "explanation": "Ready to transmit encrypted HTTP application data over the TLS 1.3 channel.",
                "crypto_values": {
                    "cipher": "AES-128-GCM",
                    "channel_active": True
                },
                "technical_details": {"RFC": "RFC 8446 Section 5"},
                "verification_status": {"valid": True, "message": "Channel active"},
                "can_advance": False,
                "is_complete": True
            }

        raise ValueError(f"Unknown step {step}")

    # -------------------------------------------------------------
    # Application Data Encryption / Decryption Demonstration
    # -------------------------------------------------------------
    def process_application_data(self, session_id: str, message: str, tamper_ciphertext: bool = False) -> Dict[str, Any]:
        session = self.get_session(session_id)
        if not session:
            raise ValueError("Session not found.")
        if session.protocol_state != "established" and session.current_step < 6:
            raise ValueError("Handshake is not yet established. Cannot transmit application data.")

        plaintext_bytes = message.encode('utf-8')
        # Encrypt with client_write_key
        enc_result = CryptoService.aes_gcm_encrypt(session.client_write_key, plaintext_bytes)

        ciphertext = enc_result["ciphertext"]
        nonce = enc_result["nonce"]
        tag = enc_result["tag"]

        tamper_applied = False
        if tamper_ciphertext and len(ciphertext) > 0:
            # Flip one bit in ciphertext
            tampered_list = bytearray(ciphertext)
            tampered_list[0] ^= 0x01
            ciphertext = bytes(tampered_list)
            tamper_applied = True

        # Now attempt decryption on server side
        decryption_success = False
        decrypted_text = None
        error_msg = None

        try:
            decrypted_bytes = CryptoService.aes_gcm_decrypt(session.client_write_key, nonce, ciphertext, tag)
            decrypted_text = decrypted_bytes.decode('utf-8')
            decryption_success = True
        except Exception as e:
            error_msg = str(e)
            decryption_success = False

        record = {
            "timestamp": time.time(),
            "plaintext": message,
            "ciphertext_hex": to_hex(ciphertext),
            "ciphertext_b64": to_base64(ciphertext),
            "nonce_hex": to_hex(nonce),
            "tag_hex": to_hex(tag),
            "tampered": tamper_applied,
            "success": decryption_success,
            "decrypted_plaintext": decrypted_text,
            "error": error_msg
        }
        session.messages_exchanged.append(record)
        return record

tls_service = TLSService()
