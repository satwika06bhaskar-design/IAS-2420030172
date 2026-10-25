import time
import uuid
import hashlib
import threading
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from app.services.crypto_service import CryptoService
from app.utils.encoding import to_hex, to_base64, sha256_fingerprint

class SSHSession:
    def __init__(self, session_id: str, client_version: str = "SSH-2.0-SecureTunnel_Client_1.0"):
        self.session_id = session_id
        self.client_version = client_version
        self.server_version = "SSH-2.0-OpenSSH_9.3p1 Debian-1ubuntu3"
        self.current_step = 0
        self.protocol_state = "initialized"
        self.created_at = time.time()
        self.updated_at = time.time()
        self.error: Optional[str] = None

        # Ephemeral Diffie-Hellman (X25519)
        self.client_kex_priv = None
        self.client_kex_pub_bytes: bytes = b""
        self.server_kex_priv = None
        self.server_kex_pub_bytes: bytes = b""
        self.shared_secret_k: bytes = b""

        # Server Host Key (Ed25519)
        self.server_host_priv, self.server_host_pub = CryptoService.generate_ed25519_keypair()
        self.server_host_pub_bytes: bytes = self.server_host_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        self.server_fingerprint = sha256_fingerprint(self.server_host_pub_bytes)
        self.known_host_fingerprint = self.server_fingerprint  # In trusted scenario

        # Exchange Hash H
        self.exchange_hash_h: bytes = b""
        self.exchange_signature: bytes = b""

        # Session Keys (RFC 4253 KDF 'A'..'F')
        self.client_iv: bytes = b""
        self.server_iv: bytes = b""
        self.client_enc_key: bytes = b""
        self.server_enc_key: bytes = b""
        self.client_mac_key: bytes = b""
        self.server_mac_key: bytes = b""

        # User Authentication
        self.user_authenticated: bool = False
        self.authenticated_user: Optional[str] = None
        self.auth_method_used: Optional[str] = None

        # Command history in terminal
        self.terminal_history: list = []

class SSHService:
    def __init__(self):
        self._sessions: Dict[str, SSHSession] = {}
        self._lock = threading.Lock()

    def create_session(self, client_version: str = "SSH-2.0-SecureTunnel_Client_1.0") -> SSHSession:
        with self._lock:
            now = time.time()
            expired = [sid for sid, s in self._sessions.items() if now - s.updated_at > 3600]
            for sid in expired:
                del self._sessions[sid]

            session_id = str(uuid.uuid4())
            session = SSHSession(session_id, client_version)
            self._sessions[session_id] = session
            return session

    def get_session(self, session_id: str) -> Optional[SSHSession]:
        with self._lock:
            return self._sessions.get(session_id)

    def reset_session(self, session_id: str) -> Optional[SSHSession]:
        with self._lock:
            if session_id in self._sessions:
                c_ver = self._sessions[session_id].client_version
                session = SSHSession(session_id, c_ver)
                self._sessions[session_id] = session
                return session
            return None

    def execute_step(self, session_id: str, step: int, host_key_scenario: str = "trusted", simulate_failure: bool = False) -> Dict[str, Any]:
        session = self.get_session(session_id)
        if not session:
            raise ValueError("SSH Session not found.")

        session.updated_at = time.time()
        expected_step = session.current_step + 1

        if step != expected_step and not (step == session.current_step and simulate_failure):
            raise ValueError(f"Invalid SSH step sequence: expected {expected_step}, requested {step}")

        # ---------------------------------------------------------
        # Step 1: Protocol Version Exchange
        # ---------------------------------------------------------
        if step == 1:
            session.current_step = 1
            session.protocol_state = "in_progress"
            return {
                "session_id": session.session_id,
                "current_step": 1,
                "step_title": "Protocol Version Exchange",
                "message_direction": "bidirectional",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "When the TCP connection opens on port 22, both endpoints immediately exchange an identification "
                    "string ending in CRLF. This establishes protocol compatibility (SSH-2.0) and software identity."
                ),
                "crypto_values": {
                    "client_banner": session.client_version,
                    "server_banner": session.server_version,
                    "protocol_version_negotiated": "SSH-2.0"
                },
                "technical_details": {
                    "RFC": "RFC 4253 Section 4.2",
                    "transport_rule": "Lines must begin with 'SSH-protoversion-softwareversion'."
                },
                "verification_status": {"valid": True, "message": "SSH-2.0 protocol matched"},
                "can_advance": True,
                "is_complete": False
            }

        # ---------------------------------------------------------
        # Step 2: Algorithm Negotiation (SSH_MSG_KEXINIT)
        # ---------------------------------------------------------
        elif step == 2:
            session.current_step = 2
            return {
                "session_id": session.session_id,
                "current_step": 2,
                "step_title": "Algorithm Negotiation (SSH_MSG_KEXINIT)",
                "message_direction": "bidirectional",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "Both parties send an SSH_MSG_KEXINIT packet with lists of supported algorithms in preference order. "
                    "The client and server select the first algorithm in the client's list that is also supported by the server."
                ),
                "crypto_values": {
                    "negotiated_kex": "curve25519-sha256@libssh.org",
                    "negotiated_host_key": "ssh-ed25519",
                    "negotiated_encryption_c2s": "aes256-gcm@openssh.com",
                    "negotiated_encryption_s2c": "aes256-gcm@openssh.com",
                    "negotiated_mac": "AEAD (integrated into AES-GCM)",
                    "negotiated_compression": "none"
                },
                "technical_details": {
                    "RFC": "RFC 4253 Section 7.1",
                    "packet_code": "SSH_MSG_KEXINIT (20)",
                    "cookie_length": "16 random bytes sent to prevent replays"
                },
                "verification_status": {"valid": True, "message": "Mutually compatible algorithms negotiated"},
                "can_advance": True,
                "is_complete": False
            }

        # ---------------------------------------------------------
        # Step 3: Diffie-Hellman Key Exchange (Curve25519)
        # ---------------------------------------------------------
        elif step == 3:
            # Client generates ephemeral keypair
            c_priv, c_pub = CryptoService.generate_x25519_keypair()
            session.client_kex_priv = c_priv
            session.client_kex_pub_bytes = c_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            # Server generates ephemeral keypair
            s_priv, s_pub = CryptoService.generate_x25519_keypair()
            session.server_kex_priv = s_priv
            session.server_kex_pub_bytes = s_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )

            # Client computes shared secret: client_priv * server_pub
            # Server computes shared secret: server_priv * client_pub
            peer_s_pub = X25519PublicKey.from_public_bytes(session.server_kex_pub_bytes)
            peer_c_pub = X25519PublicKey.from_public_bytes(session.client_kex_pub_bytes)

            k_client = session.client_kex_priv.exchange(peer_s_pub)
            k_server = session.server_kex_priv.exchange(peer_c_pub)
            assert k_client == k_server
            session.shared_secret_k = k_client

            session.current_step = 3
            return {
                "session_id": session.session_id,
                "current_step": 3,
                "step_title": "Diffie-Hellman Key Exchange (ECDH / Curve25519)",
                "message_direction": "bidirectional",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "Client sends public value e (SSH_MSG_KEX_ECDH_INIT). Server replies with public value f (SSH_MSG_KEX_ECDH_REPLY). "
                    "Each side combines its private ephemeral scalar with the peer's public key to compute the identical shared secret K. "
                    "Private values x and y never leave their respective memory spaces."
                ),
                "crypto_values": {
                    "client_ephemeral_public_e": to_hex(session.client_kex_pub_bytes, shorten=True, max_len=16),
                    "server_ephemeral_public_f": to_hex(session.server_kex_pub_bytes, shorten=True, max_len=16),
                    "derived_shared_secret_k": to_hex(session.shared_secret_k, shorten=True, max_len=16),
                    "mathematical_formula": "K = x * (y * G) = y * (x * G) on Curve25519"
                },
                "technical_details": {
                    "RFC": "RFC 5656 & RFC 8731",
                    "forward_secrecy": "Enabled. Ephemeral keys are discarded immediately after key derivation."
                },
                "verification_status": {"valid": True, "message": "Shared secret K derived identically on both sides"},
                "can_advance": True,
                "is_complete": False
            }

        # ---------------------------------------------------------
        # Step 4: Server Authentication & Host Key Verification
        # ---------------------------------------------------------
        elif step == 4:
            # Construct SSH exchange hash H:
            # H = HASH(V_C || V_S || I_C || I_S || K_S || e || f || K)
            h_data = (
                session.client_version.encode('ascii') +
                session.server_version.encode('ascii') +
                session.server_host_pub_bytes +
                session.client_kex_pub_bytes +
                session.server_kex_pub_bytes +
                session.shared_secret_k
            )
            session.exchange_hash_h = hashlib.sha256(h_data).digest()

            # Server signs exchange hash H with its host private key
            session.exchange_signature = CryptoService.ed25519_sign(session.server_host_priv, session.exchange_hash_h)

            # Scenario handling
            if host_key_scenario == "changed_mismatch" or simulate_failure:
                session.protocol_state = "failed"
                session.error = "Host key verification failed! Host key fingerprint does not match ~/.ssh/known_hosts!"
                return {
                    "session_id": session.session_id,
                    "current_step": 4,
                    "step_title": "Server Authentication (SECURITY WARNING: FINGERPRINT MISMATCH)",
                    "message_direction": "server_to_client",
                    "protocol_state": "failed",
                    "explanation": (
                        "CRITICAL SECURITY ALERT: Remote host identification has changed! "
                        "The server's fingerprint differs from the entry in ~/.ssh/known_hosts. "
                        "This indicates either a legitimate server re-installation or a MAN-IN-THE-MIDDLE (MITM) ATTACK. "
                        "The SSH client automatically aborts the connection."
                    ),
                    "crypto_values": {
                        "received_fingerprint": session.server_fingerprint,
                        "expected_known_hosts_fingerprint": "SHA256:FAKE_DIFFERENT_FINGERPRINT_FOR_DEMO",
                        "match": False
                    },
                    "technical_details": {
                        "status": "CONNECTION TERMINATED (Host key verification failed)",
                        "mitm_risk": "High. Potential active eavesdropper intercepting key exchange."
                    },
                    "verification_status": {"valid": False, "message": "Host key fingerprint mismatch rejected"},
                    "can_advance": False,
                    "is_complete": False,
                    "error": "Host key verification failed."
                }

            # Scenario: unknown host (first time connection)
            is_first_time = (host_key_scenario == "unknown_first_time")

            # Client verifies signature
            sig_valid = CryptoService.ed25519_verify(session.server_host_pub, session.exchange_signature, session.exchange_hash_h)

            session.current_step = 4
            return {
                "session_id": session.session_id,
                "current_step": 4,
                "step_title": "Server Authentication & Host Key Verification",
                "message_direction": "server_to_client",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "The server proves its identity by signing the exchange hash H with its private host key. "
                    "The client verifies this signature using the server's public host key. "
                    "Next, the client checks the host key's SHA-256 fingerprint against its local ~/.ssh/known_hosts file."
                ),
                "crypto_values": {
                    "host_key_type": "ssh-ed25519",
                    "host_key_fingerprint": session.server_fingerprint,
                    "exchange_hash_preview": to_hex(session.exchange_hash_h, shorten=True, max_len=16),
                    "signature_verified": sig_valid,
                    "trust_scenario": host_key_scenario
                },
                "technical_details": {
                    "RFC": "RFC 4253 Section 8",
                    "trust_model": "TOFU (Trust On First Use) via ~/.ssh/known_hosts",
                    "is_first_time_prompt": is_first_time
                },
                "verification_status": {"valid": sig_valid, "message": "Server host signature verified"},
                "can_advance": True,
                "is_complete": False
            }

        # ---------------------------------------------------------
        # Step 5: Session Key Derivation (RFC 4253 KDF)
        # ---------------------------------------------------------
        elif step == 5:
            # Session ID in SSH is equal to the exchange hash H of the first key exchange
            session_id_bytes = session.exchange_hash_h

            session.client_iv = CryptoService.ssh_kdf(session.shared_secret_k, session.exchange_hash_h, 'A', session_id_bytes, 12)
            session.server_iv = CryptoService.ssh_kdf(session.shared_secret_k, session.exchange_hash_h, 'B', session_id_bytes, 12)
            session.client_enc_key = CryptoService.ssh_kdf(session.shared_secret_k, session.exchange_hash_h, 'C', session_id_bytes, 32)
            session.server_enc_key = CryptoService.ssh_kdf(session.shared_secret_k, session.exchange_hash_h, 'D', session_id_bytes, 32)
            session.client_mac_key = CryptoService.ssh_kdf(session.shared_secret_k, session.exchange_hash_h, 'E', session_id_bytes, 32)
            session.server_mac_key = CryptoService.ssh_kdf(session.shared_secret_k, session.exchange_hash_h, 'F', session_id_bytes, 32)

            session.current_step = 5
            return {
                "session_id": session.session_id,
                "current_step": 5,
                "step_title": "Session Key Derivation (SSH Transport KDF)",
                "message_direction": "internal",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "SSH derives 6 directional cryptographic secrets using letters 'A' through 'F': "
                    "Initial IVs, Encryption Keys, and MAC integrity keys for both Client->Server and Server->Client directions. "
                    "Notice: This formula HASH(K || H || X || session_id) is distinct from the TLS PRF and TLS HKDF key schedules."
                ),
                "crypto_values": {
                    "key_A_client_iv": to_hex(session.client_iv, shorten=True, max_len=12),
                    "key_B_server_iv": to_hex(session.server_iv, shorten=True, max_len=12),
                    "key_C_client_enc_key": to_hex(session.client_enc_key, shorten=True, max_len=16),
                    "key_D_server_enc_key": to_hex(session.server_enc_key, shorten=True, max_len=16),
                    "key_E_client_mac_key": to_hex(session.client_mac_key, shorten=True, max_len=16),
                    "key_F_server_mac_key": to_hex(session.server_mac_key, shorten=True, max_len=16)
                },
                "technical_details": {
                    "RFC": "RFC 4253 Section 7.2",
                    "formula": "HASH(K || H || 'A'..'F' || session_id)",
                    "directional_security": "Independent keys prevent reflection attacks."
                },
                "verification_status": {"valid": True, "message": "SSH session keys derived"},
                "can_advance": True,
                "is_complete": False
            }

        # ---------------------------------------------------------
        # Step 6: User Authentication Overview
        # ---------------------------------------------------------
        elif step == 6:
            session.current_step = 6
            return {
                "session_id": session.session_id,
                "current_step": 6,
                "step_title": "User Authentication Protocol (SSH_MSG_USERAUTH_REQUEST)",
                "message_direction": "client_to_server",
                "protocol_state": session.protocol_state,
                "explanation": (
                    "CRITICAL CONCEPT: Server authentication proved the server's identity to the client in Step 4. "
                    "Now, USER authentication proves the client user's identity to the server! "
                    "All user authentication messages are sent encrypted over the secure transport established in Step 5."
                ),
                "crypto_values": {
                    "transport_layer_encrypted": True,
                    "supported_methods": ["password", "publickey"],
                    "current_user_status": "unauthenticated"
                },
                "technical_details": {
                    "RFC": "RFC 4252",
                    "service_requested": "ssh-userauth",
                    "security_note": "Passwords/credentials are protected inside the encrypted tunnel."
                },
                "verification_status": {"valid": True, "message": "Ready for user authentication"},
                "can_advance": True,
                "is_complete": False
            }

        # ---------------------------------------------------------
        # Step 7: Secure Channel & Interactive Terminal
        # ---------------------------------------------------------
        elif step == 7:
            if not session.user_authenticated:
                raise ValueError("User authentication must be completed before entering the shell session.")
            session.current_step = 7
            session.protocol_state = "established"
            return {
                "session_id": session.session_id,
                "current_step": 7,
                "step_title": "Secure Channel Established & Interactive Shell",
                "message_direction": "bidirectional",
                "protocol_state": "established",
                "explanation": (
                    "The SSH connection channel (session) is open and interactive shell is granted! "
                    "Every keystroke and command payload is encapsulated in an SSH binary packet, "
                    "symmetrically encrypted, and authenticated."
                ),
                "crypto_values": {
                    "authenticated_user": session.authenticated_user,
                    "auth_method": session.auth_method_used,
                    "cipher": "aes256-gcm@openssh.com"
                },
                "technical_details": {
                    "RFC": "RFC 4254 Section 6",
                    "channel_type": "session (pty-req, shell)"
                },
                "verification_status": {"valid": True, "message": "Interactive SSH terminal active"},
                "can_advance": False,
                "is_complete": True
            }

        raise ValueError(f"Unknown SSH step {step}")

    # ---------------------------------------------------------
    # User Authentication Execution
    # ---------------------------------------------------------
    def authenticate_user(
        self,
        session_id: str,
        auth_method: str,
        username: str,
        password: Optional[str] = None,
        public_key_authorized: bool = True,
        simulate_failure: bool = False
    ) -> Dict[str, Any]:
        session = self.get_session(session_id)
        if not session:
            raise ValueError("Session not found.")
        if session.current_step < 5:
            raise ValueError("Cannot authenticate user before session keys are derived.")

        if simulate_failure:
            return {
                "success": False,
                "method": auth_method,
                "username": username,
                "error": "Authentication failed: Permission denied (publickey,password).",
                "explanation": "Simulated incorrect credentials or unauthorized key. Server rejected request."
            }

        if auth_method == "password":
            # Educational check: demo credentials
            if username == "student" and (password == "cyber2026" or password == "demo"):
                session.user_authenticated = True
                session.authenticated_user = username
                session.auth_method_used = "password"
                return {
                    "success": True,
                    "method": "password",
                    "username": username,
                    "message": "SSH_MSG_USERAUTH_SUCCESS: Password verified inside encrypted transport.",
                    "explanation": "Password was delivered over the encrypted channel and accepted by PAM."
                }
            else:
                return {
                    "success": False,
                    "method": "password",
                    "username": username,
                    "error": "SSH_MSG_USERAUTH_FAILURE: Invalid demo password. (Hint: username='student', password='cyber2026')",
                    "explanation": "Simulated authentication failed due to invalid password."
                }

        elif auth_method == "publickey":
            if not public_key_authorized:
                return {
                    "success": False,
                    "method": "publickey",
                    "username": username,
                    "error": "SSH_MSG_USERAUTH_FAILURE: Public key not in authorized_keys.",
                    "explanation": "Server rejected key because it does not exist in ~/.ssh/authorized_keys."
                }

            # Generate demo client Ed25519 keypair and sign userauth challenge
            c_priv, c_pub = CryptoService.generate_ed25519_keypair()
            pub_bytes = c_pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            challenge = b"SSH-USERAUTH-CHALLENGE-" + session.exchange_hash_h
            sig = CryptoService.ed25519_sign(c_priv, challenge)
            verified = CryptoService.ed25519_verify(c_pub, sig, challenge)

            if verified:
                session.user_authenticated = True
                session.authenticated_user = username
                session.auth_method_used = "publickey (ssh-ed25519)"
                return {
                    "success": True,
                    "method": "publickey",
                    "username": username,
                    "client_key_fingerprint": sha256_fingerprint(pub_bytes),
                    "signature_verified": True,
                    "message": "SSH_MSG_USERAUTH_SUCCESS: Cryptographic signature verified against authorized_keys.",
                    "explanation": "User authenticated passwordlessly using Ed25519 digital signature."
                }
            else:
                return {
                    "success": False,
                    "method": "publickey",
                    "username": username,
                    "error": "Digital signature verification failed.",
                    "explanation": "The signature provided by the client private key could not be verified."
                }

        raise ValueError(f"Unknown auth method: {auth_method}")

    # ---------------------------------------------------------
    # Command Execution in Simulated Terminal
    # ---------------------------------------------------------
    def execute_command(self, session_id: str, command: str, tamper_packet: bool = False) -> Dict[str, Any]:
        session = self.get_session(session_id)
        if not session:
            raise ValueError("Session not found.")
        if not session.user_authenticated:
            raise ValueError("SSH terminal requires an authenticated session.")

        # Simulate SSH packet encryption
        cmd_bytes = command.encode('utf-8')
        enc = CryptoService.aes_gcm_encrypt(session.client_enc_key, cmd_bytes)

        ciphertext = enc["ciphertext"]
        nonce = enc["nonce"]
        tag = enc["tag"]

        tampered = False
        if tamper_packet and len(ciphertext) > 0:
            tampered_bytes = bytearray(ciphertext)
            tampered_bytes[0] ^= 0xFF
            ciphertext = bytes(tampered_bytes)
            tampered = True

        # Decrypt packet at server
        try:
            recovered_bytes = CryptoService.aes_gcm_decrypt(session.client_enc_key, nonce, ciphertext, tag)
            recovered_cmd = recovered_bytes.decode('utf-8').strip()
            # Process simulated Linux terminal output
            output = self._simulate_shell_response(recovered_cmd, session.authenticated_user)
            success = True
            error_reason = None
        except Exception as e:
            output = "Corrupted packet received! MAC / AEAD tag integrity verification failed. Connection closed."
            success = False
            error_reason = str(e)

        record = {
            "timestamp": time.time(),
            "command": command,
            "ciphertext_hex": to_hex(ciphertext),
            "nonce_hex": to_hex(nonce),
            "tag_hex": to_hex(tag),
            "tampered": tampered,
            "success": success,
            "output": output,
            "error": error_reason
        }
        session.terminal_history.append(record)
        return record

    def _simulate_shell_response(self, cmd: str, user: str) -> str:
        c = cmd.lower()
        if c in ("whoami", "id"):
            return f"uid=1001({user}) gid=1001({user}) groups=1001({user}),27(sudo)"
        elif c in ("pwd",):
            return f"/home/{user}"
        elif c in ("ls", "ls -la", "dir"):
            return "total 28\ndrwxr-xr-x 4 student student 4096 Oct 25 09:00 .\ndrwxr-xr-x 3 root    root    4096 Oct 25 08:30 ..\n-rw------- 1 student student  398 Oct 25 08:50 .bash_history\n-rw-r--r-- 1 student student  220 Oct 25 08:30 .bash_logout\ndrwx------ 2 student student 4096 Oct 25 08:45 .ssh\n-rw-r--r-- 1 student student  842 Oct 25 08:55 welcome.txt"
        elif c in ("cat welcome.txt", "type welcome.txt"):
            return "Welcome to the SecureTunnel Educational SSH Server!\nAll communications are protected by Curve25519 ECDH and AES-256-GCM."
        elif c in ("cat /etc/issue", "cat /etc/os-release"):
            return "Debian GNU/Linux 12 (bookworm) \\n \\l - SecureTunnel Lab Virtual Host"
        elif c in ("uname -a",):
            return "Linux securetunnel-lab 6.1.0-22-amd64 #1 SMP PREEMPT_DYNAMIC Debian x86_64 GNU/Linux"
        elif c in ("help", "?"):
            return "Available educational commands: whoami, pwd, ls -la, cat welcome.txt, cat /etc/issue, uname -a, clear, date"
        elif c == "date":
            return time.strftime("%a %b %d %H:%M:%S UTC %Y")
        elif c == "clear":
            return ""
        else:
            return f"{cmd}: simulated command executed successfully in educational shell."

ssh_service = SSHService()
