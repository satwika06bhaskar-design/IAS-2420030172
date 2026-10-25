from fastapi import APIRouter
from typing import List, Dict, Any

router = APIRouter(prefix="/api/learning", tags=["Learning"])

GLOSSARY_ITEMS: List[Dict[str, Any]] = [
    {
        "id": "encryption",
        "term": "Encryption",
        "category": "Fundamentals",
        "simple_definition": "The process of scrambling readable information into an unreadable form using a secret key.",
        "technical_definition": "A mathematical transformation C = E_k(P) that maps plaintext P to ciphertext C using a key k.",
        "example": "Turning 'Hello' into random-looking characters like '8f2a9c...'",
        "protocol": "TLS, SSH, IPsec"
    },
    {
        "id": "decryption",
        "term": "Decryption",
        "category": "Fundamentals",
        "simple_definition": "The reverse of encryption; converting scrambled ciphertext back into original readable text using the correct key.",
        "technical_definition": "The inverse operation P = D_k(C) that recovers original plaintext P from ciphertext C.",
        "example": "Turning '8f2a9c...' back into 'Hello' with the session key.",
        "protocol": "TLS, SSH, IPsec"
    },
    {
        "id": "plaintext",
        "term": "Plaintext",
        "category": "Fundamentals",
        "simple_definition": "Unencrypted, readable information that anyone can read without any key.",
        "technical_definition": "The original cleartext data before cryptographic encryption is applied.",
        "example": "'GET /index.html' or 'password123'",
        "protocol": "All Protocols"
    },
    {
        "id": "ciphertext",
        "term": "Ciphertext",
        "category": "Fundamentals",
        "simple_definition": "The scrambled, unreadable result produced by encrypting plaintext.",
        "technical_definition": "The encrypted output that appears as random binary or hex data to an observer.",
        "example": "'q8r+ZgN9bL==' or 'a3f019c8...'",
        "protocol": "All Protocols"
    },
    {
        "id": "public_key",
        "term": "Public Key",
        "category": "Asymmetric Cryptography",
        "simple_definition": "A key that can be openly shared with anyone. Used to encrypt messages or verify signatures.",
        "technical_definition": "The public half of an asymmetric key pair, derived from a private key using a one-way mathematical function.",
        "example": "A website's public key inside its digital certificate.",
        "protocol": "TLS, SSH"
    },
    {
        "id": "private_key",
        "term": "Private Key",
        "category": "Asymmetric Cryptography",
        "simple_definition": "A secret key that must be kept confidential by its owner. Never sent over the network.",
        "technical_definition": "The confidential secret parameter used for decrypting ciphertexts and creating digital signatures.",
        "example": "The server's private key stored securely in server memory.",
        "protocol": "TLS, SSH"
    },
    {
        "id": "symmetric_encryption",
        "term": "Symmetric Encryption",
        "category": "Symmetric Cryptography",
        "simple_definition": "Encryption where both sides use the same secret key to encrypt and decrypt.",
        "technical_definition": "A cipher where the encryption key and decryption key are identical. Very fast for large data.",
        "example": "AES-128-GCM encrypting web page traffic with a shared session key.",
        "protocol": "TLS, SSH, IPsec"
    },
    {
        "id": "asymmetric_encryption",
        "term": "Asymmetric Encryption",
        "category": "Asymmetric Cryptography",
        "simple_definition": "Encryption that uses a pair of keys: a public key for encryption and a private key for decryption.",
        "technical_definition": "Public-key cryptography relying on mathematical trapdoor functions like RSA or ECC.",
        "example": "Encrypting a pre-master secret using the server's RSA public key.",
        "protocol": "TLS 1.2, SSH"
    },
    {
        "id": "rsa",
        "term": "RSA",
        "category": "Asymmetric Cryptography",
        "simple_definition": "A popular asymmetric encryption algorithm based on the difficulty of factoring very large prime numbers.",
        "technical_definition": "Rivest–Shamir–Adleman public-key cryptosystem used for key exchange and digital signatures.",
        "example": "An RSA 2048-bit key pair on a web server.",
        "protocol": "TLS 1.2, SSH"
    },
    {
        "id": "diffie_hellman",
        "term": "Diffie–Hellman",
        "category": "Key Exchange",
        "simple_definition": "A method that allows two computers to create a shared secret key without sending the secret itself over the network.",
        "technical_definition": "Key-exchange protocol based on the discrete logarithm problem (modular arithmetic or elliptic curves).",
        "example": "Curve25519 (X25519) key exchange in TLS 1.3 and SSH.",
        "protocol": "TLS 1.3, SSH, IPsec"
    },
    {
        "id": "session_key",
        "term": "Session Key",
        "category": "Symmetric Cryptography",
        "simple_definition": "A temporary secret key used to encrypt data only for the duration of a single conversation.",
        "technical_definition": "A symmetric key derived during the handshake and discarded when the session ends.",
        "example": "A 16-byte AES key used while browsing a secure banking site.",
        "protocol": "TLS, SSH, IPsec"
    },
    {
        "id": "pre_master_secret",
        "term": "Pre-Master Secret (PMS)",
        "category": "TLS Specifics",
        "simple_definition": "The raw initial secret generated during the TLS handshake before creating session keys.",
        "technical_definition": "A 48-byte random value in TLS 1.2 or shared Diffie-Hellman secret in TLS 1.3.",
        "example": "48 random bytes generated by the browser in TLS 1.2.",
        "protocol": "TLS 1.2"
    },
    {
        "id": "master_secret",
        "term": "Master Secret",
        "category": "TLS Specifics",
        "simple_definition": "The key derived from the pre-master secret that is used to create all working session keys.",
        "technical_definition": "Master Secret = PRF(pre_master_secret, 'master secret', ClientRandom + ServerRandom).",
        "example": "The 48-byte secret stored in memory by client and server.",
        "protocol": "TLS 1.2, TLS 1.3"
    },
    {
        "id": "digital_certificate",
        "term": "Digital Certificate",
        "category": "Authentication",
        "simple_definition": "An electronic identity card that proves a website's identity and provides its public key.",
        "technical_definition": "An X.509 document binding an identity to a public key, signed by a trusted Certificate Authority.",
        "example": "An HTTPS certificate showing google.com belongs to Google LLC.",
        "protocol": "TLS, IPsec"
    },
    {
        "id": "certificate_authority",
        "term": "Certificate Authority (CA)",
        "category": "Authentication",
        "simple_definition": "A trusted organization that verifies websites and issues signed digital certificates.",
        "technical_definition": "A trusted third-party organization that signs digital certificates using a root private key.",
        "example": "Let's Encrypt or DigiCert.",
        "protocol": "TLS"
    },
    {
        "id": "tls",
        "term": "TLS (Transport Layer Security)",
        "category": "Protocols",
        "simple_definition": "The standard security protocol that protects web browsing (HTTPS) and API requests.",
        "technical_definition": "A cryptographic protocol operating above TCP providing confidentiality, integrity, and authentication.",
        "example": "https:// in your web browser URL bar.",
        "protocol": "TLS"
    },
    {
        "id": "ssh",
        "term": "SSH (Secure Shell)",
        "category": "Protocols",
        "simple_definition": "A secure protocol used to log in to and control remote computers via command line.",
        "technical_definition": "A network protocol (RFC 4251) providing encrypted remote shell, port forwarding, and SFTP transfers.",
        "example": "Running 'ssh student@server.com' in a terminal.",
        "protocol": "SSH"
    },
    {
        "id": "ipsec",
        "term": "IPsec (Internet Protocol Security)",
        "category": "Protocols",
        "simple_definition": "A suite of protocols that secures network packets at the IP network layer, often used for VPNs.",
        "technical_definition": "Protocol suite (RFC 4301) operating at Layer 3 to authenticate and encrypt IP packets.",
        "example": "A corporate VPN connecting a branch office to headquarters.",
        "protocol": "IPsec"
    },
    {
        "id": "esp",
        "term": "ESP (Encapsulating Security Payload)",
        "category": "IPsec Specifics",
        "simple_definition": "The IPsec component that provides encryption, data integrity, and anti-replay for packets.",
        "technical_definition": "IP protocol 50 that encapsulates packet data with symmetric encryption and an integrity check value.",
        "example": "ESP packet with SPI 0x10002000 encrypting TCP traffic.",
        "protocol": "IPsec"
    },
    {
        "id": "hash_function",
        "term": "Hash Function",
        "category": "Integrity",
        "simple_definition": "A one-way calculation that produces a fixed-size fingerprint of any data. Cannot be reversed.",
        "technical_definition": "A deterministic mathematical algorithm like SHA-256 mapping arbitrary data to a fixed-size digest.",
        "example": "SHA-256 producing 64 hexadecimal characters from a file.",
        "protocol": "All Protocols"
    },
    {
        "id": "digital_signature",
        "term": "Digital Signature",
        "category": "Authentication",
        "simple_definition": "A mathematical stamp proving that a message was sent by the real sender and was not changed.",
        "technical_definition": "A cryptographic hash encrypted with a private key and verified with the sender's public key.",
        "example": "An Ed25519 signature proving an SSH server's identity.",
        "protocol": "TLS, SSH"
    },
    {
        "id": "message_integrity",
        "term": "Message Integrity",
        "category": "Integrity",
        "simple_definition": "The guarantee that data has not been modified, corrupted, or tampered with by an attacker.",
        "technical_definition": "Protection against unauthorized alteration using MACs or AEAD authentication tags.",
        "example": "A 16-byte authentication tag in AES-GCM.",
        "protocol": "TLS, SSH, IPsec"
    },
    {
        "id": "nonce",
        "term": "Nonce (Number Used Once)",
        "category": "Symmetric Cryptography",
        "simple_definition": "A number used only once in encryption to ensure that identical messages produce different ciphertexts.",
        "technical_definition": "A unique initialization value that must never be repeated under the same key in AEAD ciphers.",
        "example": "A 12-byte random value used in AES-GCM.",
        "protocol": "TLS, SSH, IPsec"
    },
    {
        "id": "key_derivation",
        "term": "Key Derivation",
        "category": "Key Exchange",
        "simple_definition": "A formula that creates multiple working keys (encryption keys, integrity keys) from one master secret.",
        "technical_definition": "A pseudo-random function (like HKDF or TLS PRF) that securely expands secret key material.",
        "example": "Turning a shared secret into separate client and server encryption keys.",
        "protocol": "TLS, SSH, IPsec"
    },
    {
        "id": "cipher_suite",
        "term": "Cipher Suite",
        "category": "Protocols",
        "simple_definition": "A named collection of cryptographic algorithms that work together to secure a connection.",
        "technical_definition": "A standardized bundle defining key exchange, authentication, bulk encryption, and hashing.",
        "example": "TLS_AES_128_GCM_SHA256 in TLS 1.3.",
        "protocol": "TLS, SSH"
    },
    {
        "id": "forward_secrecy",
        "term": "Forward Secrecy",
        "category": "Key Exchange",
        "simple_definition": "A security feature where even if a server's private key is stolen later, past recorded traffic remains safe.",
        "technical_definition": "Achieved when session keys are derived using temporary (ephemeral) keys that are erased after the session.",
        "example": "TLS 1.3 and modern SSH use ephemeral Diffie–Hellman for forward secrecy.",
        "protocol": "TLS 1.3, SSH, IPsec"
    }
]

PROTOCOL_COMPARISON = {
    "protocols": [
        {
            "name": "TLS",
            "acronym": "TLS",
            "main_purpose": "Securing web browser and application data streams",
            "what_it_protects": "Individual application connections (like website visits)",
            "authentication": "Digital certificates (X.509) verified by Certificate Authorities",
            "key_exchange": "Ephemeral Diffie–Hellman (TLS 1.3) or RSA (TLS 1.2)",
            "common_uses": "Web browsing (HTTPS), mobile apps, online banking, email",
            "layer": "Presentation / Session (Runs on top of TCP)",
            "primary_purpose": "Securing web browser and application data streams",
            "auth_methods": "Digital certificates (X.509)",
            "encryption": "AES-128-GCM, AES-256-GCM, ChaCha20",
            "integrity": "AEAD Authentication Tag or HMAC-SHA256",
            "protected_traffic": "Individual application streams (HTTP, WebSocket)",
            "common_use_cases": "Web browsing (HTTPS), API gateways, e-commerce, banking portals",
            "limitations": "Protects single application connections; does not protect whole network packets"
        },
        {
            "name": "SSH",
            "acronym": "SSH",
            "main_purpose": "Secure remote command line access and administration",
            "what_it_protects": "Terminal sessions, remote command execution, and file transfers",
            "authentication": "Host keys (for server) and Passwords or Public Keys (for users)",
            "key_exchange": "Diffie–Hellman / Curve25519 key exchange",
            "common_uses": "Remote Linux server login, DevOps, and file copy (SFTP)",
            "layer": "Application Layer (TCP Port 22)",
            "primary_purpose": "Secure remote command line access and administration",
            "auth_methods": "Server Host Key & User Passwords / Public Keys",
            "encryption": "AES-256-GCM, ChaCha20-Poly1305",
            "integrity": "AEAD tags, HMAC-SHA256",
            "protected_traffic": "Interactive terminal sessions, file transfers (SFTP)",
            "common_use_cases": "Remote server administration, DevOps pipelines, Git",
            "limitations": "Designed for remote terminal sessions, not broad transparent network routing"
        },
        {
            "name": "IPsec",
            "acronym": "IPsec",
            "main_purpose": "Protecting network communication at the IP packet layer",
            "what_it_protects": "All network packets between two devices or networks",
            "authentication": "Pre-shared passwords (PSK) or digital certificates",
            "key_exchange": "Internet Key Exchange (IKEv2 / Diffie–Hellman)",
            "common_uses": "Site-to-Site VPNs connecting offices, remote work VPNs",
            "layer": "Network Layer (Layer 3 IP Protocol 50)",
            "primary_purpose": "Protecting network communication at the IP packet layer",
            "auth_methods": "Pre-Shared Keys (PSK) or Digital Certificates",
            "encryption": "ESP using AES-256-GCM, AES-CBC",
            "integrity": "ESP ICV (Authentication Tag / HMAC)",
            "protected_traffic": "All IP datagrams (TCP, UDP, ICMP) transparently",
            "common_use_cases": "Site-to-Site VPNs connecting offices, remote access VPNs",
            "limitations": "Requires network configuration at the operating system or router level"
        }
    ],
    "interactive_scenarios": [
        {
            "id": "scenario_web",
            "question": "Which protocol should you use to secure an online banking website for regular customers?",
            "recommended_protocol": "TLS",
            "why": "TLS is built into every web browser. Customers don't need to install any VPN software or configure special keys."
        },
        {
            "id": "scenario_devops",
            "question": "Which protocol should a student or system administrator use to log into a remote Linux server?",
            "recommended_protocol": "SSH",
            "why": "SSH provides an interactive terminal shell and allows logging in using public keys without passwords."
        },
        {
            "id": "scenario_vpn",
            "question": "Which protocol should be used to connect two school campuses so all computers can communicate securely?",
            "recommended_protocol": "IPsec (Tunnel Mode)",
            "why": "IPsec Tunnel Mode protects all network packets between routers automatically, without needing settings on individual computers."
        }
    ]
}

@router.get("/glossary")
def get_glossary():
    return {"terms": GLOSSARY_ITEMS, "total": len(GLOSSARY_ITEMS)}

@router.get("/protocols")
def get_protocol_comparison():
    return PROTOCOL_COMPARISON
