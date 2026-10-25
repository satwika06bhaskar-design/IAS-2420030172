import hashlib
import os
from typing import Dict, Any, List
from app.schemas.ipsec_schemas import IPPacketData, PacketFieldInspection
from app.services.crypto_service import CryptoService
from app.utils.encoding import to_hex

class IPsecService:
    # Key simulation for IPsec SA (Security Association)
    SIMULATED_SA_KEY = hashlib.sha256(b"SecureTunnel-Educational-IPsec-SA-Key-2026").digest()

    @classmethod
    def encapsulate(
        cls,
        mode: str,
        packet: IPPacketData,
        spi: int,
        seq_num: int,
        tunnel_gateway_src: str = "203.0.113.1",
        tunnel_gateway_dst: str = "198.51.100.1",
        cipher: str = "AES-256-GCM"
    ) -> Dict[str, Any]:
        """
        Perform IPsec Encapsulating Security Payload (ESP) simulation in Transport or Tunnel mode.
        """
        mode = mode.lower()
        if mode not in ("transport", "tunnel"):
            raise ValueError("IPsec mode must be 'transport' or 'tunnel'.")

        payload_bytes = packet.payload.encode('utf-8')
        orig_tcp_bytes = f"TCP:{packet.src_port}->{packet.dst_port}|Flags:ACK,PSH|Seq:{seq_num}".encode('utf-8')
        orig_ip_bytes = f"IPv4:{packet.src_ip}->{packet.dst_ip}|Proto:{packet.protocol}|TTL:64".encode('utf-8')

        # ESP Header (8 bytes): SPI (4 bytes) + Sequence Number (4 bytes)
        esp_header_bytes = spi.to_bytes(4, 'big') + seq_num.to_bytes(4, 'big')

        if mode == "transport":
            # In Transport mode:
            # Data to be encrypted = Upper layer (TCP/UDP header + Application payload) + ESP Trailer
            # ESP Trailer = Padding (to align to cipher block boundary) + Pad Length (1 byte) + Next Header (1 byte = 6 for TCP)
            raw_to_encrypt = orig_tcp_bytes + b"|" + payload_bytes
            # Padding to multiple of 16 bytes for realism
            pad_len = (16 - ((len(raw_to_encrypt) + 2) % 16)) % 16
            padding_bytes = bytes(range(1, pad_len + 1))
            esp_trailer_bytes = padding_bytes + bytes([pad_len, 6])  # 6 = TCP
            plaintext_body = raw_to_encrypt + esp_trailer_bytes

            # AEAD associated data = ESP Header (SPI + Seq)
            enc_result = CryptoService.aes_gcm_encrypt(cls.SIMULATED_SA_KEY, plaintext_body, associated_data=esp_header_bytes)
            ciphertext = enc_result["ciphertext"]
            icv_tag = enc_result["tag"]
            nonce = enc_result["nonce"]

            explanation = (
                "TRANSPORT MODE: ESP is inserted directly after the original IP header and before the transport "
                "layer (TCP). The original IP header remains in cleartext so intermediate routers can forward the packet. "
                "The TCP header, application payload, and ESP trailer are encrypted. The ESP header and encrypted payload "
                "are integrity-authenticated by the ESP ICV."
            )

            components = [
                {
                    "id": "orig_ip_hdr",
                    "name": "Original IPv4 Header",
                    "layer": "Network Layer (Layer 3)",
                    "encrypted": False,
                    "authenticated": False,
                    "details": f"Src: {packet.src_ip} -> Dst: {packet.dst_ip} (Protocol: 50 ESP)",
                    "size": 20,
                    "color": "amber"
                },
                {
                    "id": "esp_hdr",
                    "name": "ESP Header",
                    "layer": "Security Protocol (ESP)",
                    "encrypted": False,
                    "authenticated": True,
                    "details": f"SPI: 0x{spi:08X}, Seq: {seq_num}",
                    "size": 8,
                    "color": "cyan"
                },
                {
                    "id": "enc_payload",
                    "name": "Encrypted Payload (TCP + Data)",
                    "layer": "Encrypted Transport & Application",
                    "encrypted": True,
                    "authenticated": True,
                    "details": f"Ciphertext ({len(ciphertext)} bytes): {to_hex(ciphertext, shorten=True, max_len=16)}",
                    "size": len(ciphertext),
                    "color": "indigo"
                },
                {
                    "id": "esp_trailer",
                    "name": "ESP Trailer",
                    "layer": "ESP Padding & Next Header",
                    "encrypted": True,
                    "authenticated": True,
                    "details": f"Pad Length: {pad_len} bytes, Next Header: 6 (TCP)",
                    "size": 2 + pad_len,
                    "color": "purple"
                },
                {
                    "id": "esp_icv",
                    "name": "ESP ICV (Authentication Tag)",
                    "layer": "Integrity Check Value",
                    "encrypted": False,
                    "authenticated": True,
                    "details": f"ICV (16 bytes): {to_hex(icv_tag, shorten=True, max_len=16)}",
                    "size": 16,
                    "color": "emerald"
                }
            ]

        else:
            # TUNNEL MODE:
            # Entire original IP packet (Header + TCP + Payload) is encrypted as the inner packet!
            inner_packet_raw = orig_ip_bytes + b"|" + orig_tcp_bytes + b"|" + payload_bytes
            pad_len = (16 - ((len(inner_packet_raw) + 2) % 16)) % 16
            padding_bytes = bytes(range(1, pad_len + 1))
            esp_trailer_bytes = padding_bytes + bytes([pad_len, 4])  # 4 = IPv4 encapsulation
            plaintext_body = inner_packet_raw + esp_trailer_bytes

            enc_result = CryptoService.aes_gcm_encrypt(cls.SIMULATED_SA_KEY, plaintext_body, associated_data=esp_header_bytes)
            ciphertext = enc_result["ciphertext"]
            icv_tag = enc_result["tag"]
            nonce = enc_result["nonce"]

            explanation = (
                "TUNNEL MODE: The entire original IP packet (including its original IP header, TCP header, and payload) "
                "is encapsulated and encrypted as the inner packet. A brand new Outer IP Header is appended with gateway "
                "addresses (Gateway A -> Gateway B). External observers on the public internet see only gateway-to-gateway "
                "traffic; the true sender, recipient, and communication pattern remain completely concealed."
            )

            components = [
                {
                    "id": "outer_ip_hdr",
                    "name": "New Outer IPv4 Header",
                    "layer": "Tunnel Network Layer (Gateway to Gateway)",
                    "encrypted": False,
                    "authenticated": False,
                    "details": f"Tunnel Src: {tunnel_gateway_src} -> Tunnel Dst: {tunnel_gateway_dst} (Protocol: 50 ESP)",
                    "size": 20,
                    "color": "blue"
                },
                {
                    "id": "esp_hdr",
                    "name": "ESP Header",
                    "layer": "Security Protocol (ESP)",
                    "encrypted": False,
                    "authenticated": True,
                    "details": f"SPI: 0x{spi:08X}, Seq: {seq_num}",
                    "size": 8,
                    "color": "cyan"
                },
                {
                    "id": "enc_inner_packet",
                    "name": "Encrypted Inner Packet (Original IP + TCP + Data)",
                    "layer": "Encrypted Inner Tunnel Datagram",
                    "encrypted": True,
                    "authenticated": True,
                    "details": f"Encrypted Inner IPv4 ({packet.src_ip}->{packet.dst_ip}), TCP, & Payload ({len(ciphertext)} bytes)",
                    "size": len(ciphertext),
                    "color": "indigo"
                },
                {
                    "id": "esp_trailer",
                    "name": "ESP Trailer",
                    "layer": "ESP Padding & Next Header",
                    "encrypted": True,
                    "authenticated": True,
                    "details": f"Pad Length: {pad_len} bytes, Next Header: 4 (IPv4)",
                    "size": 2 + pad_len,
                    "color": "purple"
                },
                {
                    "id": "esp_icv",
                    "name": "ESP ICV (Authentication Tag)",
                    "layer": "Integrity Check Value",
                    "encrypted": False,
                    "authenticated": True,
                    "details": f"ICV (16 bytes): {to_hex(icv_tag, shorten=True, max_len=16)}",
                    "size": 16,
                    "color": "emerald"
                }
            ]

        original_packet_view = {
            "ip_header": {
                "version": 4,
                "ihl": 5,
                "src_ip": packet.src_ip,
                "dst_ip": packet.dst_ip,
                "protocol": packet.protocol,
                "ttl": 64,
                "size_bytes": 20
            },
            "tcp_header": {
                "src_port": packet.src_port,
                "dst_port": packet.dst_port,
                "seq": seq_num,
                "flags": "ACK, PSH",
                "size_bytes": 20
            },
            "payload": {
                "text": packet.payload,
                "size_bytes": len(payload_bytes)
            },
            "total_size_bytes": 20 + 20 + len(payload_bytes)
        }

        total_encap_size = sum(c["size"] for c in components)

        return {
            "mode": mode,
            "cipher": cipher,
            "original_packet": original_packet_view,
            "encapsulated_packet": {
                "total_size_bytes": total_encap_size,
                "components": components
            },
            "crypto_details": {
                "spi_hex": f"0x{spi:08X}",
                "seq_num": seq_num,
                "nonce_hex": to_hex(nonce),
                "icv_tag_hex": to_hex(icv_tag),
                "algorithm": cipher,
                "anti_replay_active": True
            },
            "explanation": explanation,
            "diagram_nodes": components
        }

    @classmethod
    def inspect_field(cls, field_id: str, mode: str = "tunnel") -> PacketFieldInspection:
        """Inspect specific packet field for educational understanding."""
        fields = {
            "orig_ip_hdr": PacketFieldInspection(
                field_id="orig_ip_hdr",
                name="Original IPv4 Header",
                layer="Internet Layer (Layer 3)",
                size_bytes=20,
                is_encrypted=False,
                is_authenticated=False,
                summary="Standard IPv4 header containing end-host source and destination IP addresses.",
                educational_note="In Transport mode, this header is visible in transit. Intermediate routers inspect it to deliver the packet. In Tunnel mode, it is encrypted within the ESP payload."
            ),
            "outer_ip_hdr": PacketFieldInspection(
                field_id="outer_ip_hdr",
                name="New Outer IPv4 Header",
                layer="Tunnel Internet Layer (Layer 3)",
                size_bytes=20,
                is_encrypted=False,
                is_authenticated=False,
                summary="Newly generated IP header that routes the encrypted packet between VPN gateways.",
                educational_note="Used exclusively in Tunnel Mode (e.g. Site-to-Site VPN). The source and destination IPs match the security gateways, shielding internal subnets from eavesdroppers."
            ),
            "esp_hdr": PacketFieldInspection(
                field_id="esp_hdr",
                name="ESP Header (SPI & Sequence Number)",
                layer="IPsec ESP Header",
                size_bytes=8,
                is_encrypted=False,
                is_authenticated=True,
                summary="Contains the Security Parameters Index (SPI, 32-bit) and Sequence Number (32-bit).",
                educational_note="The SPI allows the receiving peer to identify which Security Association (SA) keys to use for decryption. The Sequence Number prevents replay attacks."
            ),
            "enc_payload": PacketFieldInspection(
                field_id="enc_payload",
                name="Encrypted Transport & Payload",
                layer="Encrypted Layer 4+ Data",
                size_bytes=48,
                is_encrypted=True,
                is_authenticated=True,
                summary="The confidential portion of the packet in Transport Mode.",
                educational_note="Contains the original TCP or UDP header and application payload, encrypted with AES-GCM or AES-CBC. Network observers cannot view port numbers or data."
            ),
            "enc_inner_packet": PacketFieldInspection(
                field_id="enc_inner_packet",
                name="Encrypted Inner Packet",
                layer="Encrypted Layer 3 Datagram",
                size_bytes=88,
                is_encrypted=True,
                is_authenticated=True,
                summary="Entire original IP packet encrypted inside the ESP payload in Tunnel Mode.",
                educational_note="Protects internal IP addresses, transport protocol, ports, and payload. Only the VPN gateway at the far end can decrypt and route this inner packet."
            ),
            "esp_trailer": PacketFieldInspection(
                field_id="esp_trailer",
                name="ESP Trailer (Padding, Pad Length, Next Header)",
                layer="ESP Trailer",
                size_bytes=4,
                is_encrypted=True,
                is_authenticated=True,
                summary="Aligns ciphertext to cipher block size and specifies the encapsulated protocol.",
                educational_note="The 'Next Header' field indicates what protocol follows inside the decrypted payload (e.g., 6 for TCP in Transport mode, or 4 for IPv4 in Tunnel mode)."
            ),
            "esp_icv": PacketFieldInspection(
                field_id="esp_icv",
                name="ESP ICV (Integrity Check Value)",
                layer="ESP Authentication",
                size_bytes=16,
                is_encrypted=False,
                is_authenticated=True,
                summary="Cryptographic authentication tag computed over the ESP header, payload, and trailer.",
                educational_note="Verifies that no attacker has altered the ciphertext or ESP header in transit. Generated using GMAC in AES-GCM or HMAC-SHA256."
            )
        }

        if field_id in fields:
            return fields[field_id]

        return PacketFieldInspection(
            field_id=field_id,
            name="General Packet Component",
            layer="Protocol Layer",
            size_bytes=0,
            is_encrypted=False,
            is_authenticated=False,
            summary="Standard protocol field.",
            educational_note="Field component of the simulated security datagram."
        )

ipsec_service = IPsecService()
