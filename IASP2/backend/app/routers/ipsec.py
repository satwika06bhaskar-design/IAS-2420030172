from fastapi import APIRouter, HTTPException
from typing import Dict, Any
from app.schemas.ipsec_schemas import IPsecEncapsulateRequest, IPsecInspectRequest, IPsecEncapsulateResponse, PacketFieldInspection
from app.services.ipsec_service import ipsec_service

router = APIRouter(prefix="/api/ipsec", tags=["IPsec ESP"])

@router.post("/encapsulate")
def encapsulate_packet(req: IPsecEncapsulateRequest) -> Dict[str, Any]:
    """Demonstrate IPsec ESP packet encapsulation in Transport or Tunnel mode."""
    try:
        result = ipsec_service.encapsulate(
            mode=req.mode,
            packet=req.packet,
            spi=req.spi,
            seq_num=req.seq_num,
            tunnel_gateway_src=req.tunnel_gateway_src or "203.0.113.1",
            tunnel_gateway_dst=req.tunnel_gateway_dst or "198.51.100.1",
            cipher=req.cipher or "AES-256-GCM"
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Encapsulation failed: {str(e)}")

@router.post("/inspect", response_model=PacketFieldInspection)
def inspect_packet_field(req: IPsecInspectRequest) -> PacketFieldInspection:
    """Inspect field structure, encryption state, and educational significance."""
    return ipsec_service.inspect_field(field_id=req.field_id, mode=req.mode)
