import ipaddress
from typing import List, Tuple, Optional, Dict, Any
from app.models.firewall_rule import FirewallRule

def ip_in_network(ip_str: str, net_spec: Optional[str]) -> bool:
    """
    Checks if an IP matches a specification:
    - None, '', 'ANY', '*' -> True
    - Exact IP -> ip_str == net_spec
    - CIDR notation (e.g., '192.168.1.0/24') -> ip in network
    """
    if not net_spec or net_spec.strip().upper() in ["ANY", "*"]:
        return True
    
    spec = net_spec.strip()
    try:
        packet_ip = ipaddress.ip_address(ip_str.strip())
        if "/" in spec:
            net = ipaddress.ip_network(spec, strict=False)
            return packet_ip in net
        else:
            rule_ip = ipaddress.ip_address(spec)
            return packet_ip == rule_ip
    except ValueError:
        return False

def port_matches(packet_port: Optional[int], rule_port_spec: Optional[str]) -> bool:
    """
    Checks if destination port matches rule:
    - None, '', 'ANY', '*' -> True
    - Single port (e.g., '80') -> packet_port == 80
    - Port range (e.g., '80-443') -> 80 <= packet_port <= 443
    """
    if not rule_port_spec or str(rule_port_spec).strip().upper() in ["ANY", "*"]:
        return True
    
    if packet_port is None:
        return False
        
    spec = str(rule_port_spec).strip()
    if "-" in spec:
        try:
            parts = spec.split("-")
            low, high = int(parts[0]), int(parts[1])
            return low <= packet_port <= high
        except ValueError:
            return False
    else:
        try:
            p = int(spec)
            return packet_port == p
        except ValueError:
            return False

def protocol_matches(packet_proto: str, rule_proto: Optional[str]) -> bool:
    if not rule_proto or rule_proto.strip().upper() in ["ANY", "*"]:
        return True
    return packet_proto.strip().upper() == rule_proto.strip().upper()

def evaluate_packet(
    rules: List[FirewallRule],
    source_ip: str,
    destination_ip: str,
    protocol: str,
    destination_port: Optional[int] = None,
    default_policy: str = "BLOCK"
) -> Tuple[str, Optional[int], Optional[str], str]:
    """
    Evaluates enabled firewall rules in ascending priority order (first-match policy).
    Returns (decision, matched_rule_id, matched_rule_name, reason).
    """
    # Sort rules ascending by priority
    sorted_rules = sorted(rules, key=lambda r: r.priority)

    for rule in sorted_rules:
        if not rule.is_enabled:
            continue

        # Check conditions
        if not ip_in_network(source_ip, rule.source_ip):
            continue
        if not ip_in_network(destination_ip, rule.destination_ip):
            continue
        if not protocol_matches(protocol, rule.protocol):
            continue
        if not port_matches(destination_port, rule.destination_port):
            continue

        # First match found!
        decision = rule.action.upper()
        reason = (
            f"Rule #{rule.id} ('{rule.name}', Priority {rule.priority}) matched: "
            f"Action is {decision}."
        )
        return decision, rule.id, rule.name, reason

    # Fallback to default policy
    def_decision = default_policy.upper()
    reason = (
        f"No enabled rule matched packet. Default firewall policy applied: {def_decision}."
    )
    return def_decision, None, None, reason

def evaluate_packet_detailed(
    rules: List[FirewallRule],
    source_ip: str,
    destination_ip: str,
    protocol: str,
    destination_port: Optional[int] = None,
    default_policy: str = "BLOCK"
) -> Dict[str, Any]:
    """
    Detailed evaluation recording steps for UI animation and educational packet inspector.
    """
    sorted_rules = sorted(rules, key=lambda r: r.priority)
    steps = []
    matched_rule = None
    decision = default_policy.upper()
    final_reason = f"No rule matched. Default policy is {decision}."

    for rule in sorted_rules:
        if not rule.is_enabled:
            steps.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "priority": rule.priority,
                "is_enabled": False,
                "matched": False,
                "reason": "Rule is disabled, skipped."
            })
            continue

        src_ok = ip_in_network(source_ip, rule.source_ip)
        dst_ok = ip_in_network(destination_ip, rule.destination_ip)
        proto_ok = protocol_matches(protocol, rule.protocol)
        port_ok = port_matches(destination_port, rule.destination_port)

        matched = src_ok and dst_ok and proto_ok and port_ok

        if matched:
            steps.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "priority": rule.priority,
                "is_enabled": True,
                "matched": True,
                "reason": f"Matched criteria (Src: {rule.source_ip}, Dst: {rule.destination_ip}, Proto: {rule.protocol}, Port: {rule.destination_port}). Action: {rule.action}"
            })
            matched_rule = rule
            decision = rule.action.upper()
            final_reason = f"Rule #{rule.id} ('{rule.name}', Priority {rule.priority}) matched packet. Action: {decision}."
            break
        else:
            mismatches = []
            if not src_ok:
                mismatches.append(f"Source IP {source_ip} != {rule.source_ip}")
            if not dst_ok:
                mismatches.append(f"Destination IP {destination_ip} != {rule.destination_ip}")
            if not proto_ok:
                mismatches.append(f"Protocol {protocol} != {rule.protocol}")
            if not port_ok:
                mismatches.append(f"Port {destination_port} != {rule.destination_port}")
            steps.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "priority": rule.priority,
                "is_enabled": True,
                "matched": False,
                "reason": f"No match: {', '.join(mismatches)}"
            })

    return {
        "decision": decision,
        "matched_rule_id": matched_rule.id if matched_rule else None,
        "matched_rule_name": matched_rule.name if matched_rule else None,
        "reason": final_reason,
        "steps": steps
    }
