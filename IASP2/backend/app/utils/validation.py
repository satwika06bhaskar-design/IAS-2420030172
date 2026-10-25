import re

def sanitize_input_text(text: str, max_length: int = 1000) -> str:
    """Sanitize and limit user text input."""
    if not text:
        return ""
    # Strip potential control characters except normal whitespace
    cleaned = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', text)
    return cleaned[:max_length]

def validate_session_id(session_id: str) -> bool:
    """Ensure session_id conforms to UUID / safe alphanumeric format."""
    return bool(re.match(r'^[a-zA-Z0-9\-_]{8,64}$', session_id))
