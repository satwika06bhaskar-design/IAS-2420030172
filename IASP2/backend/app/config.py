import os
from pydantic import BaseModel

class Settings(BaseModel):
    APP_NAME: str = "SecureTunnel API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    SESSION_TTL_SECONDS: int = 3600  # 1 hour session expiration

settings = Settings()
