import time
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.config import settings
from app.routers import tls, ssh, ipsec, learning

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="SecureTunnel: Interactive TLS, SSH, and IPsec Educational Protocol Simulator API",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS Configuration for local frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include Routers
app.include_router(tls.router)
app.include_router(ssh.router)
app.include_router(ipsec.router)
app.include_router(learning.router)

@app.get("/api/health", tags=["General"])
def health_check():
    """Health status endpoint."""
    return {
        "status": "healthy",
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "timestamp": time.time(),
        "disclaimer": "Educational simulation only. Not for production cryptographic security."
    }

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    """Safe exception handler preventing internal stack trace leaks."""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error occurred during cryptographic simulation.",
            "detail": str(exc) if settings.DEBUG else "Please check request parameters."
        }
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="127.0.0.1", port=8000, reload=True)
