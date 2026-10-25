import contextlib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.database import engine, Base, SessionLocal
from app.services.seed_data import seed_demo_data

from app.routers import (
    firewall,
    bastion,
    traffic,
    ids,
    anomaly,
    educational,
    demo
)

@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Create DB tables
    Base.metadata.create_all(bind=engine)
    # Seed default data on start if empty
    db = SessionLocal()
    try:
        seed_demo_data(db, force_reset=False)
    finally:
        db.close()
    yield

app = FastAPI(
    title="Sentinel — Intrusion Detection & Firewall Simulator API",
    description="Educational Cybersecurity Web Application Backend for Packet-Filtering, Rule-Based IDS, and Statistical Anomaly Detection.",
    version="1.0.0",
    lifespan=lifespan
)

# CORS configuration for Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(firewall.router)
app.include_router(bastion.router)
app.include_router(traffic.router)
app.include_router(ids.router)
app.include_router(anomaly.router)
app.include_router(educational.router)
app.include_router(demo.router)

@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "system": "Sentinel Cybersecurity Simulator",
        "version": "1.0.0"
    }

@app.get("/")
def root():
    return {
        "message": "Welcome to Sentinel — Intrusion Detection & Firewall Simulator API",
        "documentation": "/docs",
        "health": "/api/health"
    }
