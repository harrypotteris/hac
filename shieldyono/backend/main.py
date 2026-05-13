"""
ShieldYONO — AI-Powered Multi-Layer Defence Backend
FastAPI application entry point
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from routers import apk_scanner, link_scanner
from database import init_db

app = FastAPI(
    title="ShieldYONO API",
    description="AI-Powered Multi-Layer Defence for SBI YONO Platform",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(
    apk_scanner.router,
    prefix="/api/apk",
    tags=["APK Scanner"]
)

app.include_router(
    link_scanner.router,
    prefix="/api/link",
    tags=["Link Scanner"]
)

@app.on_event("startup")
async def startup_event():
    init_db()
    print("✅ ShieldYONO API started")

@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "ShieldYONO API"
    }

@app.get("/api/health")
async def health():
    return {
        "status": "healthy"
    }

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )