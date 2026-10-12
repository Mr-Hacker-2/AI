import logging
import os
import uvicorn
from fastapi import FastAPI, Header, HTTPException
import secrets
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from config import PORT, CAPTURES_DIR, setup_logging
from camera_stream import router as camera_router, set_person_detection_callback, trigger_person_alert
from chat_ai import router as chat_router, ai as ai_state
from weather import router as weather_router
from maps import router as maps_router
from devai import router as devai_router
from games import router as games_router
from security import router as security_router
from terminal import router as terminal_router
from file_manager import router as file_manager_router
from banking import router as banking_router
from unified_security import trigger_voice_alert, send_alarm_to_surveillance

setup_logging()
logger = logging.getLogger(__name__)

app = FastAPI(title="Viora AI Unified Backend")

# Enable CORS for the frontend
# Never combine credentialed browser requests with a wildcard origin.
CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173"
    ).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

def require_admin_token(authorization: str | None) -> None:
    """Fail closed for endpoints that can trigger privileged local actions."""
    expected = os.environ.get("ADMIN_API_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="Admin actions are disabled until ADMIN_API_TOKEN is configured.")
    if not authorization or not secrets.compare_digest(authorization, f"Bearer {expected}"):
        raise HTTPException(status_code=401, detail="Unauthorized")

# Static files for gallery
os.makedirs(CAPTURES_DIR, exist_ok=True)
app.mount("/captures", StaticFiles(directory=CAPTURES_DIR), name="captures")

# Include the routers
app.include_router(camera_router)
app.include_router(chat_router)
app.include_router(weather_router)
app.include_router(maps_router)
app.include_router(devai_router)
app.include_router(games_router)
app.include_router(security_router)
app.include_router(terminal_router)
app.include_router(file_manager_router)
app.include_router(banking_router)

@app.get("/health")
async def health():
    """Simple health check for monitoring and tests."""
    return {"status": "ok"}

@app.post("/security/motion_detected")
async def security_motion_detected(request: dict, authorization: str | None = Header(default=None)):
    require_admin_token(authorization)
    """Endpoint to receive motion detection from security camera."""
    import threading
    threading.Thread(target=trigger_voice_alert, daemon=True).start()
    return {"status": "notified"}

@app.post("/security/trigger_alarm")
async def security_trigger_alarm(authorization: str | None = Header(default=None)):
    require_admin_token(authorization)
    """Endpoint to trigger the alarm."""
    success = send_alarm_to_surveillance()
    return {"status": "success" if success else "error"}

@app.post("/security/stop_alarm")
async def security_stop_alarm(authorization: str | None = Header(default=None)):
    require_admin_token(authorization)
    """Endpoint to stop the alarm."""
    from unified_security import stop_alarm_on_surveillance
    success = stop_alarm_on_surveillance()
    return {"status": "success" if success else "error"}

@app.on_event("startup")
async def startup_event():
    logger.info("Unified Backend starting up...")
    
    # Register person detection callback
    from unified_security import trigger_voice_alert
    set_person_detection_callback(trigger_voice_alert)
    logger.info("Person detection callback registered")
    
    if not os.environ.get("SKIP_MODEL_LOAD"):
        ai_state.load_model()
        # Dev AI model loads on first request (lazy)
    try:
        from task_scheduler import init_scheduler
        init_scheduler(ai_state.conv_manager)
    except Exception as e:
        logger.warning("Task scheduler not started: %s", e)
    logger.info("Unified Backend ready.")

@app.post("/shutdown")
async def shutdown(authorization: str | None = Header(default=None)):
    require_admin_token(authorization)
    import threading
    import time
    def delayed_exit():
        time.sleep(1)
        os._exit(0)
    threading.Thread(target=delayed_exit, daemon=True).start()
    return {"status": "shutting down..."}

@app.post("/start_surveillance")
async def start_surveillance(authorization: str | None = Header(default=None)):
    require_admin_token(authorization)
    import subprocess
    import threading
    
    def run_surveillance():
        try:
            subprocess.Popen(
                ["/home/admin/Mr-A-Hacker-pocket-Ai-version-2/venv/bin/python", "/home/admin/Mr-A-Hacker-pocket-Ai-version-2/lan_surveillance.py"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                cwd="/home/admin/Mr-A-Hacker-pocket-Ai-version-2"
            )
        except Exception as e:
            print(f"Failed to start surveillance: {e}")
    
    threading.Thread(target=run_surveillance, daemon=True).start()
    return {"status": "starting", "message": "Surveillance server starting on port 5001"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=PORT)
