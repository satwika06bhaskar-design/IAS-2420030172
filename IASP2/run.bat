@echo off
echo ========================================================
echo Starting SecureTunnel (Backend + Frontend)
echo ========================================================

echo Starting FastAPI Backend on port 8000...
start "SecureTunnel Backend" cmd /k "cd /d %~dp0backend && venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

timeout /t 2 /nobreak >nul

echo Starting Vite Frontend on port 5173...
start "SecureTunnel Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo ========================================================
echo SecureTunnel is running!
echo - Web Dashboard: http://localhost:5173
echo - Backend API:   http://127.0.0.1:8000
echo - Swagger Docs:  http://127.0.0.1:8000/docs
echo ========================================================
pause
