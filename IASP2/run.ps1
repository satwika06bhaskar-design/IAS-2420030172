# SecureTunnel Unified PowerShell Runner
Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Starting SecureTunnel Backend and Frontend..." -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

$root = $PSScriptRoot

# Start Backend in new window
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\backend'; .\venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

Start-Sleep -Seconds 2

# Start Frontend in new window
Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$root\frontend'; npm run dev"

Write-Host ""
Write-Host "Both servers launched successfully!" -ForegroundColor Green
Write-Host " - Frontend Dashboard : http://localhost:5173" -ForegroundColor Cyan
Write-Host " - Backend API Docs   : http://127.0.0.1:8000/docs" -ForegroundColor Cyan
