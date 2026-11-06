$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
if (-not (Get-Command py -ErrorAction SilentlyContinue)) { throw 'Install Python 3.11+ and ensure the py launcher is on PATH.' }
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { throw 'Install Node.js 20+ and ensure node is on PATH.' }
py -3 -m venv backend\.venv
& backend\.venv\Scripts\python.exe -m pip install --upgrade pip
& backend\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
Push-Location frontend
npm install
Pop-Location
Write-Host 'Setup complete. Start backend and frontend in two terminals; see README.md.'
