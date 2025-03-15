# Run Trafnalyzer with administrator privileges
Write-Host "Starting Trafnalyzer with administrator privileges..." -ForegroundColor Green

# Get the current script path
$scriptPath = Split-Path -Parent -Path $MyInvocation.MyCommand.Definition
$appPath = Join-Path -Path $scriptPath -ChildPath "trafnalyzer.py"

# Start a new PowerShell process with admin privileges
Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"& {python '$appPath'}`"" -Verb RunAs

Write-Host "Trafnalyzer started." -ForegroundColor Green 