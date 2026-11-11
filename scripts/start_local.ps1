param(
    [int]$PortalPort = 8000,
    [int]$AuthPort = 8001,
    [int]$RegPort = 8002,
    [int]$AccredPort = 8003,
    [int]$AuditPort = 8004
)

$Root = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"

$env:AUTH_SERVICE_URL = "http://127.0.0.1:$AuthPort"
$env:REGISTRATION_SERVICE_URL = "http://127.0.0.1:$RegPort"
$env:ACCREDITATION_SERVICE_URL = "http://127.0.0.1:$AccredPort"
$env:AUDIT_SERVICE_URL = "http://127.0.0.1:$AuditPort"

Write-Host "Iniciando EventPass SaaS..."
Write-Host "  Portal Web    : http://127.0.0.1:$PortalPort"
Write-Host "  Auth          : http://127.0.0.1:$AuthPort/docs"
Write-Host "  Registration  : http://127.0.0.1:$RegPort/docs"
Write-Host "  Accreditation : http://127.0.0.1:$AccredPort/docs"
Write-Host "  Audit         : http://127.0.0.1:$AuditPort/docs"

Start-Process $Python -ArgumentList "-m uvicorn services.auth_service.app:create_auth_app --factory --host 127.0.0.1 --port $AuthPort" -WorkingDirectory $Root
Start-Process $Python -ArgumentList "-m uvicorn services.audit_service.app:create_audit_app --factory --host 127.0.0.1 --port $AuditPort" -WorkingDirectory $Root
Start-Process $Python -ArgumentList "-m uvicorn services.accreditation_service.app:create_accreditation_app --factory --host 127.0.0.1 --port $AccredPort" -WorkingDirectory $Root
Start-Process $Python -ArgumentList "-m uvicorn services.registration_service.app:create_registration_app --factory --host 127.0.0.1 --port $RegPort" -WorkingDirectory $Root
& $Python -m uvicorn services.web_portal.app:create_portal_app --factory --host 127.0.0.1 --port $PortalPort
