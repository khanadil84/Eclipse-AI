$ErrorActionPreference = "Stop"
$BaseUrl = "http://127.0.0.1:8000"
$Suffix = [guid]::NewGuid().ToString("N").Substring(0, 8).ToUpper()
$IncidentId = "INC-DEMO-$Suffix"
$EventId = "EVT-DEMO-$Suffix"
$HostName = "sandbox-demo-$Suffix"

Write-Host "`n=== Eclipse AI end-to-end demo ===" -ForegroundColor Cyan
Write-Host "Incident: $IncidentId"
Write-Host "Checking API health..."
$health = Invoke-RestMethod -Method Get -Uri "$BaseUrl/health"
$health | ConvertTo-Json -Depth 8

Write-Host "`n1) Ingest simulated telemetry..." -ForegroundColor Cyan
$event = @{
    event_id = $EventId
    incident_id = $IncidentId
    event_type = "suspicious_process"
    severity = "high"
    confidence = 0.97
    source = "eclipse-demo"
    host_name = $HostName
    environment = "sandbox"
} | ConvertTo-Json
$ingest = Invoke-RestMethod -Method Post -Uri "$BaseUrl/telemetry/ingest" -ContentType "application/json" -Body $event
$ingest | ConvertTo-Json -Depth 8

Write-Host "`n2) Inspect incident..." -ForegroundColor Cyan
$triageBody = @{ incident_id = $IncidentId } | ConvertTo-Json
$triage = Invoke-RestMethod -Method Post -Uri "$BaseUrl/triage" -ContentType "application/json" -Body $triageBody
$triage | ConvertTo-Json -Depth 8

Write-Host "`n3) Run normal autonomous simulation..." -ForegroundColor Cyan
$normalBody = @{
    incident_id = $IncidentId
    max_steps = 6
    simulate_verification_failure = $false
} | ConvertTo-Json
$normal = Invoke-RestMethod -Method Post -Uri "$BaseUrl/agent/run" -ContentType "application/json" -Body $normalBody
$normal | ConvertTo-Json -Depth 12

Write-Host "`n4) Demonstrate verification failure, rollback, and re-verification..." -ForegroundColor Cyan
$recoveryBody = @{
    incident_id = $IncidentId
    max_steps = 8
    simulate_verification_failure = $true
} | ConvertTo-Json
$recovery = Invoke-RestMethod -Method Post -Uri "$BaseUrl/agent/run" -ContentType "application/json" -Body $recoveryBody
$recovery | ConvertTo-Json -Depth 12

Write-Host "`n5) Read recent persisted runs for this incident..." -ForegroundColor Cyan
try {
    $runs = Invoke-RestMethod -Method Get -Uri "$BaseUrl/agent/runs?incident_id=$IncidentId&limit=5"
    $runs | ConvertTo-Json -Depth 12
} catch {
    Write-Warning "Run history could not be retrieved. Check FalkorDB connection and graph state."
    throw
}

Write-Host "`nDemo complete. Confirm the run-history response and real_host_changed=false fields." -ForegroundColor Green
