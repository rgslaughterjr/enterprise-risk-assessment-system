$instance = "https://dev271799.service-now.com"
$username = "admin"
$password = "fNm=In-TA55m"

$base64Auth = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${username}:${password}"))
$headers = @{
    Authorization = "Basic $base64Auth"
    Accept = "application/json"
}

Write-Host "Testing ServiceNow API Connection..." -ForegroundColor Cyan
Write-Host "Instance: $instance" -ForegroundColor Yellow
Write-Host ""

try {
    # Test 1: Get incidents
    Write-Host "Test 1: Fetching incidents..." -ForegroundColor Cyan
    $incidentResponse = Invoke-RestMethod -Uri "$instance/api/now/table/incident?sysparm_limit=5" -Headers $headers -Method Get
    Write-Host "✅ SUCCESS: Retrieved $($incidentResponse.result.Count) incidents" -ForegroundColor Green
    
    # Show sample incident
    if ($incidentResponse.result.Count -gt 0) {
        $sample = $incidentResponse.result[0]
        Write-Host "`nSample Incident:" -ForegroundColor Yellow
        Write-Host "  Number: $($sample.number)" -ForegroundColor White
        Write-Host "  Priority: $($sample.priority)" -ForegroundColor White
        Write-Host "  State: $($sample.state)" -ForegroundColor White
        Write-Host "  Short Description: $($sample.short_description)" -ForegroundColor White
    }
    
    Write-Host ""
    
    # Test 2: Get CMDB assets
    Write-Host "Test 2: Fetching CMDB assets..." -ForegroundColor Cyan
    $assetResponse = Invoke-RestMethod -Uri "$instance/api/now/table/cmdb_ci?sysparm_limit=5" -Headers $headers -Method Get
    Write-Host "✅ SUCCESS: Retrieved $($assetResponse.result.Count) assets" -ForegroundColor Green
    
    if ($assetResponse.result.Count -gt 0) {
        $sample = $assetResponse.result[0]
        Write-Host "`nSample Asset:" -ForegroundColor Yellow
        Write-Host "  Name: $($sample.name)" -ForegroundColor White
        Write-Host "  Class: $($sample.sys_class_name)" -ForegroundColor White
    }
    
    Write-Host ""
    Write-Host "=" * 60 -ForegroundColor Green
    Write-Host "🎉 ALL TESTS PASSED! ServiceNow API is working correctly!" -ForegroundColor Green
    Write-Host "=" * 60 -ForegroundColor Green
    
} catch {
    Write-Host "❌ ERROR: Failed to connect to ServiceNow" -ForegroundColor Red
    Write-Host "Error Message: $($_.Exception.Message)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Response:" -ForegroundColor Yellow
    Write-Host $_.ErrorDetails.Message -ForegroundColor Red
}
