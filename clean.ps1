
# clean.ps1 - Remove Go build artifacts
# Usage: .\clean.ps1

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Support new folder structure: look for Chrupcio.exe in project root and src/
$exePaths = @()
$exePaths += Join-Path $scriptDir 'Chrupcio.exe'
$exePaths += Join-Path $scriptDir 'src\Chrupcio.exe'

foreach ($exePath in $exePaths) {
    if (Test-Path $exePath) {
        Write-Host "Removing executable: $exePath"
        try {
            Remove-Item -LiteralPath $exePath -Force -ErrorAction Stop
            Write-Host "Cleanup complete." -ForegroundColor Green
        } catch {
            Write-Error "Failed to remove executable: $_"
            exit 1
        }
    } else {
        Write-Host "Nothing to clean; executable not found at $exePath." -ForegroundColor Yellow
    }
}

if (Test-Path $exePath) {
    Write-Host "Removing executable: $exePath"
    try {
        Remove-Item -LiteralPath $exePath -Force -ErrorAction Stop
        Write-Host "Cleanup complete." -ForegroundColor Green
    } catch {
        Write-Error "Failed to remove executable: $_"
        exit 1
    }
} else {
    Write-Host "Nothing to clean; executable not found." -ForegroundColor Yellow
}
