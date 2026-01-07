<#
  clean.ps1 - Remove the CMake build directory and its contents

  Usage:
    .\clean.ps1
#>

$ErrorActionPreference = 'Stop'

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $scriptDir 'build'

if (Test-Path $buildDir) {
    Write-Host "Removing build directory: $buildDir"
    try {
        Remove-Item -LiteralPath $buildDir -Recurse -Force -ErrorAction Stop
        Write-Host "Cleanup complete." -ForegroundColor Green
    } catch {
        Write-Error "Failed to remove build directory: $_"
        exit 1
    }
} else {
    Write-Host "Nothing to clean; build directory not found." -ForegroundColor Yellow
}

# Also allow removing CTest temporary files if any
$ctestFiles = @('Testing', 'CTestTestfile.cmake')
foreach ($f in $ctestFiles) {
    $path = Join-Path $scriptDir $f
    if (Test-Path $path) {
        Write-Host "Removing: $path"
        Remove-Item -LiteralPath $path -Recurse -Force -ErrorAction SilentlyContinue
    }
}
