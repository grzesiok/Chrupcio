
# build.ps1 - Build Go project (cross-platform)
# Usage: .\build.ps1

$ErrorActionPreference = 'Stop'

Write-Host "Building Go project..."

$goExe = Get-Command go -ErrorAction SilentlyContinue
if (-not $goExe) {
    Write-Error "Go not found. Please install Go (https://go.dev/dl/) and ensure it's on PATH."
    exit 2
}

# Lint with golangci-lint (must be installed)
$lintExe = Get-Command golangci-lint -ErrorAction SilentlyContinue
if (-not $lintExe) {
    Write-Error "golangci-lint not found. Please install it from https://golangci-lint.run/ and ensure it's on PATH."
    exit 3
}

Write-Host "Running golangci-lint..."
& $lintExe.Source run ./src
if ($LASTEXITCODE -ne 0) {
    Write-Error "Lint errors found. Fix them before building."
    exit $LASTEXITCODE
}

# Build for Windows (default)
& $goExe.Source build -o Chrupcio.exe src/main.go
if ($LASTEXITCODE -ne 0) {
    Write-Error "Go build failed (exit code $LASTEXITCODE)"
    exit $LASTEXITCODE
}

Write-Host "Build completed: Chrupcio.exe" -ForegroundColor Green
