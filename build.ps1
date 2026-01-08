<#
  build.ps1 - Configure, build and run tests for the project using CMake and CTest

  Usage examples:
    .\build.ps1                          # Debug, Visual Studio 17 2022, x64
    .\build.ps1 -Configuration Release   # Release build
    .\build.ps1 -Generator "Ninja" -Platform ""  # Use Ninja generator
#>

param(
    [string]$Configuration = 'Debug',
    [string]$Generator = 'Visual Studio 17 2022',
    [string]$Platform = 'x64'
)

$ErrorActionPreference = 'Stop'

function Find-Executable {
    param(
        [string]$CmdName,
        [string[]]$Candidates
    )
    $cmd = Get-Command $CmdName -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($p in $Candidates) {
        if (Test-Path $p) { return $p }
    }
    return $null
}

$cmakeExe = Find-Executable -CmdName 'cmake' -Candidates @(
    'C:\Program Files\CMake\bin\cmake.exe',
    'C:\Program Files (x86)\CMake\bin\cmake.exe'
)
$ctestExe = Find-Executable -CmdName 'ctest' -Candidates @(
    'C:\Program Files\CMake\bin\ctest.exe',
    'C:\Program Files (x86)\CMake\bin\ctest.exe'
)

if (-not $cmakeExe) {
    Write-Error "cmake not found. Please install CMake (https://cmake.org/download/) or ensure it's on PATH."
    exit 2
}
if (-not $ctestExe) {
    Write-Error "ctest not found. Please ensure CTest (comes with CMake) is available."
    exit 3
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$buildDir = Join-Path $scriptDir 'build'

Write-Host "Using CMake: $cmakeExe"
Write-Host "Using CTest: $ctestExe"
Write-Host "Generator: $Generator    Platform: $Platform    Configuration: $Configuration"

if (-not (Test-Path $buildDir)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

Push-Location $buildDir
try {
    Write-Host "Configuring with CMake..."
    if ($Platform -ne "") {
        & "$cmakeExe" -G "$Generator" -A $Platform ..
    } else {
        & "$cmakeExe" -G "$Generator" ..
    }
    if ($LASTEXITCODE -ne 0) { throw "CMake configure failed (exit code $LASTEXITCODE)" }

    Write-Host "Building..."
    & "$cmakeExe" --build . --config $Configuration
    if ($LASTEXITCODE -ne 0) { throw "Build failed (exit code $LASTEXITCODE)" }

    Write-Host "Running tests (ctest)..."
    $ctestOutput = & "$ctestExe" -C $Configuration --output-on-failure 2>&1
    $testExit = $LASTEXITCODE

    # Echo raw ctest output first
    Write-Host $ctestOutput

    # Parse per-test lines like: "1/9 Test #1: ChrupcioTests ....................   Passed    0.05 sec"
    $pattern = '^\s*(\d+)/(\d+)\s+Test\s+#(?<num>\d+):\s*(?<name>.+?)\s+\.{2,}\s+(?<result>Passed|Failed|Timeout|Not Run|Skipped)\s+(?<time>\d+\.\d+)\s+sec'
    $testLines = $ctestOutput -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^\s*\d+/\d+\s+Test' }
    $results = @()
    foreach ($line in $testLines) {
        $m = [regex]::Match($line, $pattern)
        if ($m.Success) {
            $num = [int]$m.Groups['num'].Value
            $name = $m.Groups['name'].Value.Trim()
            $status = $m.Groups['result'].Value
            $time = ("{0:0.00}s" -f [double]$m.Groups['time'].Value)
            $results += [PSCustomObject]@{ Num = $num; Name = $name; Result = $status; Time = $time }
        } else {
            # Fallback: attempt to parse name/status only
            if ($line -match '^\s*\d+/\d+\s+Test\s+#\d+:\s*(.+?)\s+\.{2,}\s+(Passed|Failed|Timeout|Not Run|Skipped)\b') {
                $name = $matches[1].Trim()
                $status = $matches[2]
                $results += [PSCustomObject]@{ Num = $null; Name = $name; Result = $status; Time = '' }
            }
        }
    }

    if ($results.Count -gt 0) {
        Write-Host "`nTest results summary:"
        # Sort by numeric test id when available, otherwise put it at the end; then group by failures first
        $results = $results | Sort-Object -Property (@{Expression = { if ($_.Num) { $_.Num } else { 9999 } }}, @{Expression = { if ($_.Result -eq 'Failed') {0} elseif ($_.Result -eq 'Timeout') {1} elseif ($_.Result -eq 'Not Run') {2} elseif ($_.Result -eq 'Skipped') {3} else {4} } })
        $results | Format-Table @{Label='#';Expression={$_.Num}}, @{Label='Test Name';Expression={$_.Name}}, @{Label='Result';Expression={$_.Result}}, @{Label='Time';Expression={$_.Time}} -AutoSize
        $failed = ($results | Where-Object { $_.Result -ne 'Passed' }).Count
        if ($failed -eq 0) { $color = 'Green' } else { $color = 'Red' }
        Write-Host "`nSummary: $($results.Count) tests, $failed failed" -ForegroundColor $color
    } else {
        Write-Host "`nNo per-test lines found to summarize; raw ctest output above." -ForegroundColor Yellow
    }

    if ($testExit -ne 0) { exit $testExit }

    Write-Host "All steps completed successfully." -ForegroundColor Green
} finally {
    Pop-Location
}
