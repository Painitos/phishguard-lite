param(
    [string]$HostName = "127.0.0.1",
    [int]$Port = 8080,
    [string]$PythonPath = "py"
)

$projectRoot = Split-Path -Parent $PSScriptRoot
$env:PYTHONPATH = Join-Path $projectRoot "src"

Set-Location $projectRoot
& $PythonPath scripts\start_server.py serve --host $HostName --port $Port