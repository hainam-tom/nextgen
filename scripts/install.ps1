#!/usr/bin/env pwsh
$ErrorActionPreference = 'Stop'

function Read-YesNo($Prompt, $Default = 'Y') {
    while ($true) {
        $response = Read-Host "$Prompt";
        if ([string]::IsNullOrWhiteSpace($response)) { $response = $Default }
        switch ($response.ToUpperInvariant()) {
            'Y' { return $true }
            'YES' { return $true }
            'N' { return $false }
            'NO' { return $false }
            default { Write-Host 'Please enter Y or N.' }
        }
    }
}

function Test-PortFree($Port) {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $Port)
    try {
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        if ($listener) { $listener.Stop() }
    }
}

function Prompt-Port($DefaultPort) {
    while ($true) {
        $input = Read-Host "Select API port [$DefaultPort]"
        if ([string]::IsNullOrWhiteSpace($input)) { $input = $DefaultPort }
        if (-not [int]::TryParse($input, [ref]$null)) {
            Write-Host 'Port must be a number.'
            continue
        }
        $port = [int]$input
        if ($port -lt 1 -or $port -gt 65535) {
            Write-Host 'Port must be between 1 and 65535.'
            continue
        }
        if (-not (Test-PortFree $port)) {
            Write-Host "Port $port appears to be in use. Choose another."
            continue
        }
        return $port
    }
}

function Check-PortForward($Port) {
    try {
        $resp = Invoke-WebRequest -Uri "https://ifconfig.co/port/$Port" -TimeoutSec 6 -UseBasicParsing
        $json = $resp.Content | ConvertFrom-Json
        if ($json.reachable) {
            Write-Host "Port $($json.port) is reachable from the internet (public IP: $($json.ip))."
        } else {
            Write-Host "Port $($json.port) is NOT reachable from the internet yet (public IP: $($json.ip))."
        }
    } catch {
        Write-Host 'Skipped automatic port-forwarding check (unable to contact ifconfig.co).'
    }
}

function Write-EnvFile($RepoRoot, $Port, $ForceTls, $Host) {
    $scheme = if ($ForceTls) { 'https' } else { 'http' }
    $envPath = Join-Path $RepoRoot 'admin/.env'
    if (Test-Path $envPath) {
        $backup = "$envPath.bak.$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
        Copy-Item $envPath $backup
        Write-Host "Existing .env backed up to $(Split-Path $backup -Leaf)."
    }
    $origins = "https://127.0.0.1:$Port,http://127.0.0.1:$Port,$scheme://$Host:$Port"
    $content = @(
        'API_HOST=0.0.0.0'
        "API_PORT=$Port"
        "FORCE_TLS=$([int]$ForceTls)"
        "PUBLIC_BASE_URL=$scheme://$Host:$Port"
        "ALLOWED_ORIGINS=$origins"
        'PRODUCT_BACKUPS=3'
        'TRUST_PROXY_HEADERS=1'
    )
    $content | Set-Content -Path $envPath -Encoding UTF8
    Write-Host 'Wrote admin/.env with selected options.'
}

function Get-Python() {
    $candidate = Get-Command py -ErrorAction SilentlyContinue
    if ($candidate) { return $candidate.Path }
    $candidate = Get-Command python -ErrorAction SilentlyContinue
    if ($candidate) { return $candidate.Path }
    throw 'Python 3 is required. Install it from https://python.org/downloads/'
}

function Setup-Venv($RepoRoot, $PythonPath) {
    $venvPath = Join-Path $RepoRoot '.venv'
    if (-not (Test-Path $venvPath)) {
        & $PythonPath -m venv $venvPath
    }
    & (Join-Path $venvPath 'Scripts/python.exe') -m pip install --upgrade pip | Out-Null
    & (Join-Path $venvPath 'Scripts/python.exe') -m pip install -r (Join-Path $RepoRoot 'admin/requirements.txt')
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

Write-Host '== Vendly deployment assistant (PowerShell) =='
$python = Get-Python
$port = Prompt-Port 7890
$useTls = Read-YesNo 'Enable HTTPS with a self-signed certificate? [Y/n]' 'Y'
$host = Read-Host 'Public hostname for links [127.0.0.1]'
if ([string]::IsNullOrWhiteSpace($host)) { $host = '127.0.0.1' }

Write-Host ''
Write-Host 'Checking external visibility...'
Check-PortForward $port

Write-Host ''
Write-Host 'Creating environment configuration...'
Write-EnvFile $RepoRoot $port $useTls $host

Write-Host ''
Write-Host 'Setting up Python environment...'
Setup-Venv $RepoRoot $python

$scheme = if ($useTls) { 'HTTPS' } else { 'HTTP' }
Write-Host ''
Write-Host 'Installation complete.'
Write-Host ''
Write-Host 'Next steps:'
Write-Host "  1. Activate the virtualenv:   `"$RepoRoot\.venv\Scripts\activate.ps1`""
Write-Host '  2. Start the API:             python -m admin.app'
Write-Host ''
Write-Host "The service will listen on $host:$port via $scheme."
Write-Host "Remember to forward TCP port $port on your router if clients must reach it externally."
