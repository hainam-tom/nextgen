#!/usr/bin/env pwsh
$ErrorActionPreference = 'Stop'

function Read-YesNo($Prompt, $Default = 'Y') {
    while ($true) {
        $response = Read-Host "$Prompt"
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

function Format-Origin([string]$Scheme, [string]$Host, [int]$Port) {
    if ([string]::IsNullOrWhiteSpace($Host)) { return '' }
    $scheme = $Scheme.ToLowerInvariant()
    if ($scheme -ne 'http' -and $scheme -ne 'https') { return '' }
    $defaultPort = if ($scheme -eq 'https') { 443 } else { 80 }
    $suffix = if ($Port -eq $defaultPort) { '' } else { ":$Port" }
    return "$scheme://$Host$suffix"
}

function Build-AllowedOrigins($ApiPort, $ForceTls, $PublicBase, $FallbackHost, $Domain, $PublicPort) {
    $scheme = if ($ForceTls) { 'https' } else { 'http' }
    $origins = [System.Collections.Generic.List[string]]::new()
    $origins.Add((Format-Origin 'https' '127.0.0.1' $ApiPort))
    $origins.Add((Format-Origin 'http' '127.0.0.1' $ApiPort))
    if ($FallbackHost) { $origins.Add((Format-Origin $scheme $FallbackHost $ApiPort)) }
    if ($Domain) {
        $origins.Add((Format-Origin $scheme $Domain $PublicPort))
        if (-not $Domain.StartsWith('www.')) {
            $origins.Add((Format-Origin $scheme "www.$Domain" $PublicPort))
        }
    }
    if ($PublicBase) {
        try {
            $uri = [Uri]$PublicBase
            $port = if ($uri.IsDefaultPort) {
                if ($uri.Scheme -eq 'https') { 443 } else { 80 }
            } else {
                $uri.Port
            }
            $origins.Add((Format-Origin $uri.Scheme $uri.Host $port))
        } catch {
            # ignore invalid URI
        }
    }
    $origins | Where-Object { $_ } | Select-Object -Unique -Join ','
}

function Write-EnvFile($RepoRoot, $Port, $ForceTls, $PublicBase, $FallbackHost, $Domain, $PublicPort, $CertPath, $KeyPath, $LeEmail) {
    $envPath = Join-Path $RepoRoot 'admin/.env'
    $origins = Build-AllowedOrigins $Port $ForceTls $PublicBase $FallbackHost $Domain $PublicPort
    if (Test-Path $envPath) {
        $backup = "$envPath.bak.$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
        Copy-Item $envPath $backup
        Write-Host "Existing .env backed up to $(Split-Path $backup -Leaf)."
    }
    $lines = @(
        'API_HOST=0.0.0.0'
        "API_PORT=$Port"
        "PUBLIC_PORT=$PublicPort"
        "FORCE_TLS=$([int]$ForceTls)"
        "PUBLIC_BASE_URL=$PublicBase"
        "PUBLIC_DOMAIN=$Domain"
        "PUBLIC_FALLBACK_HOST=$FallbackHost"
        "ALLOWED_ORIGINS=$origins"
        'PRODUCT_BACKUPS=3'
        'TRUST_PROXY_HEADERS=1'
    )
    if ($CertPath) { $lines += "TLS_CERT_FILE=$CertPath" }
    if ($KeyPath) { $lines += "TLS_KEY_FILE=$KeyPath" }
    if ($LeEmail) { $lines += "LETS_ENCRYPT_EMAIL=$LeEmail" }
    $lines | Set-Content -Path $envPath -Encoding UTF8
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

function Get-PublicIp() {
    try {
        $resp = Invoke-WebRequest -Uri 'https://ifconfig.co/ip' -TimeoutSec 6 -UseBasicParsing
        $ip = $resp.Content.Trim()
        if ($ip) { return $ip }
    } catch { }
    return $null
}

function Invoke-CloudflareDns($Domain, $Ip, $ZoneId, $Token, $Proxied) {
    $headers = @{ 'Authorization' = "Bearer $Token"; 'Content-Type' = 'application/json' }
    try {
        $lookup = Invoke-RestMethod -Method Get -Uri "https://api.cloudflare.com/client/v4/zones/$ZoneId/dns_records?type=A&name=$Domain" -Headers $headers
    } catch {
        return $false
    }
    $recordId = $lookup.result | Where-Object { $_.name -eq $Domain } | Select-Object -ExpandProperty id -First 1
    $body = @{ type = 'A'; name = $Domain; content = $Ip; ttl = 120; proxied = [bool]$Proxied } | ConvertTo-Json
    $method = if ($recordId) { 'Put' } else { 'Post' }
    $uri = if ($recordId) { "https://api.cloudflare.com/client/v4/zones/$ZoneId/dns_records/$recordId" } else { "https://api.cloudflare.com/client/v4/zones/$ZoneId/dns_records" }
    try {
        $result = Invoke-RestMethod -Method $method -Uri $uri -Headers $headers -Body $body
        return [bool]$result.success
    } catch {
        return $false
    }
}

function Obtain-LetsEncryptCert($Domain, $Email) {
    $certbot = Get-Command certbot -ErrorAction SilentlyContinue
    if (-not $certbot) { return $false }
    Write-Host "Running certbot for $Domain..."
    $args = @('certonly','--standalone','--agree-tos','--non-interactive','--preferred-challenges','http','-d', $Domain)
    if ($Email) {
        $args += @('--email', $Email)
    } else {
        $args += '--register-unsafely-without-email'
    }
    try {
        & $certbot.Path @args
        return ($LASTEXITCODE -eq 0)
    } catch {
        return $false
    }
}

function Prompt-CertificatePaths($Domain) {
    while ($true) {
        $cert = Read-Host "Certificate chain path (e.g. /etc/letsencrypt/live/$Domain/fullchain.pem)"
        if ([string]::IsNullOrWhiteSpace($cert) -or -not (Test-Path $cert)) {
            Write-Host 'Certificate path is required and must exist.'
            continue
        }
        $key = Read-Host "Private key path (e.g. /etc/letsencrypt/live/$Domain/privkey.pem)"
        if ([string]::IsNullOrWhiteSpace($key) -or -not (Test-Path $key)) {
            Write-Host 'Private key path is required and must exist.'
            continue
        }
        return @{ Cert = $cert; Key = $key }
    }
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

Write-Host '== Vendly deployment assistant (PowerShell) =='
$python = Get-Python
$port = Prompt-Port 7890

$fallbackDefault = if ($env:PUBLIC_FALLBACK_HOST) { $env:PUBLIC_FALLBACK_HOST } else { '127.0.0.1' }
$fallbackHost = Read-Host "Technician fallback hostname/IP [$fallbackDefault]"
if ([string]::IsNullOrWhiteSpace($fallbackHost)) { $fallbackHost = $fallbackDefault }

$useDomain = Read-YesNo 'Configure a custom domain name? [y/N]' 'N'
$domain = ''
if ($useDomain) {
    while ($true) {
        $domain = Read-Host 'Domain (e.g. shop.example.com)'
        $domain = ($domain ?? '').Trim().ToLowerInvariant().TrimEnd('.')
        if ([string]::IsNullOrWhiteSpace($domain)) { Write-Host 'Domain cannot be empty.'; continue }
        if ($domain -notmatch '^[a-z0-9.-]+$') { Write-Host 'Domain may only contain letters, numbers, dots, and hyphens.'; continue }
        break
    }
    if (Read-YesNo "Create or update a Cloudflare DNS A record for $domain? [y/N]" 'N') {
        $ip = Get-PublicIp
        if ($ip) {
            Write-Host "Detected public IPv4: $ip"
        } else {
            $ip = Read-Host 'IPv4 address to assign'
        }
        if ($ip) {
            $zoneId = Read-Host 'Cloudflare Zone ID'
            $token = Read-Host 'Cloudflare API token (DNS edit scope)'
            $proxied = Read-YesNo 'Proxy traffic through Cloudflare (orange cloud)? [Y/n]' 'Y'
            if ($zoneId -and $token) {
                if (Invoke-CloudflareDns $domain $ip $zoneId $token $proxied) {
                    Write-Host "Cloudflare DNS record for $domain is configured."
                } else {
                    Write-Host 'Failed to configure Cloudflare DNS via API. Please update it manually.'
                }
            } else {
                Write-Host 'Skipping Cloudflare DNS update (missing zone ID or API token).'
            }
        } else {
            Write-Host 'Skipping Cloudflare DNS update (no IP provided).'
        }
    }
}

Write-Host ''
Write-Host 'Checking external visibility...'
Check-PortForward $port

$tlsMode = 'http'
$forceTls = $false
$certPath = ''
$keyPath = ''
$leEmail = ''
$publicPort = $port
$scheme = 'http'

if ($useDomain) {
    Write-Host ''
    Write-Host "TLS configuration for $domain:"
    Write-Host '  [1] Automatic Lets Encrypt certificate (recommended)'
    Write-Host '  [2] Provide existing certificate paths'
    Write-Host '  [3] Self-signed development certificate'
    Write-Host '  [4] Disable HTTPS'
    $choice = Read-Host 'Select option [1]'
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = '1' }
    switch ($choice) {
        '1' { $tlsMode = 'letsencrypt'; $forceTls = $true }
        '2' { $tlsMode = 'manual'; $forceTls = $true }
        '3' { $tlsMode = 'adhoc'; $forceTls = $true }
        '4' { $tlsMode = 'http'; $forceTls = $false }
        default { Write-Host 'Unknown option; defaulting to Lets Encrypt.'; $tlsMode = 'letsencrypt'; $forceTls = $true }
    }
} else {
    if (Read-YesNo 'Enable HTTPS with a self-signed certificate? [Y/n]' 'Y') {
        $tlsMode = 'adhoc'
        $forceTls = $true
    }
}

if ($forceTls) { $scheme = 'https' }

if ($useDomain) {
    $defaultPublicPort = if ($scheme -eq 'https') { 443 } else { 80 }
    $publicPortInput = Read-Host "External port clients will use for $domain [$defaultPublicPort]"
    if ([string]::IsNullOrWhiteSpace($publicPortInput)) { $publicPortInput = $defaultPublicPort }
    if ([int]::TryParse($publicPortInput, [ref]$null)) {
        $value = [int]$publicPortInput
        if ($value -ge 1 -and $value -le 65535) { $publicPort = $value } else { Write-Host "Invalid port supplied; using $defaultPublicPort."; $publicPort = $defaultPublicPort }
    } else {
        Write-Host "Invalid port supplied; using $defaultPublicPort."
        $publicPort = $defaultPublicPort
    }
}

if ($tlsMode -eq 'letsencrypt') {
    Write-Host ''
    Write-Host "Attempting to obtain a Let's Encrypt certificate (certbot must be installed and TCP/80 reachable)."
    $leEmail = Read-Host "Email for Let's Encrypt expiry notices (optional)"
    $success = Obtain-LetsEncryptCert $domain $leEmail
    if ($success) {
        $candidateDirs = @("/etc/letsencrypt/live/$domain", "C:/Certbot/live/$domain")
        foreach ($dir in $candidateDirs) {
            if (Test-Path $dir) {
                $possibleCert = Join-Path $dir 'fullchain.pem'
                $possibleKey = Join-Path $dir 'privkey.pem'
                if ((Test-Path $possibleCert) -and (Test-Path $possibleKey)) {
                    $certPath = $possibleCert
                    $keyPath = $possibleKey
                    Write-Host "Stored certificates in $dir."
                    break
                }
            }
        }
    } else {
        Write-Host "Let's Encrypt enrollment skipped or failed."
    }
    if (-not $certPath -or -not $keyPath) {
        if (Read-YesNo 'Provide certificate paths manually now? [Y/n]' 'Y') {
            $paths = Prompt-CertificatePaths $domain
            $certPath = $paths.Cert
            $keyPath = $paths.Key
        } else {
            Write-Host 'You can rerun the installer later to record certificate paths once available.'
        }
    }
} elseif ($tlsMode -eq 'manual') {
    Write-Host ''
    Write-Host 'Enter the paths to your existing certificate chain and private key.'
    $paths = Prompt-CertificatePaths $domain
    $certPath = $paths.Cert
    $keyPath = $paths.Key
}

$publicBase = if ($useDomain) { Format-Origin $scheme $domain $publicPort } else { Format-Origin $scheme $fallbackHost $port }

Write-Host ''
Write-Host 'Creating environment configuration...'
Write-EnvFile $RepoRoot $port $forceTls $publicBase $fallbackHost $domain $publicPort $certPath $keyPath $leEmail

Write-Host ''
Write-Host 'Setting up Python environment...'
Setup-Venv $RepoRoot $python

$displayBase = if ($publicBase) { $publicBase } else { Format-Origin $scheme $fallbackHost $port }
$dnsNote = ''
if ($useDomain) {
    $dnsNote = "Remember to keep your DNS pointing at this host and renew Let's Encrypt certificates (e.g. via 'certbot renew')."
}

Write-Host ''
Write-Host 'Installation complete.'
Write-Host ''
Write-Host 'Next steps:'
Write-Host "  1. Activate the virtualenv:   `"$RepoRoot\.venv\Scripts\activate.ps1`""
Write-Host '  2. Start the API:             python -m admin.app'
Write-Host ''
Write-Host "The service will listen on $displayBase (API port $port)."
if ($dnsNote) { Write-Host $dnsNote }
Write-Host "Remember to forward TCP port $publicPort on your router if clients must reach it externally."
