#!/usr/bin/env pwsh
$ErrorActionPreference = 'Stop'

function Test-EnvTruthy($Value) {
    if (-not $Value) { return $false }
    switch ($Value.ToString().ToLowerInvariant()) {
        '1' { return $true }
        'y' { return $true }
        'yes' { return $true }
        'true' { return $true }
        'on' { return $true }
        default { return $false }
    }
}

function Test-EnvFalsy($Value) {
    if (-not $Value) { return $false }
    switch ($Value.ToString().ToLowerInvariant()) {
        '0' { return $true }
        'n' { return $true }
        'no' { return $true }
        'false' { return $true }
        'off' { return $true }
        default { return $false }
    }
}

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
    if (Test-EnvTruthy $env:LETS_ENCRYPT_STAGING) {
        $args += '--staging'
    }
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
    $presetCert = $env:TLS_CERT_FILE
    $presetKey = $env:TLS_KEY_FILE
    while ($true) {
        $certPrompt = "Certificate chain path"
        if ($Domain) { $certPrompt += " (e.g. /etc/letsencrypt/live/$Domain/fullchain.pem)" }
        if ($presetCert) { $certPrompt += " [$presetCert]" }
        $cert = Read-Host $certPrompt
        if ([string]::IsNullOrWhiteSpace($cert)) { $cert = $presetCert }
        if ([string]::IsNullOrWhiteSpace($cert) -or -not (Test-Path $cert)) {
            Write-Host 'Certificate path is required and must exist.'
            continue
        }
        $keyPrompt = "Private key path"
        if ($Domain) { $keyPrompt += " (e.g. /etc/letsencrypt/live/$Domain/privkey.pem)" }
        if ($presetKey) { $keyPrompt += " [$presetKey]" }
        $key = Read-Host $keyPrompt
        if ([string]::IsNullOrWhiteSpace($key)) { $key = $presetKey }
        if ([string]::IsNullOrWhiteSpace($key) -or -not (Test-Path $key)) {
            Write-Host 'Private key path is required and must exist.'
            continue
        }
        return @{ Cert = $cert; Key = $key }
    }
}

function Import-InstallerEnv($ScriptDir) {
    $envFile = Join-Path $ScriptDir '.env'
    if (-not (Test-Path $envFile)) { return }
    foreach ($line in Get-Content $envFile) {
        if ($line.TrimStart().StartsWith('#')) { continue }
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $parts = $line.Split('=', 2)
        if ($parts.Count -eq 0) { continue }
        $name = $parts[0].Trim()
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $value = if ($parts.Count -gt 1) { $parts[1] } else { '' }
        [Environment]::SetEnvironmentVariable($name, $value)
    }
}

function Sync-Repository($RepoRoot) {
    if ([string]::IsNullOrWhiteSpace($RepoRoot)) { return }
    if (Test-EnvTruthy $env:INSTALL_SKIP_SYNC) { return }
    $gitDir = Join-Path $RepoRoot '.git'
    if (-not (Test-Path $gitDir)) {
        if ($env:INSTALL_REPO_URL) {
            Write-Warning "Installer repository sync requested but $RepoRoot is not a git checkout; skipping."
        }
        return
    }
    $git = Get-Command git -ErrorAction SilentlyContinue
    if (-not $git) {
        if ($env:INSTALL_REPO_URL) {
            Write-Warning 'git not available; skipping repository sync.'
        }
        return
    }
    Push-Location $RepoRoot
    try {
        $remote = if ($env:INSTALL_REPO_REMOTE) { $env:INSTALL_REPO_REMOTE } else { 'origin' }
        $branch = $env:INSTALL_REPO_BRANCH
        $current = (& $git.Path rev-parse --abbrev-ref HEAD 2>$null).Trim()
        if (-not $branch) { $branch = $current }
        if (-not $branch) { $branch = 'main' }
        if ($current -and $branch -and $current -ne $branch) {
            Write-Warning "Skipping repository sync because current branch '$current' differs from '$branch'."
            return
        }
        $url = $env:INSTALL_REPO_URL
        if ($url) {
            $existing = ''
            try { $existing = (& $git.Path remote get-url $remote 2>$null).Trim() } catch { $existing = '' }
            if (-not $existing) {
                & $git.Path remote add $remote $url | Out-Null
            } elseif ($existing -ne $url) {
                & $git.Path remote set-url $remote $url | Out-Null
            }
        }
        Write-Host "Ensuring repository is up to date from $remote/$branch..."
        & $git.Path fetch $remote $branch | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Unable to fetch $remote/$branch; continuing with local files."
            return
        }
        $mergeOutput = & $git.Path merge --ff-only FETCH_HEAD 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not fast-forward to $remote/$branch. Please update the repository manually."
        } else {
            Write-Host "Repository updated to latest $remote/$branch."
        }
    } finally {
        Pop-Location
    }
}

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = Split-Path -Parent $ScriptDir

Import-InstallerEnv $ScriptDir
Sync-Repository $RepoRoot

Write-Host '== Vendly deployment assistant (PowerShell) =='
$python = Get-Python

$defaultPort = 7890
if ($env:API_PORT -and [int]::TryParse($env:API_PORT, [ref]$null)) {
    $defaultPort = [int]$env:API_PORT
    if ($defaultPort -lt 1 -or $defaultPort -gt 65535) { $defaultPort = 7890 }
}
$port = Prompt-Port $defaultPort

$fallbackDefault = if ($env:PUBLIC_FALLBACK_HOST) { $env:PUBLIC_FALLBACK_HOST } else { '127.0.0.1' }
$fallbackHost = Read-Host "Technician fallback hostname/IP [$fallbackDefault]"
if ([string]::IsNullOrWhiteSpace($fallbackHost)) { $fallbackHost = $fallbackDefault }

$domain = ''
$useDomain = $false
if ($env:PUBLIC_DOMAIN) {
    $candidate = $env:PUBLIC_DOMAIN
    $candidate = ($candidate ?? '').Trim().ToLowerInvariant().TrimEnd('.')
    $candidate = $candidate.Replace(' ', '')
    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
        $domain = $candidate
        $useDomain = $true
        Write-Host "Using preset domain from environment: $domain"
    }
}
if (-not $useDomain) {
    $useDomain = Read-YesNo 'Configure a custom domain name? [y/N]' 'N'
}
if ($useDomain) {
    while ($true) {
        $prompt = 'Domain (e.g. shop.example.com)'
        if ($domain) { $prompt += " [$domain]" }
        $input = Read-Host $prompt
        if ([string]::IsNullOrWhiteSpace($input)) { $input = $domain }
        $input = ($input ?? '').Trim().ToLowerInvariant().TrimEnd('.')
        $input = $input.Replace(' ', '')
        if ([string]::IsNullOrWhiteSpace($input)) { Write-Host 'Domain cannot be empty.'; continue }
        if ($input -notmatch '^[a-z0-9.-]+$') { Write-Host 'Domain may only contain letters, numbers, dots, and hyphens.'; continue }
        $domain = $input
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
            $zoneDefault = $env:CLOUDFLARE_ZONE_ID
            $zonePrompt = 'Cloudflare Zone ID'
            if ($zoneDefault) { $zonePrompt += " [$zoneDefault]" }
            $zoneId = Read-Host $zonePrompt
            if ([string]::IsNullOrWhiteSpace($zoneId)) { $zoneId = $zoneDefault }
            $token = $null
            if ($env:CLOUDFLARE_API_TOKEN) {
                Write-Host 'Using Cloudflare API token from environment.'
                $token = $env:CLOUDFLARE_API_TOKEN
            } else {
                $token = Read-Host 'Cloudflare API token (DNS edit scope)'
            }
            $proxyDefaultAnswer = if (Test-EnvFalsy $env:CLOUDFLARE_PROXY_DEFAULT) { 'N' } else { 'Y' }
            $proxyPromptSuffix = if ($proxyDefaultAnswer -eq 'Y') { '[Y/n]' } else { '[y/N]' }
            $proxied = Read-YesNo "Proxy traffic through Cloudflare (orange cloud)? $proxyPromptSuffix" $proxyDefaultAnswer
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
$scheme = 'http'
$envForceTls = $env:FORCE_TLS
$presetCert = $env:TLS_CERT_FILE
$presetKey = $env:TLS_KEY_FILE
$presetLeEmail = $env:LETS_ENCRYPT_EMAIL
$certPath = ''
$keyPath = ''
$leEmail = $presetLeEmail
$publicPort = $port
if ($env:PUBLIC_PORT -and [int]::TryParse($env:PUBLIC_PORT, [ref]$null)) {
    $publicPort = [int]$env:PUBLIC_PORT
}
$forceTls = $false
if (Test-EnvTruthy $envForceTls) { $forceTls = $true }

if ($useDomain) {
    Write-Host ''
    Write-Host "TLS configuration for $domain:"
    Write-Host '  [1] Automatic Lets Encrypt certificate (recommended)'
    Write-Host '  [2] Provide existing certificate paths'
    Write-Host '  [3] Self-signed development certificate'
    Write-Host '  [4] Disable HTTPS'
    $tlsChoiceDefault = '1'
    if ($presetCert -and $presetKey) {
        $tlsChoiceDefault = '2'
    } elseif (Test-EnvFalsy $envForceTls) {
        $tlsChoiceDefault = '4'
    }
    $choice = Read-Host "Select option [$tlsChoiceDefault]"
    if ([string]::IsNullOrWhiteSpace($choice)) { $choice = $tlsChoiceDefault }
    switch ($choice) {
        '1' { $tlsMode = 'letsencrypt'; $forceTls = $true }
        '2' { $tlsMode = 'manual'; $forceTls = $true }
        '3' { $tlsMode = 'adhoc'; $forceTls = $true }
        '4' { $tlsMode = 'http'; $forceTls = $false }
        default { Write-Host 'Unknown option; defaulting to Lets Encrypt.'; $tlsMode = 'letsencrypt'; $forceTls = $true }
    }
} else {
    $httpsDefaultAnswer = if (Test-EnvFalsy $envForceTls) { 'N' } else { 'Y' }
    $httpsPromptSuffix = if ($httpsDefaultAnswer -eq 'Y') { '[Y/n]' } else { '[y/N]' }
    if (Read-YesNo "Enable HTTPS with a self-signed certificate? $httpsPromptSuffix" $httpsDefaultAnswer) {
        $tlsMode = 'adhoc'
        $forceTls = $true
    }
}

if ($forceTls) { $scheme = 'https' }

if ($useDomain) {
    $defaultPublicPort = $publicPort
    if (-not [int]::TryParse($defaultPublicPort, [ref]$null) -or $defaultPublicPort -lt 1 -or $defaultPublicPort -gt 65535) {
        $defaultPublicPort = if ($scheme -eq 'https') { 443 } else { 80 }
    }
    $publicPortInput = Read-Host "External port clients will use for $domain [$defaultPublicPort]"
    if ([string]::IsNullOrWhiteSpace($publicPortInput)) { $publicPortInput = $defaultPublicPort }
    if ([int]::TryParse($publicPortInput, [ref]$null)) {
        $value = [int]$publicPortInput
        if ($value -ge 1 -and $value -le 65535) { $publicPort = $value } else { Write-Host "Invalid port supplied; using $defaultPublicPort."; $publicPort = $defaultPublicPort }
    } else {
        Write-Host "Invalid port supplied; using $defaultPublicPort."
        $publicPort = $defaultPublicPort
    }
} else {
    if (-not [int]::TryParse($publicPort, [ref]$null)) {
        $publicPort = $port
    }
}

if ($tlsMode -eq 'letsencrypt') {
    $certPath = ''
    $keyPath = ''
    Write-Host ''
    Write-Host "Attempting to obtain a Let's Encrypt certificate (certbot must be installed and TCP/80 reachable)."
    $emailPrompt = "Email for Let's Encrypt expiry notices (optional)"
    if ($presetLeEmail) { $emailPrompt += " [$presetLeEmail]" }
    $emailInput = Read-Host $emailPrompt
    if ([string]::IsNullOrWhiteSpace($emailInput)) { $emailInput = $presetLeEmail }
    $leEmail = $emailInput
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

$publicBase = if ($env:PUBLIC_BASE_URL) {
    $env:PUBLIC_BASE_URL
} elseif ($useDomain) {
    Format-Origin $scheme $domain $publicPort
} else {
    Format-Origin $scheme $fallbackHost $port
}

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
