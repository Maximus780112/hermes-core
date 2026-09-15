# Lynq Windows bootstrap 0.1.2
# Public GitHub artifacts. Hash verify before install.
# Pairing code: env LYNQ_PAIRING_CODE only. Never argv. Never logged.

$ErrorActionPreference = 'Stop'
$ManifestUrl = 'https://github.com/Maximus780112/hermes-core/releases/download/v0.1.2/lynq-windows-manifest-0.1.2.json'
$ExpectedPe = '9a8b08d99630d246fd61254bf525a3fbd91566e4d732fbf880596b85cf263746'

function Step([string]$Msg) {
  Write-Host ("[{0:HH:mm:ss}] {1}" -f (Get-Date), $Msg)
}

function Fail([string]$Code) {
  Write-Host ("[{0:HH:mm:ss}] FAIL {1}" -f (Get-Date), $Code)
  Write-Error $Code
  exit 1
}

function Assert-GithubDownload([string]$Url) {
  $uri = [Uri]$Url
  if ($uri.Scheme -ne 'https') { Fail 'TLS_REQUIRED' }
  $hostName = $uri.Host.ToLowerInvariant()
  $ok = ($hostName -eq 'github.com') -or $hostName.EndsWith('.github.com') -or $hostName.EndsWith('.githubusercontent.com')
  if (-not $ok) { Fail 'NON_GITHUB_DOWNLOAD' }
}

Step 'Lynq bootstrap starting'
$token = [string]$env:LYNQ_PAIRING_CODE
$pairUrl = [string]$env:LYNQ_PAIR_URL
$env:LYNQ_PAIRING_CODE = $null
$env:LYNQ_PAIR_URL = $null
if ([string]::IsNullOrWhiteSpace($token)) { Fail 'MISSING_PAIRING_CODE' }
if ([string]::IsNullOrWhiteSpace($pairUrl)) { Fail 'MISSING_PAIR_URL' }
$pairUri = [Uri]$pairUrl
if ($pairUri.Scheme -ne 'https') { Fail 'TLS_REQUIRED' }

Assert-GithubDownload $ManifestUrl
Step 'Fetching manifest'
$manifest = Invoke-RestMethod -Uri $ManifestUrl -UseBasicParsing -TimeoutSec 60
if ($manifest.pe_sha256 -ne $ExpectedPe) { Fail 'MANIFEST_PE_HASH_MISMATCH' }
Assert-GithubDownload ([string]$manifest.pe_url)

$tmp = Join-Path $env:TEMP ('lynq-pe-' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$pe = Join-Path $tmp 'HermesCoreSetup-0.1.2.exe'
try {
  Step 'Downloading Core (~15 MB)'
  Invoke-WebRequest -Uri $manifest.pe_url -OutFile $pe -UseBasicParsing -TimeoutSec 180
  Step 'Verifying SHA-256'
  $got = (Get-FileHash -Path $pe -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($got -ne $ExpectedPe) { Fail 'PE_HASH_MISMATCH' }
  Step 'SHA-256 OK'

  $sig = Get-AuthenticodeSignature -FilePath $pe
  if ($sig.Status -eq 'Valid') { Step 'AUTHENTICODE=PASS' }
  else { Step ('AUTHENTICODE=UNSIGNED status=' + [string]$sig.Status + ' — Windows may block this file') }

  Step 'Installing (user-scope, silent)'
  $p = Start-Process -FilePath $pe -ArgumentList '/S' -Wait -PassThru
  if ($null -eq $p) { Fail 'INSTALLER_NOT_STARTED' }
  if ($p.ExitCode -ne 0) { Fail ('INSTALLER_EXIT_' + [string]$p.ExitCode) }

  $root = Join-Path $env:LOCALAPPDATA 'Programs\HermesCore'
  $py = Join-Path $root 'runtime\python.exe'
  if (-not (Test-Path $root)) { Fail 'INSTALL_DIR_MISSING' }
  if (-not (Test-Path $py)) { Fail 'CORE_RUNTIME_MISSING' }
  Step 'Install dir present'
  $env:HERMES_CORE_HOME = Join-Path $env:LOCALAPPDATA 'HermesCore'
  $env:PYTHONPATH = Join-Path $root 'runtime\Lib\site-packages'

  Step 'Pairing'
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $py
  $psi.Arguments = '-m hermes_core.cli pair --url ' + $pairUrl
  $psi.WorkingDirectory = $root
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  $psi.Environment['HERMES_CORE_HOME'] = $env:HERMES_CORE_HOME
  $psi.Environment['PYTHONPATH'] = $env:PYTHONPATH
  $proc = [Diagnostics.Process]::Start($psi)
  $proc.StandardInput.WriteLine($token)
  $proc.StandardInput.Close()
  $token = $null
  if (-not $proc.WaitForExit(30000)) { $proc.Kill(); Fail 'PAIRING_TIMEOUT' }
  $stdout = $proc.StandardOutput.ReadToEnd()
  [void]$proc.StandardError.ReadToEnd()
  if ($proc.ExitCode -ne 0 -or $stdout -notmatch 'ok=true') { Fail 'PAIRING_FAILED' }
  Step 'Pairing consumed'
  Step 'Lynq is ready. You can return to WhatsApp.'
}
finally {
  $token = $null
  $env:LYNQ_PAIRING_CODE = $null
  $env:LYNQ_PAIR_URL = $null
  if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
}
