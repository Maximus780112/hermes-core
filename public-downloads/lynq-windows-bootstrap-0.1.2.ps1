# Lynq Windows bootstrap 0.1.2
# Public GitHub artifacts. Hash verify before install.
# Pairing code: env LYNQ_PAIRING_CODE only. Never argv. Never logged.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$ManifestUrl = 'https://github.com/Maximus780112/hermes-core/releases/download/v0.1.2/lynq-windows-manifest-0.1.2.json'
$ExpectedPe = '9a8b08d99630d246fd61254bf525a3fbd91566e4d732fbf880596b85cf263746'

function Fail([string]$Code) {
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

$token = [string]$env:LYNQ_PAIRING_CODE
$env:LYNQ_PAIRING_CODE = $null
if ([string]::IsNullOrWhiteSpace($token)) { Fail 'MISSING_PAIRING_CODE' }

Assert-GithubDownload $ManifestUrl
Write-Output 'Downloading Lynq...'
$manifest = Invoke-RestMethod -Uri $ManifestUrl -UseBasicParsing
if ($manifest.pe_sha256 -ne $ExpectedPe) { Fail 'MANIFEST_PE_HASH_MISMATCH' }
Assert-GithubDownload ([string]$manifest.pe_url)
Assert-GithubDownload ([string]$manifest.bootstrap_url)

$tmp = Join-Path $env:TEMP ('lynq-pe-' + [guid]::NewGuid().ToString('n'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$pe = Join-Path $tmp 'HermesCoreSetup-0.1.2.exe'
try {
  Invoke-WebRequest -Uri $manifest.pe_url -OutFile $pe -UseBasicParsing
  Write-Output 'Verifying...'
  $got = (Get-FileHash -Path $pe -Algorithm SHA256).Hash.ToLowerInvariant()
  if ($got -ne $ExpectedPe) { Fail 'PE_HASH_MISMATCH' }

  $sig = Get-AuthenticodeSignature -FilePath $pe
  if ($sig.Status -eq 'Valid') { Write-Output 'AUTHENTICODE=PASS' }
  else { Write-Output ('AUTHENTICODE=UNSIGNED status=' + [string]$sig.Status) }

  Write-Output 'Installing...'
  $p = Start-Process -FilePath $pe -ArgumentList '/S' -Wait -PassThru
  if ($null -eq $p -or $p.ExitCode -ne 0) { Fail 'INSTALLER_EXIT' }

  $root = Join-Path $env:LOCALAPPDATA 'Programs\HermesCore'
  $py = Join-Path $root 'runtime\python.exe'
  if (-not (Test-Path $py)) { Fail 'CORE_RUNTIME_MISSING' }
  $env:HERMES_CORE_HOME = Join-Path $env:LOCALAPPDATA 'HermesCore'
  $env:PYTHONPATH = Join-Path $root 'runtime\Lib\site-packages'

  $pairUrl = [string]$env:LYNQ_PAIR_URL
  $env:LYNQ_PAIR_URL = $null
  if ([string]::IsNullOrWhiteSpace($pairUrl)) { Fail 'MISSING_PAIR_URL' }
  $pairUri = [Uri]$pairUrl
  if ($pairUri.Scheme -ne 'https') { Fail 'TLS_REQUIRED' }

  Write-Output 'Pairing...'
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
  $stdout = $proc.StandardOutput.ReadToEnd()
  [void]$proc.StandardError.ReadToEnd()
  $proc.WaitForExit()
  if ($proc.ExitCode -ne 0 -or $stdout -notmatch 'ok=true') { Fail 'PAIRING_FAILED' }
  Write-Output 'Connecting...'
  Write-Output 'Lynq is ready. You can return to WhatsApp.'
  Write-Output 'BOOTSTRAP=READY'
}
finally {
  $token = $null
  $env:LYNQ_PAIRING_CODE = $null
  $env:LYNQ_PAIR_URL = $null
  if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
}
