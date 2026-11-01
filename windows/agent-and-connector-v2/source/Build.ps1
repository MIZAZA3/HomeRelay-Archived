$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (!(Test-Path -LiteralPath $csc)) { throw '.NET Framework 4.x x64 compiler is required.' }
$refs = @('/r:System.Windows.Forms.dll','/r:System.Drawing.dll','/r:System.Web.Extensions.dll','/r:System.Security.dll')
function Build-App($name,$files) {
  $target = Join-Path $root $name
  New-Item -ItemType Directory -Path $target -Force | Out-Null
  $exe = @{Agent='HomeRelayAgent';Connector='HomeRelayConnector';Admin='OpenPanel'}[$name]
  & $csc /nologo /target:winexe /platform:x64 @refs "/out:$target\$exe.exe" @($files | ForEach-Object {Join-Path $PSScriptRoot $_})
  if ($LASTEXITCODE -ne 0) { throw "Build failed: $name" }
}
Build-App 'Agent' @('Common.cs','Bootstrap.cs','Agent.cs')
Build-App 'Connector' @('Common.cs','Connector.cs','ProxyProbe.cs')
Build-App 'Admin' @('Common.cs','OpenPanel.cs')
Write-Output 'Built Agent, Connector and Admin. Existing private identities/configurations were not changed.'
