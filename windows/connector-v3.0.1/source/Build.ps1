$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$refs=@('/r:System.Windows.Forms.dll','/r:System.Drawing.dll','/r:System.Web.Extensions.dll','/r:System.Security.dll')
$common=@('Common.cs','GlobalSupport.cs')|ForEach-Object {Join-Path $PSScriptRoot $_}
& $csc /nologo /platform:x64 /target:winexe /main:UnifiedProgram @refs "/out:$root\Connector\HomeRelayConnector.exe" @common @('Profiles.cs','ConnectorCore.cs','ProxyProbe.cs','AppSessions.cs','Payload.cs','ConnectorUI.cs'|ForEach-Object {Join-Path $PSScriptRoot $_})
if($LASTEXITCODE -ne 0){throw 'Connector build failed'}
& $csc /nologo /platform:x64 /target:exe /main:GlobalHelper @refs "/out:$root\Connector\HomeRelayGlobal.exe" @common (Join-Path $PSScriptRoot 'GlobalHelper.cs')
if($LASTEXITCODE -ne 0){throw 'Global helper build failed'}
Write-Output 'Built unified connector and optional global helper. No network settings changed.'
