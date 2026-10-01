[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [string]$GhidraHome,

    [Parameter(Mandatory)]
    [string]$Source,

    [Parameter(Mandatory)]
    [string]$JavaHome,

    [Parameter(Mandatory)]
    [string]$MavenHome,

    [switch]$Install
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$expectedVersion = '12.1.2'
$expectedCommit = '27f316f80139e2d5dec882519a1bdf4aa46ac04c'
$GhidraHome = (Resolve-Path -LiteralPath $GhidraHome).Path
$Source = (Resolve-Path -LiteralPath $Source).Path
$JavaHome = (Resolve-Path -LiteralPath $JavaHome).Path
$MavenHome = (Resolve-Path -LiteralPath $MavenHome).Path

$applicationProperties = Join-Path $GhidraHome 'Ghidra\application.properties'
$properties = Get-Content -Raw -LiteralPath $applicationProperties
if ($properties -notmatch "(?m)^application\.version=$([regex]::Escape($expectedVersion))$") {
    throw "Expected Ghidra $expectedVersion at $GhidraHome."
}

$revision = (& git -C $Source rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $revision -ne $expectedCommit) {
    throw "GhidraMCP source must be pinned to $expectedCommit; found $revision."
}

$extensionProperties = Join-Path $Source 'src\main\resources\extension.properties'
$moduleManifest = Join-Path $Source 'src\main\resources\Module.manifest'
$pluginSource = Join-Path $Source 'src\main\java\com\lauriewired\GhidraMCPPlugin.java'
$bridge = Join-Path $Source 'bridge_mcp_ghidra.py'
if ((Get-Content -Raw -LiteralPath $extensionProperties) -notmatch "ghidraVersion=$expectedVersion") {
    throw 'Apply assets/ghidra-mcp/GhidraMCP-12.1.2.patch before building.'
}
if ((Get-Item -LiteralPath $moduleManifest).Length -ne 0) {
    throw 'The reviewed Ghidra 12.1.2 Module.manifest must be empty.'
}
if ((Get-Content -Raw -LiteralPath $pluginSource) -notmatch 'InetSocketAddress\("127\.0\.0\.1", port\)') {
    throw 'The reviewed loopback-only plugin patch is missing.'
}
if ((Get-Content -Raw -LiteralPath $pluginSource) -notmatch 'ghidra\.mcp\.token') {
    throw 'The reviewed bearer-token authentication patch is missing.'
}
if ((Get-Content -Raw -LiteralPath $bridge) -notmatch 'def ghidra_health\(') {
    throw 'The reviewed bridge health tool patch is missing.'
}
if ((Get-Content -Raw -LiteralPath $bridge) -notmatch 'def _filter_tools\(' -or
    (Get-Content -Raw -LiteralPath $bridge) -notmatch 'choices=\["current", "read_only", "read_write"\]') {
    throw 'The reviewed Ghidra read-only/read-write tool profile filter is missing.'
}

$jars = [ordered]@{
    'Generic.jar' = 'Ghidra\Framework\Generic\lib\Generic.jar'
    'SoftwareModeling.jar' = 'Ghidra\Framework\SoftwareModeling\lib\SoftwareModeling.jar'
    'Project.jar' = 'Ghidra\Framework\Project\lib\Project.jar'
    'Docking.jar' = 'Ghidra\Framework\Docking\lib\Docking.jar'
    'Decompiler.jar' = 'Ghidra\Features\Decompiler\lib\Decompiler.jar'
    'Utility.jar' = 'Ghidra\Framework\Utility\lib\Utility.jar'
    'Base.jar' = 'Ghidra\Features\Base\lib\Base.jar'
    'Gui.jar' = 'Ghidra\Framework\Gui\lib\Gui.jar'
}
$sourceLib = Join-Path $Source 'lib'
New-Item -ItemType Directory -Force -Path $sourceLib | Out-Null
foreach ($entry in $jars.GetEnumerator()) {
    $jar = Join-Path $GhidraHome $entry.Value
    if (-not (Test-Path -LiteralPath $jar -PathType Leaf)) {
        throw "Missing required Ghidra JAR: $jar"
    }
    Copy-Item -LiteralPath $jar -Destination (Join-Path $sourceLib $entry.Key) -Force
}

$maven = Join-Path $MavenHome 'bin\mvn.cmd'
$java = Join-Path $JavaHome 'bin\java.exe'
if (-not (Test-Path -LiteralPath $maven -PathType Leaf)) { throw "Missing Maven: $maven" }
if (-not (Test-Path -LiteralPath $java -PathType Leaf)) { throw "Missing Java: $java" }

$previousJavaHome = $env:JAVA_HOME
$previousPath = $env:Path
try {
    $env:JAVA_HOME = $JavaHome
    $env:Path = "$JavaHome\bin;$MavenHome\bin;$previousPath"
    & $maven -q -f (Join-Path $Source 'pom.xml') clean package
    if ($LASTEXITCODE -ne 0) { throw "Maven failed with exit code $LASTEXITCODE." }
    $testReport = Join-Path $Source 'target\surefire-reports\com.lauriewired.AppTest.txt'
    if (-not (Test-Path -LiteralPath $testReport -PathType Leaf)) {
        throw 'Maven did not produce the GhidraMCP behavioral test report.'
    }
    $testSummary = Get-Content -Raw -LiteralPath $testReport
    if ($testSummary -notmatch 'Tests run: 1, Failures: 0, Errors: 0') {
        throw "GhidraMCP behavioral auth test did not pass: $testSummary"
    }
}
finally {
    $env:JAVA_HOME = $previousJavaHome
    $env:Path = $previousPath
}

$zip = Join-Path $Source 'target\GhidraMCP-1.0-SNAPSHOT.zip'
$jar = Join-Path $Source 'target\GhidraMCP.jar'
$installed = $false
if ($Install) {
    $extension = Join-Path $GhidraHome 'Ghidra\Extensions\GhidraMCP'
    if ($PSCmdlet.ShouldProcess($extension, 'Install reviewed GhidraMCP extension')) {
        New-Item -ItemType Directory -Force -Path (Join-Path $extension 'lib') | Out-Null
        Copy-Item -LiteralPath $jar -Destination (Join-Path $extension 'lib\GhidraMCP.jar') -Force
        Copy-Item -LiteralPath $extensionProperties -Destination (Join-Path $extension 'extension.properties') -Force
        Copy-Item -LiteralPath $moduleManifest -Destination (Join-Path $extension 'Module.manifest') -Force
        $installed = $true
    }
}

[pscustomobject]@{
    status = 'passed'
    ghidra_version = $expectedVersion
    upstream_commit = $revision
    bridge = $bridge
    zip = $zip
    zip_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $zip).Hash
    jar = $jar
    jar_sha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $jar).Hash
    installed = $installed
} | ConvertTo-Json -Depth 3
