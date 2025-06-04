# RevEngAI Plugin Installer for Windows
# This script installs the plugins and sets up the environment

param(
    [switch]$Help
)

if ($Help) {
    Write-Host "RevEngAI Plugin Installer for Windows"
    Write-Host ""
    Write-Host "Usage: .\install-windows.ps1"
    Write-Host ""
    Write-Host "This script will:"
    Write-Host "  • Install shared libraries to user's local directory"
    Write-Host "  • Install Rizin plugin to appropriate directory"
    Write-Host "  • Install Cutter plugin to appropriate directory"
    Write-Host "  • Set up environment variables"
    exit 0
}

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ArtifactDir = $ScriptDir

Write-Host "=== RevEngAI Plugin Installer for Windows ===" -ForegroundColor Green
Write-Host "Script directory: $ScriptDir"
Write-Host "Artifact directory: $ArtifactDir"

# Detect user's local library directory
$UserLibDir = "$env:USERPROFILE\\.local\\lib"
$UserBinDir = "$env:USERPROFILE\\.local\\bin"
New-Item -ItemType Directory -Force -Path $UserLibDir | Out-Null
New-Item -ItemType Directory -Force -Path $UserBinDir | Out-Null

# Install exact shared libraries from CI artifacts
Write-Host "=== Installing shared libraries ===" -ForegroundColor Yellow

# Install reai.dll to bin directory
$ReaiDllPath = "$ArtifactDir\\reai.dll"
if (Test-Path $ReaiDllPath) {
    Write-Host "Installing: reai.dll -> $UserBinDir\\"
    Copy-Item $ReaiDllPath $UserBinDir\\
    Write-Host "✅ reai.dll installed" -ForegroundColor Green
} else {
    Write-Host "❌ Error: reai.dll not found in artifacts" -ForegroundColor Red
    exit 1
}

# Install reai.lib to lib directory
$ReaiLibPath = "$ArtifactDir\\reai.lib"
if (Test-Path $ReaiLibPath) {
    Write-Host "Installing: reai.lib -> $UserLibDir\\"
    Copy-Item $ReaiLibPath $UserLibDir\\
    Write-Host "✅ reai.lib installed" -ForegroundColor Green
} else {
    Write-Host "❌ Error: reai.lib not found in artifacts" -ForegroundColor Red
    exit 1
}

# Install libcurl.dll to bin directory
$CurlDllPath = "$ArtifactDir\\libcurl.dll"
if (Test-Path $CurlDllPath) {
    Write-Host "Installing: libcurl.dll -> $UserBinDir\\"
    Copy-Item $CurlDllPath $UserBinDir\\
    Write-Host "✅ libcurl.dll installed" -ForegroundColor Green
} else {
    Write-Host "❌ Error: libcurl.dll not found in artifacts" -ForegroundColor Red
    exit 1
}

# Install libcurl_imp.lib to lib directory
$CurlLibPath = "$ArtifactDir\\libcurl_imp.lib"
if (Test-Path $CurlLibPath) {
    Write-Host "Installing: libcurl_imp.lib -> $UserLibDir\\"
    Copy-Item $CurlLibPath $UserLibDir\\
    Write-Host "✅ libcurl_imp.lib installed" -ForegroundColor Green
} else {
    Write-Host "❌ Error: libcurl_imp.lib not found in artifacts" -ForegroundColor Red
    exit 1
}

# Find and install Rizin plugin
Write-Host "=== Installing Rizin plugin ===" -ForegroundColor Yellow
$RizinPlugin = Get-ChildItem -Path $ArtifactDir -Filter "*reai_rizin*.dll" | Select-Object -First 1

if ($RizinPlugin) {
    # Get rizin plugin directory
    try {
        $RizinPluginDir = (rizin -H RZ_USER_PLUGINS).Trim()
        if (-not $RizinPluginDir) {
            throw "Empty plugin directory"
        }
    }
    catch {
        Write-Host "❌ Error: Could not get rizin plugin directory. Is rizin installed?" -ForegroundColor Red
        exit 1
    }
    
    New-Item -ItemType Directory -Force -Path $RizinPluginDir | Out-Null
    
    Write-Host "Installing Rizin plugin: $($RizinPlugin.Name) -> $RizinPluginDir\\"
    Copy-Item $RizinPlugin.FullName $RizinPluginDir\\
    
    Write-Host "✅ Rizin plugin installed" -ForegroundColor Green
}
else {
    Write-Host "❌ Error: Rizin plugin (*reai_rizin*.dll) not found in artifacts" -ForegroundColor Red
    exit 1
}

# Find and install Cutter plugin
Write-Host "=== Installing Cutter plugin ===" -ForegroundColor Yellow
$CutterPlugin = Get-ChildItem -Path $ArtifactDir -Filter "*reai_cutter*.dll" | Select-Object -First 1

if ($CutterPlugin) {
    # Common Cutter plugin directories on Windows
    $CutterPluginDirs = @(
        "$env:APPDATA\\rizin\\cutter\\plugins\\native",
        "$env:LOCALAPPDATA\\rizin\\cutter\\plugins\\native",
        "$env:USERPROFILE\\.local\\share\\rizin\\cutter\\plugins\\native"
    )
    
    # Use first existing directory or create the first one
    $CutterPluginDir = $CutterPluginDirs[0]
    foreach ($dir in $CutterPluginDirs) {
        $parentDir = Split-Path -Parent $dir
        if (Test-Path $parentDir) {
            $CutterPluginDir = $dir
            break
        }
    }
    
    New-Item -ItemType Directory -Force -Path $CutterPluginDir | Out-Null
    
    Write-Host "Installing Cutter plugin: $($CutterPlugin.Name) -> $CutterPluginDir\\"
    Copy-Item $CutterPlugin.FullName $CutterPluginDir\\
    
    Write-Host "✅ Cutter plugin installed" -ForegroundColor Green
}
else {
    Write-Host "❌ Error: Cutter plugin (*reai_cutter*.dll) not found in artifacts" -ForegroundColor Red
    exit 1
}

# Create environment setup script
Write-Host "=== Creating environment setup ===" -ForegroundColor Yellow
$EnvScript = "$UserBinDir\\reai-env.ps1"

$EnvScriptContent = @"
# RevEngAI Environment Setup
# Run this script to set up environment for using RevEngAI plugins

# Add library and binary paths
`$env:PATH = "$UserBinDir;" + `$env:PATH

Write-Host "RevEngAI environment configured" -ForegroundColor Green
Write-Host "Binary path added: $UserBinDir"
"@

$EnvScriptContent | Out-File -FilePath $EnvScript -Encoding UTF8

# Update user PATH permanently
Write-Host "=== Updating system PATH ===" -ForegroundColor Yellow
try {
    $currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    if ($currentPath -notlike "*$UserBinDir*") {
        $newPath = "$UserBinDir;$currentPath"
        [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
        Write-Host "✅ User PATH updated with $UserBinDir" -ForegroundColor Green
    }
    else {
        Write-Host "✅ User PATH already contains $UserBinDir" -ForegroundColor Green
    }
}
catch {
    Write-Host "⚠️  Warning: Could not update system PATH. You may need to add $UserBinDir manually." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🎉 Installation complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📋 Summary:"
Write-Host "  • Shared libraries installed to:"
Write-Host "    - $UserBinDir : reai.dll, libcurl.dll"
Write-Host "    - $UserLibDir : reai.lib, libcurl_imp.lib"
if ($RizinPlugin) {
    Write-Host "  • Rizin plugin installed to: $RizinPluginDir"
}
if ($CutterPlugin) {
    Write-Host "  • Cutter plugin installed to: $CutterPluginDir"
}
Write-Host "  • Environment script created: $EnvScript"
Write-Host ""
Write-Host "🚀 To use the plugins:"
Write-Host "  1. Close and reopen your terminal/PowerShell"
Write-Host "  2. The plugins should work automatically"
Write-Host "  3. If needed, run: $EnvScript""
Write-Host ""