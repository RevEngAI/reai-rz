# File : Installer.ps1
# Description : Powershell script to automatically build and install rizin and cutter plugins
# Date : 8th March 2025
# Author : Siddharth Mishra (admin@brightprogrammer.in)
# Copyright : Copyright (c) 2025 RevEngAI
#
# To execute this script, in a powershell environment run
# Set-ExecutionPolicy Bypass -Scope Process -Force; iex ".\\Scripts\\Build.ps1"
#
# Dependencies
# - MSVC Compiler Toolchain

param(
    [string]$branchName = "master"
)

Write-Host "Building plugin from branch $branchName"

$BaseDir = "$($HOME -replace '\\', '\\')\\.local\\RevEngAI\\Rizin"
$BuildDir = "$BaseDir\\Build"
$InstallPath = "$BaseDir\\Install"
$DownPath = "$BuildDir\\Artifacts"
$DepsPath = "$BuildDir\\Dependencies"

# Remove BaseDir only if it exists
if (Test-Path "$BaseDir") {
    Remove-Item -LiteralPath "$BaseDir" -Force -Recurse 
}

md "$BaseDir"
md "$BuildDir"
md "$InstallPath"
md "$DownPath"
md "$DepsPath"

# Set environment variable for this powershell session
$env:Path = $env:Path + ";$InstallPath;$InstallPath\\bin;$InstallPath\\lib;$DownPath\\aria2c;$DownPath\\7zip"

# x64 Architecture Builds
cmd /c 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'

# Download aria2c for faster download of dependencies
# Invoke-WebRequest performs single threaded downloads and that too at slow speed
Invoke-WebRequest -Uri "https://github.com/aria2/aria2/releases/download/release-1.37.0/aria2-1.37.0-win-64bit-build1.zip" -OutFile "$DownPath\\aria2c.zip"
Expand-Archive -LiteralPath "$DownPath\\aria2c.zip" -DestinationPath "$DownPath\\aria2c"
Move-Item "$DownPath\\aria2c\\aria2-1.37.0-win-64bit-build1\\*" -Destination "$DownPath\\aria2c" -Force
Remove-Item -LiteralPath "$DownPath\\aria2c\\aria2-1.37.0-win-64bit-build1" -Force -Recurse

# Download 7z for faster decompression time. Windows is lightyears behind in their tech.
# Download dependency
aria2c "https://7-zip.org/a/7zr.exe" -j8 -d "$DownPath"
aria2c "https://7-zip.org/a/7z2409-extra.7z" -j8 -d "$DownPath"

# Installing dependency
& "$DownPath\\7zr.exe" x "$DownPath\\7z2409-extra.7z" -o"$DownPath\\7zip"

# Make available a preinstalled dependency for direct use
function Make-Available () {
    param (
        [string]$pkgCmdName,
        [string]$pkgUrl,
        [string]$pkgName,
        [string]$pkgSubfolderName
    )
    
    # Download dependency
    aria2c "$pkgUrl" -j8 -d "$DownPath"
        
    # Installing dependency
    7za x "$DownPath\\$pkgName" -o"$DepsPath\\$pkgCmdName"
    Copy-Item "$DepsPath\\$pkgCmdName\\$pkgSubfolderName\\*" -Destination "$InstallPath\\" -Force -Recurse
    Remove-Item -LiteralPath "$DepsPath\\$pkgCmdName" -Force -Recurse
}

# WARN: Order of execution of these Make-Available commands is really important

# Make Cutter available for use
Make-Available -pkgCmdName "cutter" `
    -pkgUrl "https://github.com/rizinorg/cutter/releases/download/v2.4.1/Cutter-v2.4.1-Windows-x86_64.zip" `
    -pkgName "Cutter-v2.4.1-Windows-x86_64.zip" `
    -pkgSubfolderName "Cutter-v2.4.1-Windows-x86_64"

# Make Cutter Deps available for use
aria2c "https://github.com/rizinorg/cutter-deps/releases/download/v16/cutter-deps-win-x86_64.tar.gz" -j8 -d "$DownPath"

# Installing dependency
tar -xvf "$DownPath\\cutter-deps-win-x86_64.tar.gz" -C "$DownPath"
Copy-Item "$DownPath\\qt\\*" -Destination "$InstallPath\\" -Force -Recurse
Copy-Item "$DownPath\\pyside\\*" -Destination "$InstallPath\\" -Force -Recurse
Remove-Item -LiteralPath "$DownPath\\qt" -Force -Recurse
Remove-Item -LiteralPath "$DownPath\\pyside" -Force -Recurse

# Make pkg-config available for use
Make-Available -pkgCmdName "pkg-config" `
    -pkgUrl "https://cyfuture.dl.sourceforge.net/project/pkgconfiglite/0.28-1/pkg-config-lite-0.28-1_bin-win32.zip?viasf=1" `
    -pkgName "pkg-config-lite-0.28-1_bin-win32.zip" `
    -pkgSubfolderName "pkg-config-lite-0.28-1"

# Make available cmake for use
Make-Available -pkgCmdName "cmake" `
    -pkgUrl "https://github.com/Kitware/CMake/releases/download/v4.0.0-rc5/cmake-4.0.0-rc5-windows-x86_64.zip" `
    -pkgName "cmake-4.0.0-rc5-windows-x86_64.zip" `
    -pkgSubfolderName "cmake-4.0.0-rc5-windows-x86_64"
    
# Make available ninja for use
Make-Available -pkgCmdName "ninja" `
    -pkgUrl "https://github.com/ninja-build/ninja/releases/download/v1.12.1/ninja-win.zip" `
    -pkgName "ninja-win.zip" `
    -pkgSubfolderName "\\"

Write-Host "All system dependencies are satisfied."    
Write-Host "Now fetching plugin dependencies, and then building and installing these..."
    
# === 1. Download and extract curl ===
aria2c "https://curl.se/download/curl-8.13.0.zip" -d "$DownPath" -o "curl-8.13.0.zip" -j 8
$curlZipPath = "$DownPath\\curl-8.13.0.zip"
$curlSubfolder = "curl-8.13.0"
$curlInstallDir = "$DepsPath\\curl"

Write-Host "Extracting curl from $curlZipPath to $curlInstallDir..."
7za x "$curlZipPath" -o"$curlInstallDir"
Copy-Item "$curlInstallDir\\$curlSubfolder\\*" -Destination "$curlInstallDir\\" -Force -Recurse
Remove-Item "$curlInstallDir\\$curlSubfolder" -Force -Recurse

# === 2. Clone reai-rz ===
$reaiRzDir = "$DepsPath\\reai-rz"
Write-Host "Cloning reai-rz into $reaiRzDir..."
git clone --depth=1 --branch $branchName https://github.com/RevEngAI/reai-rz.git $reaiRzDir
if ($LASTEXITCODE -ne 0) {
    throw "Failed to clone reai-rz"
}

# === 3. Clone creait ===
$creaitDir = "$DepsPath\\creait"
Write-Host "Cloning creait into $creaitDir..."
git clone --depth=1 --branch master https://github.com/RevEngAI/creait.git $creaitDir
if ($LASTEXITCODE -ne 0) {
    throw "Failed to clone creait"
}

# Build and install libCURL
Write-Host Build" & INSTALL libCURL..."
cmake -S "$DepsPath\\curl" -A x64 `
    -B "$DepsPath\\curl\\Build" `
    -G "Visual Studio 17 2022" `
    -D CURL_ZLIB=OFF `
    -D CURL_ZSTD=OFF `
    -D USE_NGHTTP2=OFF `
    -D USE_LIBIDN2=OFF `
    -D CURL_BROTLI=OFF `
    -D CURL_USE_LIBPSL=OFF `
    -D CMAKE_PREFIX_PATH="$InstallPath" `
    -D CMAKE_INSTALL_PREFIX="$InstallPath" `
    -D CURL_USE_SCHANNEL=ON
cmake --build "$DepsPath\\curl\\Build" --config Release
cmake --install "$DepsPath\\curl\\Build" --prefix "$InstallPath" --config Release
Write-Host Build" & INSTALL libCURL... DONE"

# Build and install creait
Write-Host Build" & INSTALL creait..."
cmake -S "$DepsPath\\creait" -A x64 `
    -B "$DepsPath\\creait\\Build" `
    -G "Visual Studio 17 2022" `
    -D CMAKE_PREFIX_PATH="$InstallPath" `
    -D CMAKE_INSTALL_PREFIX="$InstallPath"
cmake --build "$DepsPath\\creait\\Build" --config Release
cmake --install "$DepsPath\\creait\\Build" --prefix "$InstallPath" --config Release
Write-Host Build" & INSTALL creait... DONE"


# Set up Python virtual environment for build dependencies
Write-Host "Setting up Python virtual environment..."
python -m venv "$BaseDir\\.venv"

# Activate virtual environment
& "$BaseDir\\.venv\\Scripts\\Activate.ps1"

# Install Python dependencies
Write-Host "Installing Python dependencies..."
python -m pip install --upgrade pip
python -m pip install pyyaml

# Verify PyYAML is available
python -c "import yaml; print('PyYAML is available in virtual environment')"

Write-Host "Python environment setup complete."


# Build reai-rz
cmake -S "$DepsPath\\reai-rz" -A x64 `
    -B "$DepsPath\\reai-rz\\Build" `
    -G "Visual Studio 17 2022" `
    -D CMAKE_MODULE_PATH="$InstallPath\\lib\\cmake\\Modules" `
    -D Rizin_DIR="$InstallPath\\lib\\cmake\\Rizin" `
    -D Cutter_DIR="$InstallPath\\lib\\cmake\\Cutter" `
    -D Qt5_DIR="$InstallPath\\lib\\cmake\\Qt5" `
    -D CMAKE_PREFIX_PATH="$InstallPath" `
    -D CMAKE_INSTALL_PREFIX="$InstallPath" `
    -D BUILD_CUTTER_PLUGIN=ON `
    -D CUTTER_USE_QT6=ON `
    -D CMAKE_C_FLAGS="/TC /I$InstallPath\\include" `
    -D CMAKE_CXX_FLAGS="/TC /I$InstallPath\\include" `
    -D Python3_EXECUTABLE="$BaseDir\\.venv\\Scripts\\python.exe"

cmake --build "$DepsPath\\reai-rz\\Build" --config Release
cmake --install "$DepsPath\\reai-rz\\Build" --prefix "$InstallPath" --config Release
Write-Host Build" & INSTALL reai-rz... DONE"

# Remove build artifacts
Remove-Item -Recurse -Force "$BuildDir"

# Set environment variables permanently across machine for all users
Write-Host "Installation complete! Enjoy using the plugins ;-)"
Write-Host "Contact the developers through issues or discussions in https://github.com/revengai/reai-rz"

Write-Host "`rUpdate your environment variable by adding these paths to your `$env:Path : `n$InstallPath;`n$InstallPath\\bin;`n$InstallPath\\lib;"
