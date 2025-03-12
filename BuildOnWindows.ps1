# File : Installer.ps1
# Description : Powershell script to automatically build and install rizin and cutter plugins
# Date : 8th March 2025
# Author : Siddharth Mishra (admin@brightprogrammer.in)
# Copyright : Copyright (c) 2025 RevEngAI
#
# To execute this script in a powershell environment, run
# Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex .\BuildOnWindows.ps1 

$BuildDir = "BuildFiles"
$DownPath = "$PWD\$BuildDir\Artifacts"
$DepsPath = "$PWD\$BuildDir\Dependencies"

# Setup build directory structure
if ((Test-Path "$BuildDir")) {
    Remove-Item -LiteralPath "$BuildDir" -Force -Recurse
}

md "$BuildDir"
md "$DownPath"
md "$DepsPath"

# Download aria2c for faster download of dependencies
# Invoke-WebRequest performs single threaded downloads and that too at slow speed
Invoke-WebRequest -Uri "https://github.com/aria2/aria2/releases/download/release-1.37.0/aria2-1.37.0-win-64bit-build1.zip" -OutFile "$DownPath/aria2c.zip"
Expand-Archive -LiteralPath "$DownPath/aria2c.zip" -DestinationPath "$DepsPath/aria2c"
Move-Item "$DepsPath/aria2c/aria2-1.37.0-win-64bit-build1/*" -Destination "$DepsPath/aria2c" -Force
Remove-Item -LiteralPath "$DepsPath/aria2c/aria2-1.37.0-win-64bit-build1" -Force -Recurse
$env:Path = "$DepsPath/aria2c;" + $env:Path

# Setup a list of files to be downloaded
$DepsList = @"

https://github.com/brechtsanders/winlibs_mingw/releases/download/14.2.0posix-12.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-14.2.0-mingw-w64ucrt-12.0.0-r3.zip
https://cyfuture.dl.sourceforge.net/project/pkgconfiglite/0.28-1/pkg-config-lite-0.28-1_bin-win32.zip?viasf=1
https://curl.se/windows/dl-8.12.1_4/curl-8.12.1_4-win64-mingw.zip
https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.18.zip
https://github.com/brightprogrammer/tomlc99/archive/refs/tags/v1.zip
https://github.com/RevEngAI/creait/archive/refs/heads/master.zip
https://github.com/RevEngAI/reai-rz/archive/refs/heads/master.zip
https://github.com/rizinorg/rizin/releases/download/v0.7.4/rizin-windows-shared64-v0.7.4.zip
https://github.com/rizinorg/cutter/releases/download/v2.3.4/Cutter-v2.3.4-Windows-x86_64.zip
"@

# Dump URL List to a text file for aria2c to use
$DepsList | Out-File -FilePath "$BuildDir\DependenciesList.txt" -Encoding utf8 -Force

# Download artifacts
# List of files to download with URLs and destination paths
aria2c -i "$BuildDir\DependenciesList.txt" -j8 -d "$DownPath"

# Install dependencies
# Dependency package names, archives, and subfolders to extract from
$pkgs = @(
    @{name = "pkg-config"; path="$DownPath\pkg-config-lite-0.28-1_bin-win32.zip"; subfolderName="pkg-config-lite-0.28-1"},
    @{name = "reai-rz"; path = "$DownPath\reai-rz-master.zip"; subfolderName="reai-rz-master"},
    @{name = "tomlc99"; path = "$DownPath\tomlc99-1.zip"; subfolderName="tomlc99-1"},
    @{name = "creait"; path = "$DownPath\creait-master.zip"; subfolderName="creait-master"},
    @{name = "cjson"; path = "$DownPath\cJSON-1.7.18.zip"; subfolderName="cJSON-1.7.18"},
    @{name = "curl"; path = "$DownPath\curl-8.12.1_4-win64-mingw.zip"; subfolderName="curl-8.12.1_4-win64-mingw"},
    @{name = "rizin"; path = "$DownPath\rizin-windows-shared64-v0.7.4.zip"; subfolderName="rizin-win-installer-clang_cl-64"},
    @{name = "cutter"; path = "$DownPath\Cutter-v2.3.4-Windows-x86_64.zip"; subfolderName="Cutter-v2.3.4-Windows-x86_64"},
    @{name = "mingw-gcc"; path = "$DownPath\winlibs-x86_64-posix-seh-gcc-14.2.0-mingw-w64ucrt-12.0.0-r3.zip"; subfolderName="mingw64"}
)

function Install-Dependency {
      param ([string]$packageName, [string]$packagePath, [string]$subfolderName)
      $packageInstallDir = "$DepsPath\$packageName"
      Write-Host "Installing dependency $packagePath to $packageInstallDir..."
      Expand-Archive -LiteralPath "$packagePath" -DestinationPath "$packageInstallDir"
      Move-Item "$packageInstallDir\$subfolderName\*" -Destination "$packageInstallDir\" -Force
      Remove-Item -LiteralPath "$packageInstallDir\$subfolderName" -Force -Recurse
}

foreach ($pkg in $pkgs) {
    Write-Host "Extracting $($pkg.name)"        
    Install-Dependency -packageName $pkg.name -packagePath $pkg.path -subfolderName $pkg.subfolderName
}

$env:Path = "$DepsPath\cjson\Build\bin;" + $env:Path
$env:Path = "$DepsPath\creait\Build\bin;" + $env:Path
$env:Path = "$DepsPath\curl\bin;" + $env:Path
$env:Path = "$DepsPath\cutter\bin;" + $env:Path
$env:Path = "$DepsPath\mingw-gcc\bin;" + $env:Path
$env:Path = "$DepsPath\pkgconfiglite\bin;" + $env:Path
$env:Path = "$DepsPath\reai-rz\Build\bin;" + $env:Path
$env:Path = "$DepsPath\rizin\bin;" + $env:Path
$env:Path = "$DepsPath\tomlc99\Build\bin;" + $env:Path

Write-Host "All dependencies have been installed successfully."

# Prepare creait 
# Build and install cjson
Write-Host "BUILD & INSTALL cJSON..."
$CjsonDir = "$DepsPath\cjson"
$CjsonBuildDir = "$CjsonDir\Build"
cmake -S "$CjsonDir" -B "$CjsonBuildDir" -G Ninja -D CMAKE_C_STANDARD=99 -D ENABLE_CUSTOM_COMPILER_FLAGS=OFF
ninja -C "$CjsonBuildDir"
Write-Host "BUILD & INSTALL cJSON... DONE"

# Build and install tomlc99 
Write-Host "BUILD & INSTALL tomlc99..."
$TomlDir = "$DepsPath\tomlc99"
$TomlBuildDir = "$TomlDir\Build"
cmake -S "$TomlDir" -B "$TomlBuildDir" -G Ninja -D CMAKE_C_STANDARD=23
ninja -C "$TomlBuildDir"
Write-Host "BUILD & INSTALL tomlc99... DONE"

# Build and install creait
Write-Host "BUILD & INSTALL creait..."
$CreaitDir = "$DepsPath\creait"
$CreaitBuildDir = "$CreaitDir\Build"

# Create Directory Structure
Write-Host "SETUP DIRECTORIES..."
md "$CreaitBuildDir"
md "$CreaitBuildDir\lib"
md "$CreaitBuildDir\Artifacts"
md "$CreaitBuildDir\Artifacts\Api"
Write-Host "SETUP DIRECTORIES... DONE"

# Build OBJ Files
Write-Host "COMPILING SOURCES..."
gcc -o "$CreaitBuildDir\Artifacts\AnalysisInfo.obj" -c "$CreaitDir\Source\Reai\AnalysisInfo.c"  -I "$DepsPath\creait\Include" "-Wl,rpath=$CreaitBuildDir\lib"
gcc -o "$CreaitBuildDir\Artifacts\AnnFnMatch.obj" -c "$CreaitDir\Source\Reai\AnnFnMatch.c" -I "$DepsPath\creait\Include" "-Wl,rpath=$CreaitBuildDir\lib"
gcc -o "$CreaitBuildDir\Artifacts\ApiError.obj" -c "$CreaitDir\Source\Reai\ApiError.c" -I "$DepsPath\creait\Include" "-Wl,rpath=$CreaitBuildDir\lib"
gcc -o "$CreaitBuildDir\Artifacts\Config.obj" -c "$CreaitDir\Source\Reai\Config.c" -I "$DepsPath\creait\Include" -I "$DepsPath\tomlc99" "-Wl,rpath=$CreaitBuildDir\lib"
gcc -o "$CreaitBuildDir\Artifacts\FnInfo.obj" -c "$CreaitDir\Source\Reai\FnInfo.c" -I "$DepsPath\creait\Include" "-Wl,rpath=$CreaitBuildDir\lib"
gcc -o "$CreaitBuildDir\Artifacts\Log.obj" -c "$CreaitDir\Source\Reai\Log.c" -I "$DepsPath\creait\Include" "-Wl,rpath=$CreaitBuildDir\lib"
gcc -o "$CreaitBuildDir\Artifacts\QueryResult.obj" -c "$CreaitDir\Source\Reai\QueryResult.c" -I "$DepsPath\creait\Include" "-Wl,rpath=$CreaitBuildDir\lib"
gcc -o "$CreaitBuildDir\Artifacts\Api\Reai.obj" -c "$CreaitDir\Source\Reai\Api\Reai.c"  -I "$DepsPath\creait\Include" -I "$DepsPath\curl\include" -L "$DepsPath\curl\lib" -lcurl "-Wl,rpath=$CreaitBuildDir\lib"
gcc -o "$CreaitBuildDir\Artifacts\Api\Request.obj" -c "$CreaitDir\Source\Reai\Api\Request.c" -I "$DepsPath\creait\Include" -I "$DepsPath\cjson" "-Wl,rpath=$CreaitBuildDir\lib"
gcc -o "$CreaitBuildDir\Artifacts\Api\Response.obj" -c "$CreaitDir\Source\Reai\Api\Response.c" -I "$DepsPath\creait\Include" -I "$DepsPath\cjson" "-Wl,rpath=$CreaitBuildDir\lib"
Write-Host "COMPILING SOURCES... DONE"

Write-Host "LINKING DLL..."

gcc -shared -o "$CreaitBuildDir\lib\libreai.dll" `
  "$CreaitBuildDir\Artifacts\AnalysisInfo.obj" `
  "$CreaitBuildDir\Artifacts\AnnFnMatch.obj" `
  "$CreaitBuildDir\Artifacts\ApiError.obj" `
  "$CreaitBuildDir\Artifacts\Config.obj" `
  "$CreaitBuildDir\Artifacts\FnInfo.obj" `
  "$CreaitBuildDir\Artifacts\Log.obj" `
  "$CreaitBuildDir\Artifacts\QueryResult.obj" `
  "$CreaitBuildDir\Artifacts\Api\Reai.obj" `
  "$CreaitBuildDir\Artifacts\Api\Request.obj" `
  "$CreaitBuildDir\Artifacts\Api\Response.obj" `
  -L "$DepsPath\cjson\Build" `
  -L "$DepsPath\tomlc99\Build\lib" `
  -L "$DepsPath\curl\lib" `
  -lcurl -lcjson -ltoml

Write-Host "LINKING DLL... DONE"
Write-Host "BUILD & INSTALL creait... DONE"

# Build reai-rz
cmake -S "$DepsPath\reai-rz" `
    -B "$DepsPath\reai-rz\Build" `
    -G Ninja `
    -D CMAKE_C_FLAGS="-L $DepsPath\curl\lib -L $DepsPath\cjson\Build -L $DepsPath\tomlc99\Build\lib -L $DepsPath\creait\Build\lib -I $DepsPath\creait\Include"
ninja -C "$DepsPath\reai-rz\Build"
 
$RzPluginsPath = rizin -H RZ_USER_PLUGINS
Remove-Item -LiteralPath "$RzPluginsPath" -Force -Recurse
md "$RzPluginsPath"
cp "$DepsPath\reai-rz\Build\Source\Rizin\libreai_rizin.dll" "$RzPluginsPath"
