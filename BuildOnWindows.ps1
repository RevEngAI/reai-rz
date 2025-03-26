# File : Installer.ps1
# Description : Powershell script to automatically build and install rizin and cutter plugins
# Date : 8th March 2025
# Author : Siddharth Mishra (admin@brightprogrammer.in)
# Copyright : Copyright (c) 2025 RevEngAI
#
# To execute this script, in a powershell environment run
# Set-ExecutionPolicy Bypass -Scope Process -Force; iex ".\\Installer.ps1 -buildType RelWithDebInfo"
#
# Dependencies
# - Ninja
# - CMake

param (
	[string]$buildType = "Release"
)

Write-Host "Build type is $buildType"

# Escape backslashes becuase Windows is idiot af
$CWD = $PWD.Path -replace '\\', '\\'

$BuildDir = "BuildFiles"
$DownPath = "$CWD\\$BuildDir\\Artifacts"
$DepsPath = "$CWD\\$BuildDir\\Dependencies"
$InstallPath = "$CWD\\RevEngAI"

# Remove install directory if already exists to avoid clashes
if ((Test-Path "$InstallPath")) {
    Remove-Item -LiteralPath "$InstallPath" -Force -Recurse
}

# Setup build directory structure
if ((Test-Path "$BuildDir")) {
    Remove-Item -LiteralPath "$BuildDir" -Force -Recurse
}

md "$BuildDir"
md "$DownPath"
md "$DepsPath"
md "$InstallPath"


# Set environment variable for this powershell session
$env:Path = "$InstallPath;$InstallPath\\bin;$InstallPath\\lib;$DepsPath\\aria2c;" + $env:Path

# Download aria2c for faster download of dependencies
# Invoke-WebRequest performs single threaded downloads and that too at slow speed
Invoke-WebRequest -Uri "https://github.com/aria2/aria2/releases/download/release-1.37.0/aria2-1.37.0-win-64bit-build1.zip" -OutFile "$DownPath\\aria2c.zip"
Expand-Archive -LiteralPath "$DownPath\\aria2c.zip" -DestinationPath "$DepsPath\\aria2c"
Move-Item "$DepsPath\\aria2c\\aria2-1.37.0-win-64bit-build1\\*" -Destination "$DepsPath\\aria2c" -Force
Remove-Item -LiteralPath "$DepsPath\\aria2c\\aria2-1.37.0-win-64bit-build1" -Force -Recurse

# Make available a preinstalled dependency for direct use
function Make-Available () {
	param (
		[string]$pkgCmdName,
		[string]$pkgUrl,
		[string]$pkgName,
		[string]$pkgSubfolderName
	)
	
	Write-Host "Checking if $pkgCmdName is already installed..."

	# Check if command is available in the system PATH
	$pkgIsAvailable = Get-Command $pkgCmdName -ErrorAction SilentlyContinue
	if ($pkgIsAvailable) {
		Write-Host "$pkgCmdName is already installed. Skipping..."
	} else {
		# Download dependency
		Write-Host "$pkgCmdName is not installed. Fetching..."
		aria2c "$pkgUrl" -j8 -d "$DownPath"
		Write-Host "$pkgCmdName is not installed. Fetching... DONE"
		
		# Installing dependency
		Write-Host "Installing $pkgCmdName..."
		$pkgInstallDir = "$InstallPath\\$pkgCmdName"
		Write-Host "Installing dependency $pkgPath to $packageInstallDir..."
		Expand-Archive -LiteralPath "$DownPath\\$pkgName" -DestinationPath "$DepsPath\\$pkgCmdName"
		Copy-Item "$DepsPath\\$pkgCmdName\\$pkgSubfolderName\\*" -Destination "$InstallPath\\" -Force -Recurse
		Remove-Item -LiteralPath "$DepsPath\\$pkgCmdName" -Force -Recurse
		Write-Host "Installing $pkgCmdName... DONE"
	}
}

# WARN: Order of execution of these Make-Available commands is really important

# Make Cutter available for use
Make-Available -pkgCmdName "cutter" `
    -pkgUrl "https://github.com/rizinorg/cutter/releases/download/v2.3.4/Cutter-v2.3.4-Windows-x86_64.zip" `
    -pkgName "Cutter-v2.3.4-Windows-x86_64.zip" `
    -pkgSubfolderName "Cutter-v2.3.4-Windows-x86_64"

# Make GCC available for use
Make-Available -pkgCmdName "gcc" `
	-pkgUrl "https://github.com/brechtsanders/winlibs_mingw/releases/download/14.2.0posix-12.0.0-ucrt-r3/winlibs-x86_64-posix-seh-gcc-14.2.0-mingw-w64ucrt-12.0.0-r3.zip" `
	-pkgName "winlibs-x86_64-posix-seh-gcc-14.2.0-mingw-w64ucrt-12.0.0-r3.zip" `
	-pkgSubfolderName "mingw64"
	
# Make pkg-config available for use
Make-Available -pkgCmdName "pkg-config" `
    -pkgUrl "https://cyfuture.dl.sourceforge.net/project/pkgconfiglite/0.28-1/pkg-config-lite-0.28-1_bin-win32.zip?viasf=1" `
    -pkgName "pkg-config-lite-0.28-1_bin-win32.zip" `
    -pkgSubfolderName "pkg-config-lite-0.28-1"

# Make curl available for use
Make-Available -pkgCmdName "curl-x64" `
    -pkgUrl "https://curl.se/windows/dl-8.12.1_4/curl-8.12.1_4-win64-mingw.zip" `
    -pkgName "curl-8.12.1_4-win64-mingw.zip" `
    -pkgSubfolderName "curl-8.12.1_4-win64-mingw"
	
# Make available rizin for use
Make-Available -pkgCmdName "rizin" `
    -pkgUrl "https://github.com/rizinorg/rizin/releases/download/v0.7.4/rizin-windows-shared64-v0.7.4.zip" `
    -pkgName "rizin-windows-shared64-v0.7.4.zip" `
    -pkgSubfolderName "rizin-win-installer-clang_cl-64"

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



	
# Setup a list of files to be downloaded
$DepsList = @"

https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.18.zip
https://github.com/brightprogrammer/tomlc99/archive/refs/tags/v1.zip
https://github.com/RevEngAI/creait/archive/refs/heads/master.zip
https://github.com/RevEngAI/reai-rz/archive/refs/heads/master.zip
"@

# Dump URL List to a text file for aria2c to use
$DepsList | Out-File -FilePath "$BuildDir\\DependenciesList.txt" -Encoding utf8 -Force

# Download artifacts
# List of files to download with URLs and destination paths
aria2c -i "$BuildDir\\DependenciesList.txt" -j8 -d "$DownPath"

# These dependencies need to be built on the host machine, unlike installing the pre-compiled binaries above
$pkgs = @(
    @{name = "reai-rz"; path = "$DownPath\\reai-rz-master.zip"; subfolderName="reai-rz-master"},
    @{name = "tomlc99"; path = "$DownPath\\tomlc99-1.zip"; subfolderName="tomlc99-1"},
    @{name = "creait"; path = "$DownPath\\creait-master.zip"; subfolderName="creait-master"},
    @{name = "cjson"; path = "$DownPath\\cJSON-1.7.18.zip"; subfolderName="cJSON-1.7.18"}
)
# Unpack a dependency to be built later on
# These temporarily go into dependencies directory
function Unpack-Dependency {
      param ([string]$packageName, [string]$packagePath, [string]$subfolderName)
      $packageInstallDir = "$DepsPath\\$packageName"
      Write-Host "Installing dependency $packagePath to $packageInstallDir..."
      Expand-Archive -LiteralPath "$packagePath" -DestinationPath "$packageInstallDir"
      Move-Item "$packageInstallDir\\$subfolderName\\*" -Destination "$packageInstallDir\\" -Force
      Remove-Item -LiteralPath "$packageInstallDir\\$subfolderName" -Force -Recurse
}

foreach ($pkg in $pkgs) {
    Write-Host "Extracting $($pkg.name)"        
    Unpack-Dependency -packageName $pkg.name -packagePath $pkg.path -subfolderName $pkg.subfolderName
}

# Prepare creait 
# Build and install cjson
Write-Host "BUILD & INSTALL cJSON..."
cmake -S "$DepsPath\\cjson" `
	-B "$DepsPath\\cjson\\Build" `
	-G Ninja `
	-D CMAKE_BUILD_TYPE=$buildType `
	-D CMAKE_C_STANDARD=99 `
	-D ENABLE_CUSTOM_COMPILER_FLAGS=OFF `
	-D CMAKE_PREFIX_PATH="$InstallPath" `
	-D CMAKE_INSTALL_PREFIX="$InstallPath"
ninja -C "$DepsPath\\cjson\\Build" install
Write-Host "BUILD & INSTALL cJSON... DONE"

# Build and install tomlc99 
Write-Host "BUILD & INSTALL tomlc99..."
cmake -S "$DepsPath\\tomlc99" `
	-B "$DepsPath\\tomlc99\\Build" `
	-G Ninja `
	-D CMAKE_BUILD_TYPE=$buildType `
	-D CMAKE_C_STANDARD=23 `
	-D CMAKE_PREFIX_PATH="$InstallPath" `
	-D CMAKE_INSTALL_PREFIX="$InstallPath"
ninja -C "$DepsPath\\tomlc99\\Build" install
Write-Host "BUILD & INSTALL tomlc99... DONE"

# Build and install creait
Write-Host "BUILD & INSTALL creait..."
cmake -S "$DepsPath\\creait" `
	-B "$DepsPath\\creait\\Build" `
	-G Ninja `
	-D CMAKE_BUILD_TYPE=$buildType `
	-D CMAKE_PREFIX_PATH="$InstallPath" `
	-D CMAKE_INSTALL_PREFIX="$InstallPath" `
	-D CMAKE_C_FLAGS="-L$InstallPath\\lib -I$InstallPath\\include -L$InstallPath\bin -lcurl-x64"
ninja -C "$DepsPath\\creait\\Build" install
Write-Host "BUILD & INSTALL creait... DONE"

# Build reai-rz
cmake -S "$DepsPath\\reai-rz" `
    -B "$DepsPath\\reai-rz\\Build" `
    -G Ninja `
	-D CMAKE_BUILD_TYPE=$buildType `
	-D Rizin_DIR="$InstallPath\\lib\\cmake\\Rizin" `
	-D Cutter_DIR="$InstallPath\\lib\\cmake\\Cutter" `
	-D CMAKE_PREFIX_PATH="$InstallPath" `
	-D CMAKE_INSTALL_PREFIX="$InstallPath" `
	-D CMAKE_C_FLAGS="-L$InstallPath\\lib -I$InstallPath\\include -L$InstallPath\bin -lcurl-x64"
ninja -C "$DepsPath\\reai-rz\\Build" install
Write-Host "BUILD & INSTALL reai-rz... DONE"

# Set environment variables permanently across machine for all users
Write-Host "Updating environment variable for all users..."
[Environment]::SetEnvironmentVariable("Path",  $env:Path, [System.EnvironmentVariableTarget]::User)
Write-Host "Updating environment variable for all users... DONE"

# Removing artifacts
Write-Host "Removing build files..."
Remove-Item -LiteralPath "$DepsPath" -Force -Recurse
Remove-Item -LiteralPath "$DownPath" -Force -Recurse
Remove-Item -LiteralPath "$BuildDir\\DependenciesList.txt" -Force -Recurse
Write-Host "Removing build files... DONE"

Write-Host "Installation complete! Enjoy using the plugins ;-)"
Write-Host "Contact the developers through issues or discussions in https://github.com/revengai/reai-rz"
