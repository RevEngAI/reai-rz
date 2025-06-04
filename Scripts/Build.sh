#!/bin/bash

branchName=${1:-master}

echo "Building from branch $branchName"

InstallPath="${HOME}/.local"
echo "Dependencies will be installed at prefix $InstallPath"

cd /tmp

mkdir -pv "$InstallPath/lib"
mkdir -pv "$InstallPath/include"

rm -rf /tmp/reai-rz
rm -rf /tmp/creait

git clone -b "$branchName" https://github.com/revengai/reai-rz
git clone https://github.com/revengai/creait

# Build and install creait
cmake -S "/tmp/creait" \
    -B "/tmp/creait/Build" \
    -G Ninja \
    -D CMAKE_BUILD_TYPE=Release \
    -D CMAKE_PREFIX_PATH="$InstallPath" \
    -D CMAKE_INSTALL_PREFIX="$InstallPath"
cmake --build "/tmp/creait/Build" --config Release
cmake --install "/tmp/creait/Build" --prefix "$InstallPath" --config Release

# PyYaml
python3 -m venv venv
source /tmp/venv/bin/activate
python3 -m pip install PyYaml

# Build reai-rz
cmake -S "/tmp/reai-rz" \
    -B "/tmp/reai-rz/Build" \
    -G Ninja \
    -D CMAKE_BUILD_TYPE=Release \
    -D CMAKE_PREFIX_PATH="$InstallPath" \
    -D CMAKE_INSTALL_PREFIX="$InstallPath"
cmake --build "/tmp/reai-rz/Build" --config Release
cmake --install "/tmp/reai-rz/Build" --prefix "$InstallPath" --config Release

deactivate
