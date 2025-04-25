#!/bin/bash

InstallPath="~/.local"
echo "Dependencies will be installed at prefix $InstallPath"

cd /tmp

rm -rf /tmp/reai-rz
rm -rf /tmp/creait
rm -rf /tmp/tomlc99
rm -rf /tmp/cJSON

git clone https://github.com/revengai/reai-rz
git clone https://github.com/revengai/creait
git clone https://github.com/brightprogrammer/tomlc99
git clone https://github.com/DaveGamble/cJSON

# Build and install cjson
cmake -S "/tmp/cjson" \
    -B "/tmp/cjson/Build" \
    -D ENABLE_CUSTOM_COMPILER_FLAGS=OFF \
    -D CMAKE_PREFIX_PATH="$InstallPath" \
    -D CMAKE_INSTALL_PREFIX="$InstallPath" \
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
cmake --build "/tmp/cjson/Build" --config Release
sudo cmake --install "/tmp/cjson/Build" --prefix "$InstallPath" --config Release

# Build and install tomlc99 
cmake -S "/tmp/tomlc99" \
    -B "/tmp/tomlc99/Build" \
    -D CMAKE_PREFIX_PATH="$InstallPath" \
    -D CMAKE_INSTALL_PREFIX="$InstallPath" \
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
cmake --build "/tmp/tomlc99/Build" --config Release
sudo cmake --install "/tmp/tomlc99/Build" --prefix "$InstallPath" --config Release

# Build and install creait
cmake -S "/tmp/creait" \
    -B "/tmp/creait/Build" \
    -D CMAKE_PREFIX_PATH="$InstallPath" \
    -D CMAKE_INSTALL_PREFIX="$InstallPath" \
    -D BUILD_SHARED_LIBS=OFF \
    -DCMAKE_POLICY_VERSION_MINIMUM="3.5"
cmake --build "/tmp/creait/Build" --config Release
sudo cmake --install "/tmp/creait/Build" --prefix "$InstallPath" --config Release

# Build reai-rz
cmake -S "/tmp/reai-rz" \
    -B "/tmp/reai-rz/Build" \
    -D CMAKE_PREFIX_PATH="$InstallPath" \
    -D CMAKE_INSTALL_PREFIX="$InstallPath" \
    -D CMAKE_POLICY_VERSION_MINIMUM="3.5"
cmake --build "/tmp/reai-rz/Build" --config Release
sudo cmake --install "/tmp/reai-rz/Build" --prefix "$InstallPath" --config Release

sudo chown -R $USER "$(rizin -H RZ_USER_PLUGINS)/libreai_rizin.dylib" 
