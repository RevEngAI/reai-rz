#!/bin/bash

InstallPath="~/.local"
echo "Assuming install path $InstallPath"

# Remove installed headers
sudo rm -rf "$InstallPath/include/Reai"
sudo rm -rf "$InstallPath/include/cjson"
sudo rm "$InstallPath/include/toml.h"

# Remove installed libraries
sudo rm -rf "$InstallPath/lib/libreai*"
sudo rm -rf "$InstallPath/lib/libcjson*"
sudo rm -rf "$InstallPath/lib/libtoml*"
sudo rm -rf "$InstallPath/lib/cmake/cJSON"

# Remove plugin
OS="$(uname)"
EXTENSION=""
if [[ "$OS" == "Darwin" ]]; then
    EXTENSION="dylib"
elif [[ "$OS" == "Linux" ]]; then
    EXTENSION="so"
fi
sudo rm "$(rizin -H RZ_USER_PLUGINS)/libreai_rizin.$EXTENSION"
sudo rm "$(rizin -H RZ_LIB_PLUGINS)/libreai_rizin.$EXTENSION"
