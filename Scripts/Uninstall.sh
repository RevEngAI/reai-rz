#!/bin/bash

InstallPath="${HOME}/.local"
echo "Assuming install path $InstallPath"

# Remove installed headers
sudo rm -rf "$InstallPath/include/Reai"

# Remove installed libraries
sudo rm -rf "$InstallPath/lib/libreai*"

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
