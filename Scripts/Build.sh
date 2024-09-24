#!/usr/bin/env sh

cmake -G Ninja -B Build -D AUTOINSTALL_REQUIRED=OFF -D BUILD_RIZIN_PLUGIN_ONLY=OFF -D CMAKE_BUILD_TYPE=Debug -D CMAKE_INSTALL_PREFIX=/usr/local
ninja -C Build
