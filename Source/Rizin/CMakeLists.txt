# RevEngAI Rizin Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 12/06/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

# Generate command descriptors
add_subdirectory(CmdGen)

find_package(CURL REQUIRED)
find_package(SQLite3 REQUIRED)

# main plugin library and sources
set(ReaiRzPluginSources "Rizin.c" "../Plugin.c" "CmdHandlers.c")

# Rizin only accepts shared libraries for plugins
add_library(reai_rizin MODULE SHARED ${ReaiRzPluginSources})
target_link_libraries(
  reai_rizin PUBLIC
  Rizin::Core
  reai_cmdescs
  reai
  cjson
  toml
  CURL::libcurl
  SQLite::SQLite3
)
target_link_directories(
  reai_rizin PUBLIC
)

# install the built binaries to cutter's plugin directory
install(TARGETS reai_rizin DESTINATION "${RIZIN_INSTALL_PLUGDIR}")
