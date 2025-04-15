# RevEngAI Rizin Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 12/06/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

# Generate command descriptors
add_subdirectory(CmdGen)

# main plugin library and sources
set(ReaiRzPluginSources "Rizin.c" "../Plugin.c" "CmdHandlers.c" "Table.c")

# Libraries needs to be searched here to be linked properly
# Because MSVC obviously
find_package(CURL REQUIRED)
pkg_check_modules(CJSON REQUIRED libcjson)
pkg_check_modules(TOML REQUIRED libtoml)

# Rizin only accepts shared libraries for plugins
add_library(reai_rizin MODULE SHARED ${ReaiRzPluginSources})
target_link_libraries(
  reai_rizin
  PUBLIC
  Rizin::Core
  reai_cmdescs
  reai
  ${CURL_LIBRARIES}
  ${CJSON_LIBRARIES}
  ${TOML_LIBRARIES}
)

# install the built binaries to cutter's plugin directory
install(TARGETS reai_rizin DESTINATION "${RIZIN_INSTALL_PLUGDIR}")
