# RevEngAI Rizin Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 12/06/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

# Generate command descriptors
add_subdirectory(CmdGen)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

find_package(CURL REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_search_module(cJSON REQUIRED libcjson)
pkg_search_module(toml REQUIRED libtoml)
find_package(SQLite3 REQUIRED)

# main plugin library and sources
set(ReaiRzPluginSources "Plugin.c" "CmdHandlers.c")

# Rizin only accepts shared libraries for plugins
add_library(reai_rizin MODULE SHARED ${ReaiRzPluginSources})
target_link_libraries(
  reai_rizin PUBLIC
  Rizin::Core
  reai_cmdescs
  ${CREAIT_LINK_LIBRARIES}
  # CURL::libcurl
  # ${cJSON_LIBRARIES}
  # ${cJSON_LINK_LIBRARIES}
  # ${toml_LIBRARIES}
  # ${SQLite3_LIBRARIES}
)
target_link_directories(
  reai_rizin PUBLIC
  # ${cJSON_LIBRARY_DIRS}
  # ${SQLite3_INCLUDE_DIRS}
)

# install the built binaries to cutter's plugin directory
install(TARGETS reai_rizin DESTINATION "${RIZIN_INSTALL_PLUGDIR}")
