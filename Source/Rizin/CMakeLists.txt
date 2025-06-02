# RevEngAI Rizin Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 12/06/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

# Generate command descriptors
add_subdirectory(CmdGen)

# main plugin library and sources
set(ReaiRzPluginSources "Rizin.c" "../Plugin.c" "CmdHandlers.c")

# Libraries needs to be searched here to be linked properly
# Because MSVC obviously
find_package(CURL REQUIRED)
find_package(Creait REQUIRED)

# Rizin only accepts shared libraries for plugins
add_library(reai_rizin MODULE SHARED ${ReaiRzPluginSources})
target_include_directories(reai_rizin PUBLIC ${CREAIT_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS})
target_link_libraries(
  reai_rizin
  PUBLIC
  Rizin::Core
  reai_cmdescs
  ${CREAIT_LIBRARIES}
  ${CURL_LIBRARIES}
)
set_target_properties(
    reai_rizin PROPERTIES
    INSTALL_RPATH "$ENV{HOME}/.local/lib"
    BUILD_RPATH "${CMAKE_BINARY_DIR}/Source/Rizin"
)

# install the built binaries to cutter's plugin directory
install(TARGETS reai_rizin DESTINATION "${RIZIN_INSTALL_PLUGDIR}")
