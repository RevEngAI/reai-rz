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
    BUILD_RPATH "${CMAKE_BINARY_DIR}/Source/Rizin"
)

# Set platform-specific INSTALL_RPATH
if(APPLE)
    # macOS: @loader_path is relative to the plugin location
    # Plugin is at: ~/.local/lib/rizin/plugins/plugin.dylib
    # Libraries at: ~/.local/lib/librz_*.dylib
    # For development builds: $ENV{HOME} expands correctly at build time
    # For CI builds: install script will fix rpath at installation time
    set_target_properties(reai_rizin PROPERTIES
        INSTALL_RPATH "@loader_path;@loader_path/../lib;@loader_path/../../../lib;@rpath;$ENV{HOME}/.local/lib;/usr/local/lib;/opt/homebrew/lib;/usr/lib;/lib"
    )
elseif(UNIX)
    # Linux: $ORIGIN is relative to the plugin location  
    set_target_properties(reai_rizin PROPERTIES
        INSTALL_RPATH "$ORIGIN:$ORIGIN/../lib:$ORIGIN/../../../lib:$ENV{HOME}/.local/lib:/usr/local/lib:/usr/lib:/lib"
    )
endif()
# Windows: No rpath needed, DLLs are found via PATH or same directory

# install the built binaries to cutter's plugin directory
install(TARGETS reai_rizin DESTINATION "${RIZIN_INSTALL_PLUGDIR}")
