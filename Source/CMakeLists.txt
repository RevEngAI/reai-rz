# RevEngAI Cutter Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 07/06/2024
# Copyright : Copyright (c) Siddharth Mishra. All Rights Reserved.

set(CMAKE_INCLUDE_CURRENT_DIR ON)

# main plugin library and sources
file(GLOB_RECURSE ReaiCutterPluginSource ${CMAKE_CURRENT_SOURCE_DIR} *.cpp *.c)
add_library(reai_cutter STATIC MODULE ${ReaiCutterPluginSource})
target_link_libraries(reai_cutter PRIVATE Cutter::Cutter Rizin::Core)

# install the built binaries to cutter's plugin directory
install(TARGETS reai_cutter DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
