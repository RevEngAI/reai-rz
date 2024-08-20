# RevEngAI Cutter Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 07/06/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(Rizin)

if(NOT BUILD_RIZIN_PLUGIN_ONLY)
  add_subdirectory(Cutter)
endif()
