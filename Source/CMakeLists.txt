# RevEngAI Cutter Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 07/06/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Not linking curl and sqlite explicitly fails build (linker error)
# TODO: create a FindCreait.cmake file to address all these libraries in one variable ${CREAIT_LINK_LIBRARIES}

find_package(CURL REQUIRED)

set(CREAIT_LIBRARIES ${CURL_LIBRAIRES} CURL::libcurl reai cjson toml)
message(INFO "CREAIT_LIBRARIES = ${CREAIT_LIBRARIES}")

add_subdirectory(Rizin)

if(BUILD_CUTTER_PLUGIN)
  add_subdirectory(Cutter)
endif()
