# RevEngAI Cutter Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 07/06/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# These libraries are installed by autoinstall feature or by explicit installation of creait library
find_library(libreai NAMES reai HINTS ${CMAKE_BINARY_DIR}/lib REQUIRED)
find_library(libcjson NAMES cjson HINTS ${CMAKE_BINARY_DIR}/lib  REQUIRED)
find_library(libtoml NAMES toml HINTS ${CMAKE_BINARY_DIR}/lib REQUIRED)

# Not linking curl and sqlite explicitly fails build (linker error)
# TODO: create a FindCreait.cmake file to address all these libraries in one variable ${CREAIT_LINK_LIBRARIES}

find_package(CURL REQUIRED)

set(CREAIT_LIBRARIES ${CURL_LIBRAIRES} CURL::libcurl ${libreai} ${libcjson} ${libtoml})
message(INFO "CREAIT_LIBRARIES = ${CREAIT_LIBRARIES}")

add_subdirectory(Rizin)

if(NOT BUILD_RIZIN_PLUGIN_ONLY)
  add_subdirectory(Cutter)
endif()
