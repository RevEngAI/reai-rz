# RevEngAI Cutter Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 07/06/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Not linking curl and sqlite explicitly fails build (linker error)
# TODO: create a FindCreait.cmake file to address all these libraries in one variable ${CREAIT_LINK_LIBRARIES}

# Get latest tag
execute_process(
    COMMAND git describe --tags --abbrev=0
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_TAG
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

# Get current branch name
execute_process(
    COMMAND git rev-parse --abbrev-ref HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_BRANCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

# Get short commit hash
execute_process(
    COMMAND git rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE GIT_COMMIT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

# Fallbacks if git fails
if(NOT GIT_TAG)
    set(GIT_TAG "unknown-tag")
endif()

if(NOT GIT_BRANCH)
    set(GIT_BRANCH "unknown-branch")
endif()

if(NOT GIT_COMMIT)
    set(GIT_COMMIT "unknown-commit")
endif()

# Final version string: <tag>-<branch>-<commit>
set(PLUGIN_VERSION "${GIT_TAG}-${GIT_BRANCH}-${GIT_COMMIT}")
message(STATUS "Plugin version: ${PLUGIN_VERSION}")

# Generate version header
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/PluginVersion.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/PluginVersion.h
    @ONLY
)

add_subdirectory(Rizin)

if(BUILD_CUTTER_PLUGIN)
  add_subdirectory(Cutter)
endif()
