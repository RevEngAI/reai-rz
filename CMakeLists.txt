# RevEngAI Cutter Plugin
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 07/06/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

# Writing python plugins is a P.I.T.A
# Reference for writing this CPP plugin was taken from rz-retdec CPP plugin.
# REF : https://github.com/rizinorg/rz-retdec/blob/dev/CMakeLists.txt
# Some regions of code that are copy-pasted are LGPL licensed (as rz-retdec is too)
# Those regions of code will be marked as such, both in build system files and in actual
# plugin code.

cmake_minimum_required(VERSION 3.5)

project(rz-reai VERSION 0 LANGUAGES C CXX)

option(BUILD_SHARED_LIBS "Build using shared libraries" OFF)
option(BUILD_RIZIN_PLUGIN_ONLY "Whether to build rizin plugin only" ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ----------------------------------------
# ---- LGPL-3.0 LICENSED REGION BEGIN ----
# ----------------------------------------

# Minimal required version
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Build parameters.
if(MSVC) # Windows
	# Disable warnings (there are too many of them, including warnings from
	# third-party libraries, which cannot be selectively disabled when using MSVC).
	string(REGEX REPLACE "/W[0-4]" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W0")

	# Disable the min() and max() macros to prevent errors when using e.g.
	# std::numeric_limits<...>::max()
	# (http://stackoverflow.com/questions/1904635/warning-c4003-and-errors-c2589-and-c2059-on-x-stdnumeric-limitsintmax).
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /DNOMINMAX")
elseif(UNIX) # Linux or macOS
	# Common options.
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fpermissive")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

	# Set C flags
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC -Wall -Wextra -fsanitize=address")
else()
	message(FATAL_ERROR "Unsupported system type: ${CMAKE_SYSTEM_NAME}")
endif()

# On Linux and macOS, set RPATH relative to the origin of the installed
# executables (i.e. relative to the bin directory). This allows us to move the
# installation directory into a different location after installation, which is
# useful e.g. when the installation is performed on one machine but we want to
# run the executables on a different machine.
#
# On Windows, there is no need to set anything as DLLs are installed into the
# bin directory, where they are automatically picked up by executables.
#
# For more details, see
#  - https://github.com/avast/retdec/issues/77
#  - https://cmake.org/Wiki/CMake_RPATH_handling
if(APPLE)
        set(CMAKE_INSTALL_RPATH "@executable_path/../lib")
elseif(UNIX)
        set(CMAKE_INSTALL_RPATH "$ORIGIN/../lib")
endif()

# This will give us path where plugins are installed on this sytem, also libraries to be linked.
find_package(Rizin REQUIRED)
set(RIZIN_INSTALL_PLUGDIR "${Rizin_PLUGINDIR}" CACHE STRING "Directory to install Rizin plugins into")

if(NOT BUILD_RIZIN_PLUGIN_ONLY)
  find_package(Cutter REQUIRED)
  set(CUTTER_INSTALL_PLUGDIR "${Cutter_USER_PLUGINDIR}" CACHE STRING "Directory to install Cutter plugin into")
endif()

# --------------------------------------
# ---- LGPL-3.0 LICENSED REGION END ----
# --------------------------------------

add_subdirectory(Source)
