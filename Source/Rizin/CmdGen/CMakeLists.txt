# This file is converted to CMake script from a modified version of meson.build
# present in same directory, which was itself extracted from rizin's source code.
# Author : Siddharth Mishra (admin@brightprogrammer.in)
# Copyright : Licensed under the same conditions as Rizin.
# Date : 13th June 2024

find_package(Python3 REQUIRED)
execute_process(COMMAND "${Python3_EXECUTABLE}" -c "import yaml" RESULT_VARIABLE PY_YAML_FOUND)

# if return code is not zero
if(${PY_YAML_FOUND})
    message(FATAL_ERROR "PyYaml is a required dependency for generating command descriptions. Please install PyYaml.")
endif()

# Generate Root.yaml with corrected file paths.
set(SUBCOMMANDS_FILES_BASE "${CMAKE_CURRENT_SOURCE_DIR}/Yaml")

set(CmdDescsRootYamlIn "${CMAKE_CURRENT_SOURCE_DIR}/Yaml/Root.yaml.in")
set(CmdDescsRootYaml "${CMAKE_CURRENT_BINARY_DIR}/Yaml/Root.yaml")
configure_file(${CmdDescsRootYamlIn} ${CmdDescsRootYaml} @ONLY)

set(CmdDescsReaiYamlIn "${CMAKE_CURRENT_SOURCE_DIR}/Yaml/Reai.yaml.in")
set(CmdDescsReaiYaml "${CMAKE_CURRENT_BINARY_DIR}/Yaml/Reai.yaml")
configure_file(${CmdDescsReaiYamlIn} ${CmdDescsReaiYaml} @ONLY)

set(CmdDescsCollectionsYamlIn "${CMAKE_CURRENT_SOURCE_DIR}/Yaml/Collections.yaml.in")
set(CmdDescsCollectionsYaml "${CMAKE_CURRENT_BINARY_DIR}/Yaml/Collections.yaml")
configure_file(${CmdDescsCollectionsYamlIn} ${CmdDescsCollectionsYaml} @ONLY)

set(CmdDescGenerator "${CMAKE_CURRENT_SOURCE_DIR}/Generators/CmdDescsGenerator.py")
set(CmdDescYamlFiles ${CmdDescsReaiYaml} ${CmdDescsRootYaml} ${CmdDescsCollectionsYaml})
set(CmdDescOutputFiles "${CMAKE_CURRENT_BINARY_DIR}/Output/CmdDescs.c" "${CMAKE_CURRENT_BINARY_DIR}/Output/CmdDescs.h")

add_custom_command(
    OUTPUT ${CmdDescOutputFiles}
    COMMAND "${Python3_EXECUTABLE}" ${CmdDescGenerator} --output-dir ${CMAKE_CURRENT_BINARY_DIR} --src-output-dir ${CMAKE_CURRENT_BINARY_DIR} ${CmdDescYamlFiles}
    DEPENDS ${CmdDescYamlFiles}
    COMMENT "Generating CmdDescs.c and CmdDescs.h"
)

add_library(reai_cmdescs ${CmdDescOutputFiles})
target_link_libraries(reai_cmdescs PUBLIC Rizin::Core)
target_include_directories(reai_cmdescs PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/../..)
set_target_properties(
    reai_cmdescs
    PROPERTIES
    ADDITIONAL_CLEAN_FILES ${CmdDescsReaiYaml}
    ADDITIONAL_CLEAN_FILES ${CmdDescsRootYaml}
    ADDITIONAL_CLEAN_FILES ${CmdDescsCollectionsYaml}
    ADDITIONAL_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/Output/CmdDescs.c"
    ADDITIONAL_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/Output/CmdDescs.h"
)
