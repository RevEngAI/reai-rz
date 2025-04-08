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
    message(FATAL_ERROR "PyYaml is used only to generate commands. It can be installed in a dedicated python virtual environment, and used from there.")
    message(FATAL_ERROR "The plugin does not require PyYaml, once the build is complete, and you don't wish to rebuild it in near future.")
endif()

# Generate Root.yaml with corrected file paths.
set(SUBCOMMANDS_FILES_BASE "${CMAKE_CURRENT_SOURCE_DIR}/Yaml")

# Generator code and it's generated code
set(CmdDescGenerator "${CMAKE_CURRENT_SOURCE_DIR}/Generators/CmdDescsGenerator.py")
set(CmdDescOutputFiles "${CMAKE_CURRENT_BINARY_DIR}/Output/CmdDescs.c" "${CMAKE_CURRENT_BINARY_DIR}/Output/CmdDescs.h")

# Provide files IN and OUT that are to be configured by CMake
set(YAML_FILES Root Reai Collections Functions Analysis Binaries)
set(CmdDescYamlFiles "")
foreach(name IN LISTS YAML_FILES)
    set(infile "${CMAKE_CURRENT_SOURCE_DIR}/Yaml/${name}.yaml.in")
    set(outfile "${CMAKE_CURRENT_BINARY_DIR}/Yaml/${name}.yaml")
    configure_file(${infile} ${outfile} @ONLY)
    list(APPEND CmdDescYamlFiles ${outfile})
endforeach()

# Generate command descriptor code for Rizin plugin
add_custom_command(
    OUTPUT ${CmdDescOutputFiles}
    COMMAND "${Python3_EXECUTABLE}" ${CmdDescGenerator} --output-dir ${CMAKE_CURRENT_BINARY_DIR} --src-output-dir ${CMAKE_CURRENT_BINARY_DIR} ${CmdDescYamlFiles}
    DEPENDS ${CmdDescYamlFiles}
    COMMENT "Generating CmdDescs.c and CmdDescs.h"
)

# Make the code generated available as library
add_library(reai_cmdescs ${CmdDescOutputFiles})
target_link_libraries(reai_cmdescs PUBLIC Rizin::Core)
target_include_directories(reai_cmdescs PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/../..)
foreach(f in LISTS CmdDescYamlFiles)
    set_target_properties(
        reai_cmdescs
        PROPERTIES
        ADDITIONAL_CLEAN_FILES ${f}
    )
endforeach()
set_target_properties(
    reai_cmdescs
    PROPERTIES
    ADDITIONAL_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/Output/CmdDescs.c"
    ADDITIONAL_CLEAN_FILES "${CMAKE_CURRENT_BINARY_DIR}/Output/CmdDescs.h"
)
