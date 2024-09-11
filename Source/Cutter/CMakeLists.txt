# RevEngAI Cutter Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 12/06/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

# AUTOMOC is alteast required to allow using of Q_PLUGIN_METADATA
set(CMAKE_AUTOMOC ON) # Auto Meta Object Compiler
set(CMAKE_AUTOUIC ON) # Auto User Interface Compiler
set(CMAKE_AUTORCC ON) # Auto Resource Compile

# main plugin library and sources
set(ReaiCutterPluginSource "Cutter.cpp" "../Plugin.c" "Ui/ConfigSetupDialog.cpp" "Ui/Table.cpp"
                           "Ui/FunctionRenameDialog.cpp")
add_library(reai_cutter STATIC MODULE ${ReaiCutterPluginSource})
target_link_libraries(reai_cutter PUBLIC Cutter::Cutter Rizin::Core ${CREAIT_LIBRARIES})

# install the built binaries to cutter's plugin directory
install(TARGETS reai_cutter DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
