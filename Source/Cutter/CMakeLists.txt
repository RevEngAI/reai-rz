# RevEngAI Cutter Plugin Sources
# Author    : Siddharth Mishra (admin@brightprogrammer.in)
# Date      : 12/06/2024
# Copyright : Copyright (c) RevEngAI. All Rights Reserved.

# AUTOMOC is alteast required to allow using of Q_PLUGIN_METADATA
set(CMAKE_AUTOMOC ON) # Auto Meta Object Compiler
set(CMAKE_AUTOUIC ON) # Auto User Interface Compiler
set(CMAKE_AUTORCC ON) # Auto Resource Compile

# Libraries needs to be searched here to be linked properly
# Because MSVC obviously
find_package(CURL REQUIRED)
find_package(Creait REQUIRED)

if(CUTTER_USE_QT6)
  find_package(Qt6 COMPONENTS Widgets REQUIRED)
  set(QT_LIBRARIES ${Qt6_LIBRARIES})
else()
  find_package(Qt5 COMPONENTS Widgets REQUIRED)
  set(QT_LIBRARIES ${Qt5_LIBRARIES})
endif()

# main plugin library and sources
set(ReaiCutterPluginSource "Cutter.cpp" "Decompiler.cpp" "../Plugin.c"
                           "Ui/AutoAnalysisDialog.cpp" "Ui/CreateAnalysisDialog.cpp"
                           "Ui/BinarySearchDialog.cpp" "Ui/CollectionSearchDialog.cpp"
                           "Ui/RecentAnalysisDialog.cpp" "Ui/InteractiveDiffWidget.cpp")
add_library(reai_cutter STATIC MODULE ${ReaiCutterPluginSource})
target_include_directories(reai_cutter PUBLIC ${CREAIT_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS})
target_link_libraries(
  reai_cutter
  PUBLIC
  Cutter::Cutter
  Rizin::Core
  ${CREAIT_LIBRARIES}
  ${CURL_LIBRARIES}
  ${QT_LIBRARIES}
)
set_target_properties(
    reai_cutter PROPERTIES
    BUILD_RPATH "${CMAKE_BINARY_DIR}/Source/Rizin"
)

# Set platform-specific INSTALL_RPATH
if(APPLE)
    # macOS: @loader_path is relative to the plugin location
    # Cutter plugin is at: ~/Library/Application Support/rizin/cutter/plugins/native/plugin.so
    # Libraries at: ~/.local/lib/librz_*.dylib
    # For development builds: $ENV{HOME} expands correctly at build time
    # For CI builds: install script will fix rpath at installation time
    set_target_properties(reai_cutter PROPERTIES
        INSTALL_RPATH "@loader_path;@loader_path/../lib;@rpath;$ENV{HOME}/.local/lib;/usr/local/lib;/opt/homebrew/lib;/usr/lib;/lib"
    )
elseif(UNIX)
    # Linux: $ORIGIN is relative to the plugin location  
    set_target_properties(reai_cutter PROPERTIES
        INSTALL_RPATH "$ORIGIN:$ORIGIN/../lib:$ENV{HOME}/.local/lib:/usr/local/lib:/usr/lib:/lib"
    )
endif()
# Windows: No rpath needed, DLLs are found via PATH or same directory

# install the built binaries to cutter's plugin directory
install(TARGETS reai_cutter DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
