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
                           "Ui/FunctionRenameDialog.cpp" "Ui/FunctionSimilarityDialog.cpp"
                           "Ui/AutoAnalysisDialog.cpp" "Ui/CreateAnalysisDialog.cpp"
                           "Ui/BinarySearchDialog.cpp" "Ui/CollectionSearchDialog.cpp"
                           "Ui/RecentAnalysisDialog.cpp")
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
    INSTALL_RPATH "$ENV{HOME}/.local/lib"
    BUILD_RPATH "${CMAKE_BINARY_DIR}/Source/Radare"
)

# install the built binaries to cutter's plugin directory
install(TARGETS reai_cutter DESTINATION "${CUTTER_INSTALL_PLUGDIR}")
