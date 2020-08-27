
cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(ZeekPluginAnalyzer_ZIP)

include(ZeekPlugin)

find_package(libzip)

if (NOT LIBZIP_FOUND)
    message(FATAL_ERROR "Cannot find libzip, use --with-libzip=DIR")
endif ()

include_directories(BEFORE ${LIBZIP_INCLUDE_DIR})
zeek_plugin_begin(Zeek ZIP)
zeek_plugin_cc(src/Plugin.cc)
zeek_plugin_cc(src/ZIP.cc)
zeek_plugin_bif(src/analyzer_zip.bif)
zeek_plugin_bif(src/events.bif)
zeek_plugin_dist_files(README CHANGES COPYING VERSION)
zeek_plugin_link_library(${LIBZIP_LIBRARIES})
zeek_plugin_end()

file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
