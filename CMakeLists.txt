cmake_minimum_required(VERSION 3.3)

project(wpeframework-ocdm-playready-nexus-svp)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
include(GNUInstallDirs)

# Thunder or WPEFramework will provide the proper NAMESPACE.
find_package(Thunder QUIET)
if(NOT Thunder_FOUND)
    message(DEPRECATION "Thunder not found, swiching to WPEFramework")
    find_package(WPEFramework REQUIRED)
endif()

find_package(PkgConfig REQUIRED)
pkg_search_module(PLAYREADY4 playready4 QUIET)

if(PLAYREADY4_FOUND)
  find_package(Playready4 REQUIRED)
else()
  find_package(Playready3 REQUIRED)
endif()

set(DRM_PLUGIN_NAME PlayReady)

add_library(${DRM_PLUGIN_NAME} SHARED 
    MediaSession.cpp
    MediaSystem.cpp
)

set_target_properties(${DRM_PLUGIN_NAME} PROPERTIES 
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED YES
    SUFFIX ".drm"
    PREFIX ""
)

target_link_libraries(${DRM_PLUGIN_NAME} 
    PRIVATE
        Playready::Playready
)

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${NAMESPACE}/OCDM)
