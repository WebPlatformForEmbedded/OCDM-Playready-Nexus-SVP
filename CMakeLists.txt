cmake_minimum_required(VERSION 3.3)

option(NEXUS_PLAYREADY_SVP_ENABLE "SAGE/SVP is enabled" OFF)

set(DRM_PLUGIN_NAME PlayReady)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(WPEFramework REQUIRED)
find_package(${NAMESPACE}Core REQUIRED)
find_package(NEXUS REQUIRED)
find_package(NXCLIENT REQUIRED)
find_package(NexusPlayready REQUIRED)

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

target_compile_definitions(${DRM_PLUGIN_NAME} 
    PRIVATE 
        BSTD_CPU_ENDIAN=BSTD_ENDIAN_LITTLE
        USE_PK_NAMESPACES=1
        DRM_INCLUDE_PK_NAMESPACE_USING_STATEMENT=1
        DRM_BUILD_PROFILE=900
)

target_link_libraries(${DRM_PLUGIN_NAME} 
    PRIVATE
        ${NAMESPACE}Core::${NAMESPACE}Core 
        NEXUS::NEXUS
        NXCLIENT::NXCLIENT
        NexusPlayready::NexusPlayready
)

if (NEXUS_PLAYREADY_SVP_ENABLE)
    target_compile_definitions(${DRM_PLUGIN_NAME} 
        PRIVATE 
            NEXUS_PLAYREADY_SVP_ENABLE
    )
endif()

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${NAMESPACE}/OCDM)

