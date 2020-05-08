# If not stated otherwise in this file or this component's LICENSE file the
# following copyright and licenses apply:
#
# Copyright 2020 RDK Management
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.3)

project(DRMPlayreadySVP)

set(DRM_PLUGIN_NAME PlayReady)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(WPEFramework REQUIRED)
find_package(${NAMESPACE}Core REQUIRED)
find_package(NEXUS REQUIRED)
find_package(NXCLIENT REQUIRED)
find_package(NexusPlayready REQUIRED)

string(REPLACE "-Wl,--as-needed" "" CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -Wl,--no-as-needed")

add_library(${DRM_PLUGIN_NAME} SHARED 
    MediaSession.cpp
    MediaSystem.cpp
    MediaSessionExt.cpp
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

install(TARGETS ${DRM_PLUGIN_NAME} DESTINATION ${CMAKE_INSTALL_PREFIX}/share/${NAMESPACE}/OCDM)

