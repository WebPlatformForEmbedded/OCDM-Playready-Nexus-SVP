# - Try to find Broadcom Nexus Playready 3.
# Once done this will define
#  PlayreadyFOUND     - System has a Nexus Playready 3 
#  Playready::Playready - The Nexus Playready 3 library
#
# Copyright (C) 2019 Metrological B.V
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1.  Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
# 2.  Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND ITS CONTRIBUTORS ``AS
# IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR ITS
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
# OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
# OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
find_package(NEXUS REQUIRED)	
find_package(NXCLIENT REQUIRED)

find_path(PLAYREADY_INCLUDE_DIR drmmanager.h
    PATH_SUFFIXES playready refsw)

find_path(NEXUS_INCLUDE_DIR b_secbuf.h
    PATH_SUFFIXES refsw)

list(APPEND PLAYREADY_INCLUDE_DIRS ${PLAYREADY_INCLUDE_DIR} ${NEXUS_INCLUDE_DIR})

# main lib
find_library(PLAYREADY_LIBRARY playready30pk)

# needed libs
list(APPEND NeededLibs prdyhttp)

# needed svp libs
list(APPEND NeededLibs drmrootfs srai b_secbuf)

foreach (_library ${NeededLibs})
    find_library(LIBRARY_${_library} ${_library})
    if(NOT EXISTS "${LIBRARY_${_library}}")
        message(SEND_ERROR "Could not find mandatory library: ${_library}")
    endif()
    list(APPEND PLAYREADY_LIBRARIES ${LIBRARY_${_library}})
endforeach ()

set(PLAYREADY_COMPILE_DEFINITIONS
    BSTD_CPU_ENDIAN=BSTD_ENDIAN_LITTLE
    USE_PK_NAMESPACES=1
    DRM_INCLUDE_PK_NAMESPACE_USING_STATEMENT=1
    DRM_BUILD_PROFILE=900
    CMD_DRM_PLAYREADY_SAGE_IMPL
    PLAYREADY_SAGE
)

if(EXISTS "${PLAYREADY_LIBRARY}")
    set(PLAYREADY_FOUND TRUE)

    if(NOT TARGET Playready::Playready)
        add_library(Playready::Playready UNKNOWN IMPORTED)
        
        set_target_properties(Playready::Playready PROPERTIES
            IMPORTED_LINK_INTERFACE_LANGUAGES   "CXX"
            IMPORTED_LOCATION                   "${PLAYREADY_LIBRARY}"
            IMPORTED_NO_SONAME                  TRUE
            INTERFACE_INCLUDE_DIRECTORIES       "${PLAYREADY_INCLUDE_DIRS}"
            INTERFACE_COMPILE_DEFINITIONS       "${PLAYREADY_COMPILE_DEFINITIONS}"
            INTERFACE_LINK_LIBRARIES            "${PLAYREADY_LIBRARIES}" NEXUS::NEXUS NXCLIENT::NXCLIENT
        )

        mark_as_advanced(
            PLAYREADY_LIBRARY 
            PLAYREADY_COMPILE_DEFINITIONS 
            PLAYREADY_LIBRARIES 
            PLAYREADY_COMPILE_DEFINITIONS 
            PLAYREADY_INCLUDE_DIR 
            NEXUS_INCLUDE_DIR
        )
    endif()
endif()