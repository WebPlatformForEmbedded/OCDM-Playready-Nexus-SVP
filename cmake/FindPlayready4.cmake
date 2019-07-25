# - Try to find Playready 4.
# Once done this will define
#  Playready_FOUND     - System has a Playready 4
#  Playready::Playready - The Playready 4 library
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

find_package(PkgConfig REQUIRED)
include(FindPackageHandleStandardArgs)

pkg_search_module(PC_PLAYREADY4 playready4 REQUIRED)

find_package_handle_standard_args(PC_PLAYREADY4 DEFAULT_MSG 
    PC_PLAYREADY4_INCLUDE_DIRS 
    PC_PLAYREADY4_LIBRARIES 
    PC_PLAYREADY4_CFLAGS_OTHER)
    
mark_as_advanced(
    PC_PLAYREADY4_INCLUDE_DIRS 
    PC_PLAYREADY4_LIBRARIES  
    PC_PLAYREADY4_CFLAGS_OTHER
)

if(PC_PLAYREADY4_FOUND)
    set(Playready_FOUND TRUE)
    
    list(GET ${PC_PLAYREADY4_LIBRARIES} 0 PLAYREADY4_LIBRARY)

    if(NOT TARGET Playready::Playready)
        add_library(Playready::Playready UNKNOWN IMPORTED)
        
        set_target_properties(Playready::Playready PROPERTIES
            IMPORTED_LINK_INTERFACE_LANGUAGES   "CXX"
            IMPORTED_LOCATION                   "${PLAYREADY4_LIBRARY}"
            IMPORTED_NO_SONAME                  TRUE
            INTERFACE_INCLUDE_DIRECTORIES       "${PC_PLAYREADY4_INCLUDE_DIRS}"
            INTERFACE_LINK_LIBRARIES            "${PC_PLAYREADY4_LIBRARIES}"
            INTERFACE_COMPILE_OPTIONS           "${PC_PLAYREADY4_CFLAGS_OTHER}"
        )
    endif()
endif()