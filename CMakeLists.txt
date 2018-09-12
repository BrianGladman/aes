cmake_minimum_required(VERSION 3.10)
project(aes_code VERSION 1.0.0 DESCRIPTION "AES code in C and assembly")

include(CheckCCompilerFlag)
include(CheckSymbolExists)

set(SOURCES aeskey.c aes_modes.c aestab.c aescrypt.c)

if("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    check_c_compiler_flag(-march=native HAS_MARCH_NATIVE)
    if(HAS_MARCH_NATIVE)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -march=native")
        set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -march=native")
    endif()
endif()

list(APPEND CMAKE_REQUIRED_INCLUDES "${CMAKE_SOURCE_DIR}")
check_symbol_exists(INTEL_AES_POSSIBLE aesopt.h INTEL_AES_POSSIBLE)

if(CMAKE_SYSTEM_PROCESSOR STREQUAL "x86_64")
    set(CMAKE_ASM_NASM_COMPILER "yasm")
    enable_language(ASM_NASM)
    if(INTEL_AES_POSSIBLE)
        list(APPEND SOURCES aes_ni.c)
        set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -DINTEL_AES_POSSIBLE")
    endif()
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -D__GNUC__")
        if(CMAKE_BUILD_TYPE MATCHES Debug OR CMAKE_BUILD_TYPE MATCHES RelWithDebInfo)
            set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -g dwarf2")
        endif()
    endif()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DASM_AMD64_C")
    list(APPEND SOURCES aes_amd64.asm)
endif()

add_library(aes SHARED ${SOURCES})
if(UNIX AND NOT APPLE)
    set_target_properties(aes PROPERTIES
        SOVERSION 0
        VERSION ${PROJECT_VERSION}
    )
endif()

add_executable(aesxam aesxam.c)
target_link_libraries(aesxam aes)

add_executable(tablegen tablegen.c)

add_executable(aes_gav aesgav.c aesaux.c)
target_link_libraries(aes_gav aes)
