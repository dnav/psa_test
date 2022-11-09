cmake_minimum_required(VERSION 3.11)

project(psa_test C)

include(FetchContent)

##########################
# Retrieve mbedtls 2.28.0
#
FetchContent_Declare(
    mbedtls2
    URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v2.28.0.zip
)

FetchContent_GetProperties(mbedtls2)
if(NOT mbedtls2_POPULATED)
    message("Retrieving Mbed TLS v2.28.0 release from https://github.com/Mbed-TLS/mbedtls...")
    FetchContent_Populate(mbedtls2)
endif()


include(${CMAKE_CURRENT_LIST_DIR}/mbedtls.cmake)

add_executable(${PROJECT_NAME}
               main.c
               ${MBEDTLS_SOURCES}
               ${MBEDTLS_HEADERS})

target_include_directories(${PROJECT_NAME} PRIVATE
                           ${MBEDTLS_INCLUDE_DIR}
                           ${MBEDTLS_SOURCE_DIR}
                           ${CMAKE_CURRENT_LIST_DIR})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread -Wall")

if (WIN32)
    target_link_libraries(${PROJECT_NAME} wsock32 ws2_32)
    set(CMAKE_C_FLAGS_DEBUG "/ZI")
endif()



