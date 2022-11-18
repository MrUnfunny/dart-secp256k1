cmake_minimum_required(VERSION 3.16)

project(tap-protocol LANGUAGES C)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_SHARED_LIB_TAPPROTOCOL "Build as shared library" ON)

set(${PROJECT_NAME}_HEADERS
        include/a.h
        )

set(${PROJECT_NAME}_SOURCES 
        src/a.c
        )

add_library(${PROJECT_NAME} SHARED ${${PROJECT_NAME}_HEADERS} ${${PROJECT_NAME}_SOURCES})


if (UNIX)
  add_compile_options(-fPIC)
endif()

add_subdirectory(contrib/bitcoin-core)

target_link_libraries(${PROJECT_NAME} 
        PRIVATE bitcoin-core
        #-fsanitize=undefined -fsanitize=address -fsanitize-address-use-after-scope
        )

target_include_directories(${PROJECT_NAME}
        PUBLIC ${PROJECT_SOURCE_DIR}/include
        PUBLIC ${PROJECT_SOURCE_DIR}/contrib/include
        )

target_compile_definitions(${PROJECT_NAME} PRIVATE TAPPROTOCOL_LIBRARY)

target_compile_options(${PROJECT_NAME} PRIVATE 
       $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
        #-fsanitize=undefined -fsanitize=address -fsanitize-address-use-after-scope
       )


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

