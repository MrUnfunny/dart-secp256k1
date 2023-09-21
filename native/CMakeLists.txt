cmake_minimum_required(VERSION 3.16)

project(secp256k1 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(${PROJECT_NAME}_HEADERS
        include/a.hpp
        )

set(${PROJECT_NAME}_SOURCES 
        src/a.cpp
        )

add_library(${PROJECT_NAME} SHARED ${${PROJECT_NAME}_HEADERS} ${${PROJECT_NAME}_SOURCES})

if (UNIX)
  add_compile_options(-fPIC)
endif()

if (ANDROID)
  add_library(libsecp256k1 STATIC IMPORTED)
  set_target_properties(libsecp256k1 PROPERTIES IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/contrib/secp256k1/build/android/${ANDROID_ABI}/lib/libsecp256k1.a)
  set_target_properties(libsecp256k1 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR}/contrib/secp256k1/include)
elseif(IOS)
  add_library(libsecp256k1 STATIC IMPORTED)
  set_target_properties(libsecp256k1 PROPERTIES IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/contrib/secp256k1/build/iphoneos/libsecp256k1.a)
  set_target_properties(libsecp256k1 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR}/contrib/secp256k1/include)
elseif(WIN32)
  message(FATAL_ERROR "Not support yet!")
elseif(LINUX)
  add_library(libsecp256k1 STATIC IMPORTED)
  set_target_properties(libsecp256k1 PROPERTIES IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/contrib/secp256k1/.libs/libsecp256k1.so)
  set_target_properties(libsecp256k1 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR}/contrib/secp256k1/include)
else()
  add_library(libsecp256k1 STATIC IMPORTED)
  set_target_properties(libsecp256k1 PROPERTIES IMPORTED_LOCATION ${PROJECT_SOURCE_DIR}/contrib/secp256k1/.libs/libsecp256k1.a)
  set_target_properties(libsecp256k1 PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${PROJECT_SOURCE_DIR}/contrib/secp256k1/include)
endif()


target_link_libraries(${PROJECT_NAME}
        PUBLIC libsecp256k1
        )

target_include_directories(${PROJECT_NAME}
        PUBLIC ${PROJECT_SOURCE_DIR}/include
        PUBLIC ${PROJECT_SOURCE_DIR}/contrib/
        )

target_compile_options(${PROJECT_NAME} PRIVATE 
       $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
        #-fsanitize=undefined -fsanitize=address -fsanitize-address-use-after-scope
       )


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)

