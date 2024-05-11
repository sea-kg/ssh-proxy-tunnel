cmake_minimum_required(VERSION 3.7)
project(ssl_proxy_tunnel)

set(CMAKE_CXX_STANDARD 14)

set(SOURCE_FILES
    src/main.cpp
    src/ssl_tunnel_thread.cpp
)

set(INCLUDE_DIRS
    src/
)


add_executable(ssl_proxy_tunnel ${SOURCE_FILES})

list(APPEND CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/openssl/build")

# OPENSSL_ROOT_DIR
find_package(OpenSSL REQUIRED)
target_link_libraries(ssl_proxy_tunnel OpenSSL::SSL Threads::Threads)

set(CMAKE_THREAD_PREFER_PTHREAD TRUE)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)
find_package(Threads REQUIRED)

include_directories(${INCLUDE_DIRS})

set_target_properties(ssl_proxy_tunnel
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}"
)
