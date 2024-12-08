cmake_minimum_required(VERSION 3.26.5)
project(EncryptedChat)

set(CMAKE_CXX_STANDARD 17)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${OPENSSL_INCLUDE_DIR})


# Adds subdirectories for client and server
add_subdirectory(Client)
add_subdirectory(Server)
