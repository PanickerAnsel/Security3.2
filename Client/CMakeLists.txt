# Creates client executable
add_executable(client_executable main.cpp
        client.cpp  ../Common/common.cpp
)

target_link_libraries(client_executable OpenSSL::SSL OpenSSL::Crypto)

# Include the Common folder for shared headers
target_include_directories(client_executable PRIVATE ../Common)