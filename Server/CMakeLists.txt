# Creates the server executable
add_executable(server_executable server.cpp
        main.cpp ../Common/common.cpp)

target_link_libraries(server_executable OpenSSL::SSL OpenSSL::Crypto)

# Include the Common folder for shared headers
target_include_directories(server_executable PRIVATE ../Common)