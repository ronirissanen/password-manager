cmake_minimum_required(VERSION 3.20)
project(password-manager)

set(CMAKE_CXX_STANDARD 17)

add_executable(password-manager
    src/main.cpp
    src/crypto.cpp
    src/vault.cpp
    src/secure_memory.cpp
    src/cli.cpp
    
)

target_include_directories(password-manager PRIVATE include)

target_link_libraries(password-manager PRIVATE sodium)