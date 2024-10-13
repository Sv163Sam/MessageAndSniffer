cmake_minimum_required(VERSION 3.10)
project(Crypto_1_3)

set(LibSSH_INCLUDE_DIRS "/opt/homebrew/Cellar/openssl@3/3.3.2/include")
set(LibSSH_LIBRARIES "/opt/homebrew/Cellar/openssl@3/3.3.2/lib/libssl.dylib")

include_directories(${LibSSH_INCLUDE_DIRS})

add_executable(Server Server/server.cpp)
target_link_libraries(Server ${LibSSH_LIBRARIES})

add_executable(Client Client/client.cpp)
target_link_libraries(Client ${LibSSH_LIBRARIES})




