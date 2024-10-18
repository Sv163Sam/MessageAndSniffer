cmake_minimum_required(VERSION 3.11)
project(Crypto_1_3)

set(LibSSH_INCLUDE_DIRS "/opt/homebrew/Cellar/openssl@3/3.3.2/include")
set(LibSSH_LIBRARIES "/opt/homebrew/Cellar/openssl@3/3.3.2/lib/libssl.dylib")
set(LibPCAP_INCLUDE_DIRS "/opt/homebrew/Cellar/libpcap/1.10.5/include")
set(LibPCAP_LIBRARIES "/opt/homebrew/Cellar/libpcap/1.10.5/lib/libpcap.dylib")

include_directories(${LibSSH_INCLUDE_DIRS})
include_directories(${LibPCAP_INCLUDE_DIRS})

add_executable(Server Server/server.cpp)
target_link_libraries(Server ${LibSSH_LIBRARIES})

add_executable(Client_1 Client_1/client_1.cpp)
target_link_libraries(Client_1 ${LibSSH_LIBRARIES})

add_executable(Client_2 Client_2/client_2.cpp)
target_link_libraries(Client_2 ${LibSSH_LIBRARIES})

add_executable(Sniffer Sniffer/sniffer.cpp)
target_link_libraries(Sniffer ${LibPCAP_LIBRARIES})


