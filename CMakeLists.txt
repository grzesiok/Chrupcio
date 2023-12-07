# CMakeList.txt : CMake project for Chrupcio, include source and define
# project specific logic here.
#
include(FetchContent)

# Require minimum CMAKE version
cmake_minimum_required(VERSION 3.14)

# Definition of project
project(Chrupcio DESCRIPTION "Capturing network traffic into DB"
                 VERSION 1.0.0
                 LANGUAGES CXX)

# Setting global configuration
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_FLAGS /EHsc)

# building libpqxx
FetchContent_Declare(
  libpqxx
  GIT_REPOSITORY https://github.com/jtv/libpqxx.git
  GIT_TAG 7.7
)
set(PQXX_LIBRARIES pqxx)

FetchContent_MakeAvailable(libpqxx)

# building PcapPlusPlus
FetchContent_Declare(
  PcapPlusPlus
  GIT_REPOSITORY https://github.com/seladb/PcapPlusPlus.git
  GIT_TAG v23.09
)
set(PcapPlusPlus_LIBRARIES Pcap++ Packet++ Common++)
set(PCAP_LIBRARY ${CMAKE_CURRENT_SOURCE_DIR}/../npcap-sdk/Lib/x64/wpcap.lib)
set(PCAP_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../npcap-sdk/Include)
set(Packet_LIBRARY ${CMAKE_CURRENT_SOURCE_DIR}/../npcap-sdk/Lib/x64/Packet.lib)
set(Packet_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../npcap-sdk/Include)

FetchContent_MakeAvailable(PcapPlusPlus)

# Add source to this project's executable.
add_executable(${PROJECT_NAME} "Chrupcio.cpp"
                               "Chrupcio.h"
                               "service/ServiceBase.h"
                               "service/ServiceBase.cpp"
                               "service/ServiceInstaller.h"
                               "service/ServiceInstaller.cpp"
                               "pcap/NetworkWatcher.h"
                               "pcap/NetworkWatcher.cpp"
                               "execute_unit/CommandManager.h"
                               "execute_unit/Command.h"
                               "Status.h"
                               "service/ServiceException.h"
                               "execute_unit/CommandManager.cpp")

target_link_libraries(${PROJECT_NAME} "${PQXX_LIBRARIES}"
                                      "${PcapPlusPlus_LIBRARIES}")
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
                                                  ${CMAKE_CURRENT_SOURCE_DIR}/out/build/x64-debug/_deps/libpqxx-src/include
                                                  ${CMAKE_CURRENT_SOURCE_DIR}/out/build/x64-debug/_deps/libpqxx-build/include
                                                  ${CMAKE_CURRENT_SOURCE_DIR}/out/build/x64-debug/_deps/pcapplusplus-src/Common++/header
                                                  ${CMAKE_CURRENT_SOURCE_DIR}/out/build/x64-debug/_deps/pcapplusplus-src/Packet++/header
                                                  ${CMAKE_CURRENT_SOURCE_DIR}/out/build/x64-debug/_deps/pcapplusplus-src/Pcap++/header
                                                  ${PCAP_INCLUDE_DIR})
# TODO: Add tests and install targets if needed.
