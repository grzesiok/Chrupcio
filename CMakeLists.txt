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
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# building libpqxx
FetchContent_Declare(
  libpqxx
  GIT_REPOSITORY https://github.com/jtv/libpqxx.git
  GIT_TAG 7.7
)
set(PQXX_LIBRARIES pqxx)

FetchContent_MakeAvailable(libpqxx)

# building PcapPlusPlus
#add_subdirectory(deps/PcapPlusPlus build-PcapPlusPlus)

# Add source to this project's executable.
add_executable(${PROJECT_NAME} "Chrupcio.cpp" "Chrupcio.h" "service/ServiceBase.h" "service/ServiceBase.cpp" "service/ServiceInstaller.h" "service/ServiceInstaller.cpp" "pcap/NetworkWatcher.h" "pcap/NetworkWatcher.cpp" "execute_unit/CommandManager.h" "execute_unit/Command.h"   "Status.h" "service/ServiceException.h" "execute_unit/CommandManager.cpp" "pcap/PacketAnalyzeCommand.h" "pcap/PacketAnalyzeCommand.cpp")

target_link_libraries(Chrupcio "pqxx")
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(${PROJECT_NAME} "${PQXX_LIBRARIES}")

# Add include for external software
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/out/build/x64-debug/_deps/libpqxx-src/include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/out/build/x64-debug/_deps/libpqxx-build/include)
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../npcap-sdk/Include)
target_link_libraries(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/../npcap-sdk/Lib/x64/Packet.lib)
target_link_libraries(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/../npcap-sdk/Lib/x64/wpcap.lib)
if(WIN32)
  target_link_libraries(${PROJECT_NAME} wsock32 ws2_32)
endif()
# TODO: Add tests and install targets if needed.
