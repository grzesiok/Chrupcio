# CMakeList.txt : CMake project for Chrupcio, include source and define
# project specific logic here.
#

# Require minimum CMAKE version
cmake_minimum_required(VERSION 3.27)

# Definition of project
project(Chrupcio DESCRIPTION "Capturing network traffic into DB"
                 LANGUAGES CXX)

# Add source to this project's executable.
add_executable(${PROJECT_NAME} "Chrupcio.cpp" "Chrupcio.h" "service/ServiceBase.h" "service/ServiceBase.cpp" "service/ServiceInstaller.h" "service/ServiceInstaller.cpp" "pcap/NetworkWatcher.h" "pcap/NetworkWatcher.cpp")
target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_20)

# Add include for external software
target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../npcap-sdk/Include)
target_link_libraries(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/../npcap-sdk/Lib/x64/Packet.lib)
target_link_libraries(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/../npcap-sdk/Lib/x64/wpcap.lib)

# TODO: Add tests and install targets if needed.
