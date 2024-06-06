# CMakeList.txt : CMake project for Chrupcio, include source and define
# project specific logic here.
#
include(FetchContent)

# Require minimum CMAKE version
cmake_minimum_required(VERSION 3.14)

# Definition of project
project(Chrupcio DESCRIPTION "Windows service"
                 VERSION 1.0.0
                 LANGUAGES CXX)

# Setting global configuration
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc /Zi")

# building spdlog
#FetchContent_Declare(
#  spdlog
#  GIT_REPOSITORY https://github.com/gabime/spdlog.git
#  GIT_TAG v1.14.1
#)

#FetchContent_MakeAvailable(spdlog)

# Add source to this project's executable.
add_executable(${PROJECT_NAME} "Chrupcio.cpp"
                               "Chrupcio.h"
                               "service/ServiceBase.h"
                               "service/ServiceBase.cpp"
                               "service/ServiceInstaller.h"
                               "service/ServiceInstaller.cpp"
                               "execute_unit/CommandManager.h"
                               "execute_unit/Command.h"
                               "Status.h"
                               "service/ServiceException.h"
                               "execute_unit/CommandManager.cpp"
                               "service/ServiceEvent.h"
                               "algortihms/queue/queue.h"
                               "algortihms/queue/queue.cpp"
                               "algortihms/memory/memory.h")

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
#target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
#                                                  ${CMAKE_CURRENT_SOURCE_DIR}/out/build/x64-debug/_deps/spdlog-src/include)
# TODO: Add tests and install targets if needed.
