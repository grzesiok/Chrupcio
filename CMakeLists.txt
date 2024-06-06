# CMakeList.txt : CMake project for Chrupcio, include source and define
# project specific logic here.
#

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

# Add source to this project's executable.
add_executable(${PROJECT_NAME} "Chrupcio.cpp"
                               "Chrupcio.h"
                               "service/ServiceBase.h"
                               "service/ServiceBase.cpp"
                               "service/ServiceInstaller.h"
                               "service/ServiceInstaller.cpp"
                               "Status.h"
                               "service/ServiceException.h"
                               "service/ServiceEvent.h")

target_include_directories(${PROJECT_NAME} PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
# TODO: Add tests and install targets if needed.