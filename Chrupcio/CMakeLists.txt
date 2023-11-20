# CMakeList.txt : CMake project for Chrupcio, include source and define
# project specific logic here.
#

# Add source to this project's executable.
add_executable (Chrupcio "Chrupcio.cpp" "Chrupcio.h" "service/ServiceBase.h" "service/ServiceBase.cpp" "service/ServiceInstaller.h" "service/ServiceInstaller.cpp")

if (CMAKE_VERSION VERSION_GREATER 3.12)
  set_property(TARGET Chrupcio PROPERTY CXX_STANDARD 20)
endif()

# TODO: Add tests and install targets if needed.
