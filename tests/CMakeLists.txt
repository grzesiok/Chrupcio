# Tests for Chrupcio

add_executable(ChrupcioTests
    ${CMAKE_CURRENT_SOURCE_DIR}/test_main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_memory.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_queue.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/test_commandmanager.cpp
    ${CMAKE_SOURCE_DIR}/algortihms/queue/queue.cpp
    ${CMAKE_SOURCE_DIR}/execute_unit/CommandManager.cpp
)

target_include_directories(ChrupcioTests PRIVATE ${CMAKE_SOURCE_DIR})
# Keep same compile flags as main project
target_compile_features(ChrupcioTests PRIVATE cxx_std_20)
target_compile_options(ChrupcioTests PRIVATE /EHsc /Zi)

# Download doctest (single-header) using FetchContent
include(FetchContent)
FetchContent_Declare(
  doctest
  GIT_REPOSITORY https://github.com/onqtam/doctest.git
  GIT_TAG v2.4.9
)
# Populate but do NOT call FetchContent_MakeAvailable to avoid configuring doctest's own CMake
FetchContent_GetProperties(doctest)
if (NOT doctest_POPULATED)
  FetchContent_Populate(doctest)
endif()

# Add doctest include directory (repo provides doctest/doctest.h)
target_include_directories(ChrupcioTests PRIVATE ${doctest_SOURCE_DIR})

target_compile_definitions(ChrupcioTests PRIVATE UNIT_TEST)

# Register the test executable with CTest (runs all tests)
add_test(NAME ChrupcioTests COMMAND ChrupcioTests)

# Also register each doctest TEST_CASE as a separate CTest test so
# Test Explorer / CTest shows individual test cases.
# We discover test names by scanning test sources for TEST_CASE("...")
file(GLOB DOCTEST_TEST_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
foreach(_file IN LISTS DOCTEST_TEST_SOURCES)
    file(READ ${_file} _content)
    string(REGEX MATCHALL [=[TEST_CASE\("([^\"]+)"\)]=] _matches "${_content}")
    foreach(_m IN LISTS _matches)
        # extract captured group (the test name)
        string(REGEX REPLACE [=[TEST_CASE\("([^\"]+)"\)]=] "\\1" _testname "${_m}")
        # make a safe CTest name
        string(REGEX REPLACE "[^A-Za-z0-9_]" "_" _testid "${_testname}")
        # ensure unique name
        set(_ctest_name "${_testid}")
        math(EXPR _i "0")
        while(TARGET_EXISTS_${_ctest_name})
            math(EXPR _i "${_i} + 1")
            set(_ctest_name "${_testid}_${_i}")
        endwhile()
        add_test(NAME "${_ctest_name}" COMMAND $<TARGET_FILE:ChrupcioTests> --test-case "${_testname}")
    endforeach()
endforeach()
