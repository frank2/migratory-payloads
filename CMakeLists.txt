cmake_minimum_required(VERSION 3.15)

project(sheep_monitor CXX)
# the CMake way to set /MT and /MTd
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(sheep_monitor main.cpp)
target_link_options(sheep_monitor PRIVATE "/NODEFAULTLIB")
