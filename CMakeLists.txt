cmake_minimum_required(VERSION 3.10)
project(ftype VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall -Wextra -O2)

# 1. 核心静态库
add_library(ftype STATIC src/ftype.cpp)
target_include_directories(ftype PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# 2. 命令行 Demo
add_executable(ftype_demo examples/demo.cpp)
target_link_libraries(ftype_demo PRIVATE ftype)

# 3. 单元测试 (CTest)
enable_testing()
add_executable(ftype_test tests/test_ftype.cpp)
target_link_libraries(ftype_test PRIVATE ftype)
add_test(NAME ftype_unit_tests COMMAND ftype_test ${CMAKE_CURRENT_SOURCE_DIR}/test_samples)
