cmake_minimum_required(VERSION 3.16)
project(x402_bch LANGUAGES CXX)

add_library(x402_bch INTERFACE)
target_include_directories(x402_bch INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(x402_bch INTERFACE cxx_std_17)
find_library(GMPXX_LIBRARY NAMES gmpxx REQUIRED)
find_library(GMP_LIBRARY NAMES gmp REQUIRED)
target_link_libraries(x402_bch INTERFACE ${GMPXX_LIBRARY} ${GMP_LIBRARY})

add_executable(x402_bch_conformance tests/conformance_test.cpp)
target_link_libraries(x402_bch_conformance PRIVATE x402_bch)
enable_testing()
add_test(NAME x402_bch_conformance COMMAND x402_bch_conformance WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
