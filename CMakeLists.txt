cmake_minimum_required(VERSION 2.8.12)
project(paillier)

find_package(pybind11 REQUIRED)

file(GLOB_RECURSE SRC_FRONTEND ${CMAKE_SOURCE_DIR}/*.cc)
pybind11_add_module(paillier_bind ${SRC_FRONTEND})
target_link_libraries(paillier_bind PUBLIC crypto)
