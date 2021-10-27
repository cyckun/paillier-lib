cmake_minimum_required(VERSION 2.8.12)
project(paillier)

find_package(pybind11 REQUIRED)
pybind11_add_module(paillier_bind  paillier_bind.cpp)