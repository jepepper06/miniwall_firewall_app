cmake_minimum_required(VERSION 3.5.0)
project(Converters C)
add_library(converter STATIC converter.c)
install(TARGETS converter DESTINATION .)