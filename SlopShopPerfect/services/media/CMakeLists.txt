cmake_minimum_required(VERSION 3.28)

project(slopshop_media VERSION 1.3.0 LANGUAGES C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(slopshop_media
  src/ppm.c
  src/thumbnail.c
  src/pipeline.cpp
)

target_include_directories(slopshop_media PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)

if(MSVC)
  target_compile_options(slopshop_media PRIVATE /W4 /WX /sdl /GS /guard:cf)
  target_link_options(slopshop_media PRIVATE /DYNAMICBASE /NXCOMPAT /HIGHENTROPYVA)
else()
  # Warnings are errors, and the usual hardening set is on for every build type
  # rather than only for release.
  target_compile_options(slopshop_media PRIVATE
    -Wall
    -Wextra
    -Werror
    -Wconversion
    -Wsign-conversion
    -Wshadow
    -Wcast-qual
    -Wpointer-arith
    -Wvla
    -Wformat=2
    -Wformat-security
    -Werror=implicit-function-declaration
    -fstack-protector-strong
    -fstack-clash-protection
    -fno-common
    -fno-delete-null-pointer-checks
    -fno-strict-aliasing
    -D_FORTIFY_SOURCE=3
  )
  target_link_options(slopshop_media PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    -Wl,-z,separate-code
  )
endif()

# The sanitiser build is what CI runs the fuzz corpus against.
option(SLOPSHOP_MEDIA_SANITIZE "Build with address and undefined behaviour sanitisers" OFF)
if(SLOPSHOP_MEDIA_SANITIZE AND NOT MSVC)
  target_compile_options(slopshop_media PRIVATE
    -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  target_link_options(slopshop_media PRIVATE -fsanitize=address,undefined)
endif()

install(TARGETS slopshop_media ARCHIVE DESTINATION lib)
install(DIRECTORY include/ DESTINATION include)
