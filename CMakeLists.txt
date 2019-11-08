cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

# honor visibility properties
cmake_policy(SET CMP0063 NEW)
# enforce IPO if enabled
cmake_policy(SET CMP0069 NEW)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
endif()

project(bfe LANGUAGES C VERSION 1.0 DESCRIPTION "Bloom Filter Encryption Library")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

include(GNUInstallDirs)
include(CheckCCompilerFlag)
include(CheckIPOSupported)

function(check_c_compiler_flag_and_add flag result)
  check_c_compiler_flag("${flag}" ${result})
  if(${result})
    add_compile_options("${flag}")
  endif()
endfunction()

check_c_compiler_flag_and_add(-Wall CC_SUPPORTS_WALL)
check_c_compiler_flag_and_add(-Wextra CC_SUPPORTS_WEXTRA)
check_c_compiler_flag_and_add(-Wshadow CC_SUPPORTS_WSHADOW)
check_c_compiler_flag_and_add(-Werror=implicit-function-declaration CC_SUPPORTS_WERROR_IMPLICIT_FUNCTION_DECLARATION)

check_ipo_supported(RESULT LTO_SUPPORTED)

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/zf_log/CMakeLists.txt)
  set(HAVE_ZFLOG 1)
endif()

find_package(relic REQUIRED)
find_package(Doxygen)
find_package(OpenMP)
if(HAVE_ZFLOG)
  # force PIC for zf_log
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  add_subdirectory(zf_log)
endif()

add_library(bfe SHARED
            bloomfilter.c
            bfe.c
            util.c
            FIPS202-opt64/KeccakHash.c
            FIPS202-opt64/KeccakP-1600-opt64.c
            FIPS202-opt64/KeccakSpongeWidth1600.c)

set_target_properties(bfe PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(bfe PROPERTIES C_VISIBILITY_PRESET hidden)
if (LTO_SUPPORTED)
  set_target_properties(bfe PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

configure_file(bfe.pc.in bfe.pc @ONLY)

target_link_libraries(bfe PUBLIC ${RELIC_LIBRARY})
target_link_libraries(bfe PRIVATE m)
if(HAVE_ZFLOG)
  target_link_libraries(bfe PRIVATE zf_log)
  target_compile_definitions(bfe PRIVATE HAVE_ZFLOG)
endif()
target_include_directories(bfe PUBLIC ${RELIC_INCLUDE_DIR})
if(OpenMP_C_FOUND)
  target_link_libraries(bfe PRIVATE OpenMP::OpenMP_C)
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "GNU")
  target_link_options(bfe PRIVATE LINKER:-z,relro LINKER:-z,now)
  if(HAVE_ZFLOG)
    target_link_options(bfe PRIVATE LINKER:--exclude-libs,ALL)
  endif()
endif()

install(TARGETS bfe
        EXPORT bfe-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES ${CMAKE_BINARY_DIR}/bfe.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/bfe)
install(EXPORT bfe-targets
        NAMESPACE bfe::
        FILE bfe-config.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bfe)

if(DOXYGEN_FOUND)
  set(DOXYGEN_RECURSIVE NO)
  set(DOXYGEN_EXTRACT_ALL YES)
  set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
  set(DOXYGEN_TYPEDEF_HIDES_STRUCT YES)
  set(DOXYGEN_SOURCE_BROWSER YES)
  doxygen_add_docs(doxygen ${CMAKE_CURRENT_SOURCE_DIR}/include COMMENT "Generate doxygen documentation")
endif()

# benchmarks
add_executable(bench bench.c)
target_link_libraries(bench PRIVATE bfe ${RELIC_LIBRARY})

# testing
enable_testing()
add_subdirectory(tests)
