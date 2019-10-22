cmake_minimum_required(VERSION 3.9 FATAL_ERROR)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
endif()

project(bfe LANGUAGES C VERSION 0.9.1 DESCRIPTION "Bloom Filter Encryption Library")

set(CMAKE_C_STANDARD 99)

include(GNUInstallDirs)
find_package(relic REQUIRED)

add_library(bfe SHARED
        bfibe.c
        bitset.c
        bloomfilter.c
        bloomfilter_enc.c
        hibe.c
        logger.c
        tb_bloomfilter_enc.c
        test.c
        util.c)

set_target_properties(bfe PROPERTIES
        VERSION ${PROJECT_VERSION})
configure_file(bfe.pc.in bfe.pc @ONLY)

add_subdirectory(FIPS202-opt64)
target_link_libraries(bfe ${RELIC_LIBRARY} m FIPS202-opt64)

target_include_directories(bfe PRIVATE .)
target_include_directories(bfe PRIVATE ${RELIC_INCLUDE_DIR})

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


#add_executable(bfe bfibe.c bfibe.h util.c util.h murmurhash3.c murmurhash3.h bitset.c bitset.h bloomfilter_enc.c bloomfilter_enc.h bloomfilter.c bloomfilter.h test.c logger.c logger.h hibe.c hibe.h tb_bloomfilter_enc.c tb_bloomfilter_enc.h) # replace this with add_library()

