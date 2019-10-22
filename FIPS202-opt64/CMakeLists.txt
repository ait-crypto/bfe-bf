add_library (FIPS202-opt64 align.h brg_endian.h KeccakHash.c KeccakHash.h KeccakP-1600-64.macros KeccakP-1600-opt64.c KeccakP-1600-opt64-config.h KeccakP-1600-SnP.h KeccakP-1600-unrolling.macros KeccakSponge.inc KeccakSponge-common.h KeccakSpongeWidth1600.c KeccakSpongeWidth1600.h SimpleFIPS202.c SimpleFIPS202.h SnP-Relaned.h)

set(CMAKE_C_FLAGS "-fPIC")

install(TARGETS FIPS202-opt64
        EXPORT FIPS202-opt64-targets
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
install(EXPORT FIPS202-opt64-targets
        NAMESPACE bfe::
        FILE bfe-config.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/bfe)