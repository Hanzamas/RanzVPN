set(COMPONENT_NAME "Testing Utility")
set(COMPONENT_INTERNAL_NAME "vpntest")

add_executable(vpntest vpntest.c harness.c harness_pack.c stress.c runtime.c crypto.c)

# Named string test of NAT-4 (#90)
target_sources(vpntest PRIVATE strtest.c)

# Named UDP Acceleration receive test of FIX-1 (#97)
target_sources(vpntest PRIVATE udpaccel.c)

# Named SeLow test of FIX-2 (#98)
target_sources(vpntest PRIVATE selowtest.c)

# Named DLL search order test of FIX-4 (#100)
target_sources(vpntest PRIVATE dllsearch.c)

# Named machine identity test of FIX-5 (#101)
target_sources(vpntest PRIVATE machineid.c)

# Named VM detection test of FIX-7 (#103)
target_sources(vpntest PRIVATE vmdetect.c)

# Named TCP/IP packet test of SEC-1 (#96)
target_sources(vpntest PRIVATE tcpiptest.c)

# Named X.509 and certificate signature test of SEC-2 (#96)
target_sources(vpntest PRIVATE x509test.c)

# Named BUF and binary configuration bounds test of SEC-3 (#96)
target_sources(vpntest PRIVATE bufbounds.c)

# Named keepalive span and client Pack size cap tests of SEC-4 (#96)
target_sources(vpntest PRIVATE keepalive.c packcap.c)

# Named StorePacket test of SEC-5 (#96)
target_sources(vpntest PRIVATE storepacket.c)

# Named console input test of SEC-7 (#96)
target_sources(vpntest PRIVATE consoleline.c)

# Named temp directory and string table test of SEC-8 (#96)
target_sources(vpntest PRIVATE tempdir.c)

# Named packet parser tests of PKG-9 (#113)
target_sources(vpntest PRIVATE pkttest.c)

set_target_properties(vpntest
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

if(WIN32)
  set_target_properties(vpntest
    PROPERTIES
    PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  get_filename_component(COMPONENT_FILE_NAME vpntest NAME)
  set(COMPONENT_FILE_NAME "${COMPONENT_FILE_NAME}.exe")

  configure_file("${TOP_DIRECTORY}/src/BuildFiles/VerScript/ver.rc" "${CMAKE_CURRENT_BINARY_DIR}/ver.rc")

  target_sources(vpntest PRIVATE
    "vpntest.rc"
    "ver.rc"

    "${TOP_DIRECTORY}/src/BuildFiles/Manifests/common.manifest"
  )

  # The hamcore files, as resources (cmake/RanzResources.cmake)
  ranz_hamcore_resources(vpntest)
endif()

target_link_libraries(vpntest cedar)

# The resources test (runtime.c) compares every hamcore file the executable serves with its source
# file. A source property, so the resource scripts of vpntest do not get the quoted path.
set_source_files_properties(runtime.c PROPERTIES COMPILE_DEFINITIONS "RANZ_HAMCORE_SOURCE_DIR=\"${TOP_DIRECTORY}/src/bin/hamcore\"")
