file(GLOB SOURCES_MAYAQUA "*.c" "Crypto/*.c")
file(GLOB HEADERS_MAYAQUA "*.h" "Crypto/*.h")

if(WIN32)
  add_library(mayaqua STATIC ${SOURCES_MAYAQUA} ${HEADERS_MAYAQUA})
endif()

# The src root only: every unit includes "Mayaqua/X.h", "Cedar/X.h" and "GlobalConst.h" from
# there; a Mayaqua unit includes the headers of its own directory by their plain names
target_include_directories(mayaqua PUBLIC "${TOP_DIRECTORY}/src")

# The project's build options (cmake/RanzOptions.cmake), for Mayaqua and every target built on it
target_link_libraries(mayaqua PUBLIC ranz_options)

set_target_properties(mayaqua
  PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  LIBRARY_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

find_package(OpenSSL 3.0 REQUIRED)

if(OPENSSL_VERSION VERSION_LESS "4.0.0")
  set(OQS_ENABLE ON CACHE BOOL "By setting this to OFF, Open Quantum Safe algorithms will not be built in")
else()
  # oqsprovider is built against OpenSSL 3 only
  set(OQS_ENABLE OFF)
endif()

if(OQS_ENABLE)
  set(OQS_BUILD_ONLY_LIB ON CACHE BOOL "Set liboqs to build only the library (no tests)")
  set(BUILD_TESTING OFF CACHE BOOL "By setting this to OFF, no tests or examples will be compiled.")
  set(OQS_PROVIDER_BUILD_STATIC ON CACHE BOOL "Build a static library instead of a shared library") # Build oqsprovider as a static library (defaults to shared)
  list(PREPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/src/Mayaqua/3rdparty/")

    # Disable all other KEM families
  set(OQS_ENABLE_KEM_FRODOKEM OFF)
  set(OQS_ENABLE_KEM_NTRUPRIME OFF)
  set(OQS_ENABLE_KEM_NTRU OFF)
  set(OQS_ENABLE_KEM_CLASSIC_MCELIECE OFF)
  set(OQS_ENABLE_KEM_HQC OFF)
  set(OQS_ENABLE_KEM_BIKE OFF)

  # Disable all SIG families
  set(OQS_ENABLE_SIG_ML_DSA OFF)
  set(OQS_ENABLE_SIG_FALCON OFF)
  set(OQS_ENABLE_SIG_DILITHIUM OFF)
  set(OQS_ENABLE_SIG_SPHINCS OFF)
  set(OQS_ENABLE_SIG_MAYO OFF)
  set(OQS_ENABLE_SIG_CROSS OFF)
  set(OQS_ENABLE_SIG_UOV OFF)
  set(OQS_ENABLE_SIG_SNOVA OFF)
  set(OQS_ENABLE_SIG_SLH_DSA OFF)

  add_subdirectory(3rdparty/liboqs)
  add_subdirectory(3rdparty/oqs-provider)

  target_include_directories(oqsprovider PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/3rdparty/liboqs/include)
  set_property(TARGET oqsprovider PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_link_libraries(mayaqua PRIVATE oqsprovider)
else()
  target_compile_definitions(mayaqua PRIVATE SKIP_OQS_PROVIDER)
endif()

find_package(ZLIB REQUIRED)

# Required because we include <openssl/opensslv.h> in Encrypt.h.
target_include_directories(mayaqua PUBLIC ${OPENSSL_INCLUDE_DIR})

target_link_libraries(mayaqua
  PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
)

if(WIN32)
  set_target_properties(mayaqua
    PROPERTIES
    COMPILE_PDB_NAME "mayaqua"
    COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  )

  target_link_libraries(mayaqua
    PRIVATE
      "bcrypt.lib"
      "crypt32.lib"
      "DbgHelp.Lib"
      "dwmapi.lib"
      "iphlpapi.lib"
      "ntdll.lib"
      "Psapi.Lib"
      "Secur32.Lib"
      "setupapi.lib"
      "winhttp.lib"
      "winmm.lib"
      "ws2_32.lib"
      "WtsApi32.Lib"
    )
endif()
