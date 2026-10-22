file(GLOB SOURCES_MAYAQUA "*.c" "Crypto/*.c")
file(GLOB HEADERS_MAYAQUA "*.h" "Crypto/*.h")

add_library(mayaqua STATIC ${SOURCES_MAYAQUA} ${HEADERS_MAYAQUA})

# The src root only: every unit includes "Mayaqua/X.h", "Cedar/X.h" and "GlobalConst.h" from
# there; a Mayaqua unit includes the headers of its own directory by their plain names
target_include_directories(mayaqua PUBLIC "${TOP_DIRECTORY}/src")

# The project's build options (cmake/RanzOptions.cmake), for Mayaqua and every target built on it
target_link_libraries(mayaqua PUBLIC ranz_options)

# The warning flags of the project's own code (cmake/RanzWarnings.cmake); PRIVATE: they stay on Mayaqua
target_link_libraries(mayaqua PRIVATE ranz_warnings)

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

  if(CMAKE_C_COMPILER_ID STREQUAL "Clang" AND MSVC)
    # clang-cl: liboqs puts -g3 and -fno-omit-frame-pointer in its flags (it treats clang-cl as
    # GNU-style clang), and clang-cl ignores both with a warning for every liboqs source file.
    # The vendored code is not ours to change, so the two warnings are off for liboqs and
    # oqs-provider; the option is directory-wide and applies to targets created after this line
    add_compile_options(-Wno-unknown-argument -Wno-unused-command-line-argument)
  endif()

  # liboqs refuses to configure for an architecture it has no optimised code for unless
  # OQS_PERMIT_UNSUPPORTED_ARCHITECTURE is ON; Windows on ARM64 is such a target (the workflow
  # used to pass the flag on the command line, so a local ARM64 configure failed)
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$" OR CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "ARM" OR VCPKG_TARGET_TRIPLET MATCHES "^arm64")
    set(OQS_PERMIT_UNSUPPORTED_ARCHITECTURE ON CACHE BOOL "Permit building liboqs for an architecture without optimised code")
  endif()

  # /volatile:ms for the vendored targets. cmake/RanzOptions.cmake applies it to the project's own
  # code through ranz_options, which liboqs and oqs-provider do not link; both live under
  # src/Mayaqua/3rdparty, so the "Check /volatile:ms" CI step counts their compile commands and fails
  # when they lack it. Directory-wide, so it reaches the targets the add_subdirectory calls below
  # create; C and CXX only, so the resource and assembly compile steps are left out.
  add_compile_options("$<$<COMPILE_LANGUAGE:C,CXX>:/volatile:ms>")

  add_subdirectory(3rdparty/liboqs)
  add_subdirectory(3rdparty/oqs-provider)

  target_include_directories(oqsprovider PUBLIC ${CMAKE_CURRENT_BINARY_DIR}/3rdparty/liboqs/include)
  set_property(TARGET oqsprovider PROPERTY POSITION_INDEPENDENT_CODE ON)
  target_link_libraries(mayaqua PRIVATE oqsprovider)
else()
  target_compile_definitions(mayaqua PRIVATE SKIP_OQS_PROVIDER)
endif()

find_package(ZLIB REQUIRED)

# The OpenSSL headers stay private to Mayaqua: no Mayaqua header includes one, so Cedar, the
# executables and the fuzz targets build without them
target_include_directories(mayaqua PRIVATE ${OPENSSL_INCLUDE_DIR})

target_link_libraries(mayaqua
  PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
    ZLIB::ZLIB
)

set_target_properties(mayaqua
  PROPERTIES
  COMPILE_PDB_NAME "mayaqua"
  COMPILE_PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
)

# Only the libraries Mayaqua sources call. EnumProcesses and GetModuleFileNameEx resolve to
# the K32 exports of kernel32 (PSAPI_VERSION 2); setupapi.lib: the net-class table of
# MsNetClassEnum (MicrosoftAdapter.c); ole32.lib and oleaut32.lib: the COM calls and BSTRs of the
# Windows Firewall rule (MicrosoftFirewall.c).
target_link_libraries(mayaqua
  PRIVATE
    "bcrypt.lib"
    "crypt32.lib"
    "DbgHelp.Lib"
    "iphlpapi.lib"
    "ntdll.lib"
    "ole32.lib"
    "oleaut32.lib"
    "Secur32.Lib"
    "setupapi.lib"
    "shlwapi.lib"
    "winhttp.lib"
    "winmm.lib"
    "ws2_32.lib"
  )
