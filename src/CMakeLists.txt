# The project's definitions and include path come from the targets, not from this directory:
# ranz_options (cmake/RanzOptions.cmake) and the src root that mayaqua exports
# (src/Mayaqua/CMakeLists.txt), so the vendored targets get neither

if(NOT WIN32)
  message(FATAL_ERROR "Ranz VPN builds on Windows only")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "Ranz VPN builds for x64 and arm64 only")
endif()

if(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
  # cl.exe only. clang-cl takes /Qspectre and ignores it with a warning, so it is not set for
  # clang-cl: docs/adr/0024-clang-cl-spectre.md
  message("Setting QSPECTRE")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /Qspectre")
  # The additional security checks of ADR-0039 decision 1, cl.exe only for the same reason:
  # clang-cl accepts /sdl and ignores it. Its /GS below is the strong stack protector that /sdl
  # turns on in cl.exe.
  message("Setting /sdl")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /sdl")
else()
  message(STATUS "No /Qspectre with ${CMAKE_C_COMPILER_ID}: docs/adr/0024-clang-cl-spectre.md")
  message(STATUS "No /sdl with ${CMAKE_C_COMPILER_ID}: it ignores the switch (docs/adr/0039-security-hardening-baseline.md)")
endif()

# The stack buffer-overrun checks of ADR-0039 decision 1. Both compilers default to /GS; it is named
# so that a toolchain default cannot drop it. CI checks the shipped executables for every flag of
# that decision (.github/scripts/binary-hardening.ps1).
message("Setting /GS")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /GS")

#
# https://msrc-blog.microsoft.com/2020/08/17/control-flow-guard-for-clang-llvm-and-rust/
#

message("Setting CONTROL FLOW GUARD") 
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /guard:cf")
set(CMAKE_EXE_LINKER_FLAGS  "${CMAKE_EXE_LINKER_FLAGS} /guard:cf /DYNAMICBASE")

message("Setting CETCOMPAT")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /CETCOMPAT")

# Full, high-entropy ASLR and DEP (ADR-0039 decision 1). Both linkers set them by default for a
# 64-bit executable with /DYNAMICBASE; they are named for the same reason as /GS above.
message("Setting /HIGHENTROPYVA /NXCOMPAT")
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /HIGHENTROPYVA /NXCOMPAT")

# Optimised linking of the executables: /OPT:REF drops unreferenced functions and data, /OPT:ICF
# folds identical ones. /DEBUG, which the RelWithDebInfo flags keep for the PDBs, turns both off
# unless they are named. CMake's /INCREMENTAL becomes /INCREMENTAL:NO, as in
# cmake/RanzSanitizers.cmake: the linker ignores it next to /OPT:REF, with a warning.
# Debug builds keep CMake's flags. So do ASan builds (RANZ_ASAN): /OPT:ICF could fold two
# instrumented globals into one address that ASan then registers twice.
# /OPT:ICF gives identical functions one address. The only comparison of a function pointer
# against a named function, r->ThreadProc == TCPAcceptedThread (Listener.c), names a function
# whose body is unique. A log record says with IsCsv how its line starts (LogWriter.c).
if(NOT RANZ_ASAN)
  message("Setting /OPT:REF /OPT:ICF /INCREMENTAL:NO")
  foreach(_ranz_config RELWITHDEBINFO RELEASE MINSIZEREL)
    set(_ranz_var "CMAKE_EXE_LINKER_FLAGS_${_ranz_config}")
    string(REGEX REPLACE " */INCREMENTAL(:NO|:YES)?" "" ${_ranz_var} "${${_ranz_var}}")
    set(${_ranz_var} "${${_ranz_var}} /INCREMENTAL:NO /OPT:REF /OPT:ICF")
  endforeach()
endif()

# Cedar communication module
add_subdirectory(Cedar)

# Mayaqua kernel
add_subdirectory(Mayaqua)

# ranz-node, the node of the new core. The slim fork's vpnserver and vpncmd are retired (CORE-S8-1, #84).
add_subdirectory(ranz-node)

# vpntest
add_subdirectory(vpntest)

# The new core (ADR-0022): the crypto, session, peer and transport modules, and their test program coretest
add_subdirectory(Core)
add_subdirectory(coretest)

# libFuzzer targets (RANZ_FUZZ=ON only)
if(RANZ_FUZZ)
  add_subdirectory(fuzz)
endif()

# Every target exists now: the new core links no OpenSSL, no liboqs and nothing of the slim fork
ranz_core_check_links(corecrypto corenoise corepeer coretransport corecontrol corevxlan coreswitch corepolicy corefrontdoor coretest)
