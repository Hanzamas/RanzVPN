# src/guard/CMakeLists.txt
# ranzguard: the release-only hardened licence-gate and key-handling binary (SEC-4 #282, ADR-0036).
# Freestanding and x64 only: no CRT and an empty import table (every API is resolved at run time). It is
# added from the top-level CMakeLists, not from src/, so it does not inherit the /guard:cf, /CETCOMPAT
# and /OPT linker flags that src/CMakeLists.txt sets: control-flow guard would put a load-config import
# back into the import table the empty-IAT check asserts is empty.

add_executable(ranzguard ranzguard.c)

set_target_properties(ranzguard PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  PDB_OUTPUT_DIRECTORY "${BUILD_DIRECTORY}"
  # No CRT: clear the static-runtime selection the top-level CMakeLists makes
  MSVC_RUNTIME_LIBRARY ""
)

# Freestanding: no stack-security cookie, so no __security_check_cookie from the CRT is referenced
target_compile_options(ranzguard PRIVATE /GS-)

# The VMProtect SDK path, used only at the release step. When RANZ_VMPROTECT_SDK_DIR is set the markers
# become real virtualization; CI leaves it unset and the markers are nothing, so CI builds this variant
# without the paid tool.
if(RANZ_VMPROTECT_SDK_DIR)
  target_include_directories(ranzguard PRIVATE "${RANZ_VMPROTECT_SDK_DIR}")
  target_compile_definitions(ranzguard PRIVATE RANZ_VMPROTECT_SDK)
  target_link_libraries(ranzguard PRIVATE "${RANZ_VMPROTECT_SDK_DIR}/VMProtectSDK64.lib")
endif()

# No default libraries and a custom entry point, so the import table is empty; console subsystem so the
# token ranzguard prints reaches the harden self-test.
target_link_options(ranzguard PRIVATE
  /NODEFAULTLIB
  /ENTRY:RanzGuardMain
  /SUBSYSTEM:CONSOLE
)
