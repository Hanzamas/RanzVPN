# vpnserver (cmake/RanzExecutable.cmake): a Windows GUI subsystem executable with the hamcore
# files as resources
ranz_add_executable(vpnserver WIN32 HAMCORE
  DESCRIPTION "Server"
  ICON "Server.ico"
  SOURCES
    "vpnserver.c"
)
