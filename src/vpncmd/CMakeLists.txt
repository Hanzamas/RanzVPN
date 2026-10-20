# vpncmd (cmake/RanzExecutable.cmake): a console executable with the hamcore files as resources
ranz_add_executable(vpncmd HAMCORE
  DESCRIPTION "Command Line Management Utility"
  ICON "vpncmd.ico"
  SOURCES
    "vpncmd.c"
)
