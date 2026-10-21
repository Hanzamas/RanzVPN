# ranz-node (cmake/RanzExecutable.cmake): the node of the new core, a Windows GUI subsystem executable with
# the hamcore files as resources, run as the ranzvpnserver service. It shares the icon of vpnserver.
ranz_add_executable(ranz-node WIN32 HAMCORE
  DESCRIPTION "Node"
  ICON "../vpnserver/Server.ico"
  SOURCES
    "ranz-node.c"
)
