# ranz-node (cmake/RanzExecutable.cmake): the node of the new core, a Windows GUI subsystem executable with
# the hamcore files as resources, run as the ranzvpnserver service. Its icon is the one of the retired
# vpnserver (CORE-S8-1, #84).
ranz_add_executable(ranz-node WIN32 HAMCORE
  DESCRIPTION "Node"
  ICON "Node.ico"
  SOURCES
    "ranz-node.c"
)
