# ranz-node (cmake/RanzExecutable.cmake): the node of the new core, a Windows GUI subsystem executable with
# the hamcore files as resources, run as the ranzvpnserver service. Its icon is the one of the retired
# vpnserver (CORE-S8-1, #84). The linker map shows every object and symbol that it links: CI uploads it and
# checks that it holds none of the SE-VPN code of the slim fork (step "ranz-node links no SE-VPN code" of
# windows.yml; CORE-S8-2, #576).
ranz_add_executable(ranz-node WIN32 HAMCORE
  DESCRIPTION "Node"
  ICON "Node.ico"
  SOURCES
    "ranz-node.c"
  LINK_OPTIONS
    "/MAP:${BUILD_DIRECTORY}/ranz-node.map"
)
