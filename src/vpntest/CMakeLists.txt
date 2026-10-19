# vpntest (cmake/RanzExecutable.cmake): a console executable with the hamcore files as resources
ranz_add_executable(vpntest HAMCORE
  DESCRIPTION "Testing Utility"
  ICON "vpntest.ico"
  SOURCES
    vpntest.c harness.c harness_pack.c stress.c runtime.c crypto.c
    # Named string test of NAT-4 (#90)
    strtest.c
    # Named UDP Acceleration receive test of FIX-1 (#97)
    udpaccel.c
    # Named SeLow test of FIX-2 (#98)
    selowtest.c
    # Named DLL search order test of FIX-4 (#100)
    dllsearch.c
    # Named machine identity test of FIX-5 (#101)
    machineid.c
    # Named VM detection test of FIX-7 (#103)
    vmdetect.c
    # Named TCP/IP packet test of SEC-1 (#96)
    tcpiptest.c
    # Named X.509 and certificate signature test of SEC-2 (#96)
    x509test.c
    # Named BUF and binary configuration bounds test of SEC-3 (#96)
    bufbounds.c
    # Named keepalive span and client Pack size cap tests of SEC-4 (#96)
    keepalive.c packcap.c
    # Named StorePacket test of SEC-5 (#96)
    storepacket.c
    # Named console input test of SEC-7 (#96)
    consoleline.c
    # Named temp directory and string table test of SEC-8 (#96)
    tempdir.c
    # vpncmd command cases of the harness (golden family "cmd"), PKG-2 (#106)
    harness_cmd.c
    # Named log writer, syslog and eraser tests of PKG-4 (#108)
    logtest.c
    # Named login path tests of PKG-6 (#110)
    login.c
    # Named packet parser tests of PKG-9 (#113)
    pkttest.c
    # Named PACK decoder bounds test of FND-42 (#114)
    packdecode.c
    # Named string table loader test of FND-43 (#114)
    tablecache.c
    # Named registry test of FND-64 (#121)
    registry.c
  # The resources test (runtime.c) compares every hamcore file the executable serves with its source
  # file. A C-only definition, so the resource scripts of vpntest do not get the quoted path.
  C_DEFINITIONS
    "RANZ_HAMCORE_SOURCE_DIR=\"${TOP_DIRECTORY}/src/bin/hamcore\""
)
