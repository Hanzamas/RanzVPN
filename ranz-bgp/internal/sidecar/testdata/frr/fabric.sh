#!/usr/bin/env bash
# The fabric of TestFRREVPN (frr_test.go; SDN-25 #201), which the job "EVPN with FRR" of ranz.yml starts: FRR, the
# reference BGP speaker of a data-centre fabric (ADR-0032), in a container of its own on the bridge ranz-fabric of this
# runner, which stands in for the second host (ADR-0002 amendment of 2026-10-21). The runner is the gateway, on
# 172.31.25.1; the container is one leaf of the fabric, on 172.31.25.10, its VTEP. Each VRF of the leaf is a VRF of the
# kernel of the container with its L3 VNI on a VXLAN device in a bridge whose MAC is the router MAC of the VRF, as FRR
# documents EVPN type-5 with symmetric routing, and the LAN 172.16.1.1/24 and fd16::1/64 on a dummy device: red on VNI
# 10101 with the router MAC 02:00:5e:10:00:01, blue on VNI 10102 with 02:00:5e:10:00:02. FRR (frr.conf and daemons next
# to this script) starts once the devices are there.
#
# The argument is the image of FRR, which ranz.yml pins by its digest. The container is ranz-frr.
set -euo pipefail

image="$1"
here="$(cd "$(dirname "$0")" && pwd)"
name=ranz-frr

# The VRF, VXLAN and dummy devices need their modules, which the kernel of the runner may keep in linux-modules-extra
for module in vrf vxlan dummy; do
  if ! sudo modprobe "$module"; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq "linux-modules-extra-$(uname -r)"
    sudo modprobe "$module"
  fi
done

docker network create --driver bridge --subnet 172.31.25.0/24 --gateway 172.31.25.1 ranz-fabric
docker run -d --name "$name" --privileged --network ranz-fabric --ip 172.31.25.10 \
  --sysctl net.ipv6.conf.all.disable_ipv6=0 --sysctl net.ipv6.conf.default.disable_ipv6=0 \
  "$image" tail -f /dev/null
pid="$(docker inspect -f '{{.State.Pid}}' "$name")"

# ip of the runner in the network namespace of the container
ns() {
  sudo nsenter -t "$pid" -n ip "$@"
}

# A VRF of the leaf: its name, its routing table, its L3 VNI and its router MAC
vrf() {
  ns link add "$1" type vrf table "$2"
  ns link set "$1" up
  ns link add "br$3" type bridge
  ns link set "br$3" address "$4"
  ns link set "br$3" master "$1"
  ns link add "vxlan$3" type vxlan id "$3" local 172.31.25.10 dstport 4789 nolearning
  ns link set "vxlan$3" master "br$3"
  ns link set "vxlan$3" up
  ns link set "br$3" up
  ns link add "lan-$1" type dummy
  ns link set "lan-$1" master "$1"
  ns addr add 172.16.1.1/24 dev "lan-$1"
  ns -6 addr add fd16::1/64 dev "lan-$1" nodad
  ns link set "lan-$1" up
}
vrf red 1001 10101 02:00:5e:10:00:01
vrf blue 1002 10102 02:00:5e:10:00:02
ns -d link show
ns addr show

docker cp "$here/frr.conf" "$name:/etc/frr/frr.conf"
docker cp "$here/daemons" "$name:/etc/frr/daemons"
docker exec "$name" chown -R frr:frr /etc/frr
docker exec "$name" /usr/lib/frr/frrinit.sh start

# bgpd has the VRF blue, the last of the configuration, within a minute
ready=0
for attempt in $(seq 1 60); do
  if docker exec "$name" vtysh -c 'show bgp vrf blue summary' > /dev/null 2>&1; then
    ready=$attempt
    break
  fi
  sleep 1
done
if [ "$ready" = 0 ]; then
  docker exec "$name" cat /tmp/frr.log || true
  echo "::error::bgpd of FRR did not answer within 60 s"
  exit 1
fi
echo "bgpd of FRR answered after $ready s"
docker exec "$name" vtysh -c 'show version' -c 'show evpn vni' -c 'show bgp vrf all summary'
