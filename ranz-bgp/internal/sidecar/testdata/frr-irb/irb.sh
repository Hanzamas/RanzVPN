#!/usr/bin/env bash
# The fabric of TestFRRIRB (frr_irb_test.go; SDN-67 #294), which the job "EVPN with FRR" of ranz.yml starts after the one of
# TestFRRStretch: one leaf of a data-centre fabric with symmetric IRB, FRR in a container of its own on the bridge ranz-irb of
# this runner, which stands in for the second host (ADR-0002 amendment of 2026-10-21). The runner is the gateway, on
# 172.31.27.1; the leaf is on 172.31.27.10 (AS 65020), its VTEP.
#
# The leaf has two VRFs of its kernel, each with its L3 VNI on a VXLAN device in a bridge whose MAC is the router MAC of the
# VRF, as fabric.sh has them: red on VNI 10201 with the router MAC 02:00:5e:20:00:01, blue on VNI 10202 with 02:00:5e:20:00:02.
# In each VRF is the same stretched Network 10.50.0.0/24, on an L2 VNI of its own (5020 in red, 5021 in blue): a VXLAN device
# in a bridge that does not learn on the VXLAN device and suppresses ARP there (neigh_suppress), as stretch.sh has it, and the
# bridge is the SVI of the Network in the VRF, with the address 10.50.0.254 of the leaf, so that the leaf routes for its hosts
# as FRR documents symmetric IRB. Behind each bridge is a host of the fabric, a network namespace of this runner on a veth pair
# into the bridge, with the same address in both VRFs and the leaf as its first hop: ranz-irb-red, 10.50.0.10 with the MAC
# address 02:00:5e:50:20:0a, and ranz-irb-blue, 10.50.0.10 with 02:00:5e:50:21:0a. The hosts have no IPv6, so that they send
# nothing into the Network by themselves. The leaf carries the L2 VNI 5030 too, in a bridge of no VRF: the Network of a stretch
# without irb. The leaf forwards IPv4, between its SVIs and its L3 VNIs. FRR (leaf.conf, and the daemons and vtysh.conf of
# ../frr) starts once the devices are there.
#
# The argument is the image of FRR, which ranz.yml pins by its digest. The container is ranz-irb-leaf.
set -euo pipefail

image="$1"
here="$(cd "$(dirname "$0")" && pwd)"
name=ranz-irb-leaf
vtep=172.31.27.10

# The VRF, VXLAN and veth devices need their modules, which the kernel of the runner may keep in linux-modules-extra
for module in vrf vxlan veth; do
  if ! sudo modprobe "$module"; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq "linux-modules-extra-$(uname -r)"
    sudo modprobe "$module"
  fi
done

docker network create --driver bridge --subnet 172.31.27.0/24 --gateway 172.31.27.1 ranz-irb
docker run -d --name "$name" --privileged --network ranz-irb --ip "$vtep" "$image" tail -f /dev/null
pid="$(docker inspect -f '{{.State.Pid}}' "$name")"

# ip of the runner in the network namespace of the leaf
ns() {
  sudo nsenter -t "$pid" -n ip "$@"
}

# The leaf routes between the SVIs of its Networks and its L3 VNIs
sudo nsenter -t "$pid" -n sysctl -qw net.ipv4.ip_forward=1

# A VRF of the leaf: its name, its routing table, its L3 VNI and its router MAC
vrf() {
  ns link add "$1" type vrf table "$2"
  ns link set "$1" up
  ns link add "br$3" type bridge
  ns link set "br$3" address "$4"
  ns link set "br$3" master "$1"
  ns link add "vxlan$3" type vxlan id "$3" local "$vtep" dstport 4789 nolearning
  ns link set "vxlan$3" master "br$3"
  ns link set "vxlan$3" up
  ns link set "br$3" up
}

# An L2 VNI of the leaf, in a bridge that suppresses ARP on its VXLAN device and learns nothing there: the VNI, and the VRF
# whose SVI the bridge is, with the address of the leaf in the Network, or nothing for a bridge of no VRF
l2vni() {
  ns link add "br$1" type bridge
  ns link add "vxlan$1" type vxlan id "$1" local "$vtep" dstport 4789 nolearning
  ns link set "vxlan$1" master "br$1"
  sudo nsenter -t "$pid" -n bridge link set dev "vxlan$1" neigh_suppress on learning off
  ns link set "vxlan$1" up
  if [ $# -gt 1 ]; then
    ns link set "br$1" master "$2"
    ns addr add 10.50.0.254/24 dev "br$1"
  fi
  ns link set "br$1" up
}

# A host of the fabric behind the bridge of an L2 VNI: the name of its namespace, the VNI, and its MAC address; its address is
# 10.50.0.10, and the leaf is its first hop
host() {
  local host="$1" vni="$2" mac="$3"
  sudo ip netns add "$host"
  sudo ip link add "$host" type veth peer name "$host-br"
  sudo ip link set "$host" netns "$host"
  sudo ip link set "$host-br" netns "$pid"
  sudo ip netns exec "$host" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
  sudo ip netns exec "$host" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
  sudo ip netns exec "$host" ip link set "$host" address "$mac"
  sudo ip netns exec "$host" ip addr add 10.50.0.10/24 dev "$host"
  sudo ip netns exec "$host" ip link set lo up
  sudo ip netns exec "$host" ip link set "$host" up
  sudo ip netns exec "$host" ip route add default via 10.50.0.254
  ns link set "$host-br" master "br$vni"
  ns link set "$host-br" up
}

vrf red 1001 10201 02:00:5e:20:00:01
vrf blue 1002 10202 02:00:5e:20:00:02
l2vni 5020 red
l2vni 5021 blue
l2vni 5030
host ranz-irb-red 5020 02:00:5e:50:20:0a
host ranz-irb-blue 5021 02:00:5e:50:21:0a
ns -d link show
ns addr show
sudo nsenter -t "$pid" -n bridge -d link show

docker cp "$here/leaf.conf" "$name:/etc/frr/frr.conf"
docker cp "$here/../frr/daemons" "$name:/etc/frr/daemons"
docker cp "$here/../frr/vtysh.conf" "$name:/etc/frr/vtysh.conf"
docker exec "$name" chown -R frr:frr /etc/frr
docker exec "$name" /usr/lib/frr/frrinit.sh start

# zebra has the L2 VNIs, and bgpd the VRF blue, the last of the configuration, within a minute
ready=0
for attempt in $(seq 1 60); do
  if docker exec "$name" vtysh -c 'show bgp vrf blue summary' > /dev/null 2>&1 &&
    docker exec "$name" vtysh -c 'show evpn vni 5030' 2> /dev/null | grep -q 5030; then
    ready=$attempt
    break
  fi
  sleep 1
done
if [ "$ready" = 0 ]; then
  docker exec "$name" cat /tmp/frr.log || true
  echo "::error::FRR of $name did not carry the VNI 5030 and the VRF blue within 60 s"
  exit 1
fi
echo "FRR of $name answered after $ready s"
docker exec "$name" vtysh -c 'show version' -c 'show evpn vni' -c 'show bgp vrf all summary'
