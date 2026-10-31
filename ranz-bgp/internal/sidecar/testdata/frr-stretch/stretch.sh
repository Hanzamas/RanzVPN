#!/usr/bin/env bash
# The fabric of TestFRRStretch (frr_stretch_test.go; SDN-64 #291), which the job "EVPN with FRR" of ranz.yml starts after the
# one of TestFRREVPN: two leaves of a data-centre fabric, FRR in a container of its own each, on the bridge ranz-stretch of
# this runner, which stands in for the second host (ADR-0002 amendment of 2026-10-21). The runner is the gateway, on
# 172.31.26.1; leaf a is on 172.31.26.10 (AS 65010) and leaf b on 172.31.26.11 (AS 65011), each address its VTEP. Each leaf
# carries the L2 VNI 5010 of the stretched Network, route target 65000:5010: a VXLAN device in a bridge of the kernel of the
# container, which does not learn on the VXLAN device and suppresses ARP and neighbour discovery there (neigh_suppress), so
# that the bridge answers an ARP request for a host of a type-2 route of MAC plus IP itself, as FRR documents ARP and ND
# suppression. Behind each leaf is a host of the fabric, a network namespace of this runner on a veth pair into the bridge:
# ranz-host-a, 10.50.0.10 with the MAC address 02:00:5e:50:00:0a, behind leaf a, and ranz-host-b, 10.50.0.11 with
# 02:00:5e:50:00:0b, behind leaf b. The hosts answer an ICMP echo request to the broadcast address, and have no IPv6, so that
# they send nothing into the Network by themselves. FRR (leaf-a.conf, leaf-b.conf, and the daemons and vtysh.conf of
# ../frr) starts once the devices are there.
#
# The argument is the image of FRR, which ranz.yml pins by its digest. The containers are ranz-leaf-a and ranz-leaf-b.
set -euo pipefail

image="$1"
here="$(cd "$(dirname "$0")" && pwd)"

# The VXLAN and veth devices need their modules, which the kernel of the runner may keep in linux-modules-extra
for module in vxlan veth; do
  if ! sudo modprobe "$module"; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq "linux-modules-extra-$(uname -r)"
    sudo modprobe "$module"
  fi
done

docker network create --driver bridge --subnet 172.31.26.0/24 --gateway 172.31.26.1 ranz-stretch

# A leaf: its name, its address and VTEP, its configuration, and its host: the name of the namespace, the address and the MAC
leaf() {
  local name="$1" vtep="$2" conf="$3" host="$4" address="$5" mac="$6"
  docker run -d --name "$name" --privileged --network ranz-stretch --ip "$vtep" "$image" tail -f /dev/null
  local pid
  pid="$(docker inspect -f '{{.State.Pid}}' "$name")"

  # The L2 VNI in the bridge of the leaf, which suppresses ARP and ND on its VXLAN device and learns nothing there
  sudo nsenter -t "$pid" -n ip link add br5010 type bridge
  sudo nsenter -t "$pid" -n ip link add vxlan5010 type vxlan id 5010 local "$vtep" dstport 4789 nolearning
  sudo nsenter -t "$pid" -n ip link set vxlan5010 master br5010
  sudo nsenter -t "$pid" -n bridge link set dev vxlan5010 neigh_suppress on learning off
  sudo nsenter -t "$pid" -n ip link set vxlan5010 up
  sudo nsenter -t "$pid" -n ip link set br5010 up

  # The host of the fabric behind the leaf
  sudo ip netns add "$host"
  sudo ip link add "$host" type veth peer name "$host-br"
  sudo ip link set "$host" netns "$host"
  sudo ip link set "$host-br" netns "$pid"
  sudo ip netns exec "$host" sysctl -qw net.ipv6.conf.all.disable_ipv6=1
  sudo ip netns exec "$host" sysctl -qw net.ipv6.conf.default.disable_ipv6=1
  sudo ip netns exec "$host" sysctl -qw net.ipv4.icmp_echo_ignore_broadcasts=0
  sudo ip netns exec "$host" ip link set "$host" address "$mac"
  sudo ip netns exec "$host" ip addr add "$address/24" dev "$host"
  sudo ip netns exec "$host" ip link set lo up
  sudo ip netns exec "$host" ip link set "$host" up
  sudo nsenter -t "$pid" -n ip link set "$host-br" master br5010
  sudo nsenter -t "$pid" -n ip link set "$host-br" up
  sudo nsenter -t "$pid" -n ip -d link show
  sudo nsenter -t "$pid" -n bridge -d link show

  docker cp "$here/$conf" "$name:/etc/frr/frr.conf"
  docker cp "$here/../frr/daemons" "$name:/etc/frr/daemons"
  docker cp "$here/../frr/vtysh.conf" "$name:/etc/frr/vtysh.conf"
  docker exec "$name" chown -R frr:frr /etc/frr
  docker exec "$name" /usr/lib/frr/frrinit.sh start
}

leaf ranz-leaf-a 172.31.26.10 leaf-a.conf ranz-host-a 10.50.0.10 02:00:5e:50:00:0a
leaf ranz-leaf-b 172.31.26.11 leaf-b.conf ranz-host-b 10.50.0.11 02:00:5e:50:00:0b

# zebra of each leaf has the L2 VNI and bgpd answers within a minute
for name in ranz-leaf-a ranz-leaf-b; do
  ready=0
  for attempt in $(seq 1 60); do
    if docker exec "$name" vtysh -c 'show bgp l2vpn evpn summary' > /dev/null 2>&1 &&
      docker exec "$name" vtysh -c 'show evpn vni 5010' 2> /dev/null | grep -q 5010; then
      ready=$attempt
      break
    fi
    sleep 1
  done
  if [ "$ready" = 0 ]; then
    docker exec "$name" cat /tmp/frr.log || true
    echo "::error::FRR of $name did not carry the VNI 5010 within 60 s"
    exit 1
  fi
  echo "FRR of $name answered after $ready s"
  docker exec "$name" vtysh -c 'show version' -c 'show evpn vni 5010' -c 'show bgp l2vpn evpn summary'
done
