#!/bin/bash

ip netns add ns1
ip link add veth0 type veth peer name veth1 netns ns1
ip -n ns1 addr add dev veth1 2001:db8:100::2/128 
ip link set veth0 up
ip -n ns1 link set veth1 up
# turn off offloading to ensure not corrupted packet
ip netns exec ns1 ethtool --offload veth1 tx off
ip netns exec ns1 ip -6 route add default dev veth1
