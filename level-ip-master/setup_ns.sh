#!/bin/bash

# Setup network namespace with veth pair, start xterm in it

# nsterm ns0 veth0 10.0.0 24

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

NS=ns0
DEV=veth0
DEV_A=${DEV}a
DEV_B=${DEV}b
ADDR=10.0.0
ADDR_A=${ADDR}.254
ADDR_B=${ADDR}.1
MASK=24

# echo ns=$NS dev=$DEV col=$COL mask=$MASK

ip netns add $NS
ip link add $DEV_A type veth peer name $DEV_B netns $NS
ip addr add $ADDR_A/$MASK dev $DEV_A
ip link set ${DEV}a up
ip netns exec $NS ip addr add $ADDR_B/$MASK dev $DEV_B
ip netns exec $NS ip link set ${DEV}b up
ip netns exec $NS ip route add default via $ADDR_A dev $DEV_B


#ip link add $DEV_A type veth peer name $DEV_B
#ip addr add $ADDR_A/$MASK dev $DEV_A
#ip link set ${DEV}a up
#ip addr add $ADDR_B/$MASK dev $DEV_B
#ip link set ${DEV}b up
#ip route add default via $ADDR_A dev $DEV_B

iptables -F OUTPUT
iptables -A OUTPUT -p tcp -o ${DEV}a --tcp-flags RST RST -j DROP
ip netns exec $NS iptables -F OUTPUT
ip netns exec $NS iptables -A OUTPUT -p tcp -o ${DEV}b --tcp-flags RST RST -j DROP

iptables -F INPUT
#iptables -A INPUT -p tcp -i ${DEV}a --tcp-flags RST RST -j DROP
ip netns exec $NS iptables -F INPUT
#ip netns exec $NS iptables -A INPUT -p tcp -i ${DEV}b --tcp-flags RST RST -j DROP
