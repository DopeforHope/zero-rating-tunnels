#!/bin/bash

# OPPOSING_IP is the IP of the other NATing device (Laptop or Pi)
OPPOSING_IP=192.168.42.45
# IP of the device which is behind the here provided NAT
CLIENT_NAT_IP=192.168.64.11
# IP of the router
ROUTER_WAN_IP=130.149.39.112

echo "OPPOSING_IP: $OPPOSING_IP"
echo "CLIENT_NAT_IP: $CLIENT_NAT_IP"
echo "ROUTER_WAN_IP: $ROUTER_WAN_IP"

# block direct traffic between opposing device and NAT client
sudo iptables -I FORWARD 1 -s $OPPOSING_IP -d $CLIENT_NAT_IP -j DROP
sudo iptables -I FORWARD 1 -d $OPPOSING_IP -s $CLIENT_NAT_IP -j DROP

# block direct traffic between router and NAT client
sudo iptables -I FORWARD 1 -s $ROUTER_WAN_IP -d $CLIENT_NAT_IP -j DROP
sudo iptables -I FORWARD 1 -d $ROUTER_WAN_IP -s $CLIENT_NAT_IP -j DROP

