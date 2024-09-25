
veth-pair:
	sudo ip netns add httptap-ns
	sudo ip link add httptap-veth type veth peer name httptap-ceth
	sudo ip link set httptap-veth up
	sudo ip link set httptap-ceth netns httptap-ns
	sudo ip link add httptap-br type bridge
	sudo ip link set httptap-br up
	sudo ip link set httptap-veth master httptap-br
	sudo ip addr add 10.0.0.1/24 dev httptap-br
	sudo ip netns exec httptap-ns ip link set lo up
	sudo ip netns exec httptap-ns ip link set httptap-ceth up
	sudo ip netns exec httptap-ns ip addr add 10.0.0.50/24 dev httptap-ceth
	sudo ip netns exec httptap-ns ip route add default via 10.0.0.1
	sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/24 ! -o httptap-br -j MASQUERADE

veth-ping:
	sudo ip netns exec httptap-ns ping 8.8.8.8

veth-bash:
	sudo ip netns exec httptap-ns bash

cleanup-veth-pair:
	-sudo ip netns del httptap-ns
	-sudo ip link del httptap-br
