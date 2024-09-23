DEVICE := httptap2
ADDRESS := 10.1.2.4
PORT := 19870
SUBNET := 10.1.2.255/24

default: run

run:
	go build -o .bin ./echo
	sudo ./.bin --tun $(DEVICE) --address $(ADDRESS) --port $(PORT)

create-tun:
	sudo ip tuntap add user $(USER) mode tun $(DEVICE)

bring-tun-up:
	sudo ip link set $(DEVICE) up

assign-address:
	sudo ip addr add $(SUBNET) dev $(DEVICE)

ping:
	echo abc | netcat -q 1 $(ADDRESS) $(PORT)
