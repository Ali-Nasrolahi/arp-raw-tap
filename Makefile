all: arp.c
	gcc -pedantic -Wall -Wextra arp.c -o arp -g

run: all
	sudo ./arp

clean:
	$(RM) arp

ovsup:
	sudo ip tuntap add tap0 mode tap
	sudo ovs-vsctl add-br br0
	sudo ovs-vsctl add-port br0 int0 -- set interface int0 type='internal'
	sudo ovs-vsctl add-port br0 tap0
	sudo ip l set up int0
	sudo ip l set up tap0
	sudo ip a add 172.16.60.157/24 dev int0

ovsdown:
	sudo ovs-vsctl del-br br0
	sudo ip tuntap del tap0 mode tap
