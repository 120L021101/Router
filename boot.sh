ip link add veth1 type veth peer name veth2

ip link set veth1 up
ip link set veth2 up

ip addr add 192.168.1.1/24 dev veth1
ip addr add 192.168.1.2/24 dev veth2
