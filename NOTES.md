
To discover where the widely used python package certifi reads its certificates from, run:

    python -m certifi





Print the available filesystem types:

    cat /proc/filesystems



# How can I set up gvisor to route packets from my TUN onwards to the internet, and back again?

Clues: stack.LinkEndpoint and stack.NetworkDispatcher

LinkEndpoint contains NetworkLinkEndpoint interface, which has the following:

	// Attach attaches the data link layer endpoint to the network-layer
	// dispatcher of the stack.
	//
	// Attach is called with a nil dispatcher when the endpoint's NIC is being
	// removed.
	Attach(dispatcher NetworkDispatcher)

The NetworkDispatch interface in full is:

    type NetworkDispatcher interface {
        // DeliverNetworkPacket finds the appropriate network protocol endpoint
        // and hands the packet over for further processing.
        //
        //
        // If the link-layer has a header, the packet's link header must be populated.
        //
        // DeliverNetworkPacket may modify pkt.
        DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer)

        // DeliverLinkPacket delivers a packet to any interested packet endpoints.
        //
        // This method should be called with both incoming and outgoing packets.
        //
        // If the link-layer has a header, the packet's link header must be populated.
        DeliverLinkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer)
    }

sniffer implements this as follows:

    // DeliverNetworkPacket implements the stack.NetworkDispatcher interface. It is
    // called by the link-layer endpoint being wrapped when a packet arrives, and
    // logs the packet before forwarding to the actual dispatcher.
    func (e *Endpoint) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {

Here are all the places this function is implemented:

    https://github.com/search?q=repo%3Agoogle%2Fgvisor%20DeliverNetworkPacket&type=code

One place it is implemented is nic, which is not exported but seems central:

    https://github.com/google/gvisor/blob/48b7308dcef150deacf42b62e9aea90451944946/pkg/tcpip/stack/nic.go#L163

For what it's worth here is the core implementation of socket in sentry, which intercepts all the linux syscalls in a container run by runsc. It is backed by a tcpip.Endpoint:

    https://github.com/google/gvisor/blob/48b7308dcef150deacf42b62e9aea90451944946/pkg/sentry/socket/netstack/netstack.go#L362

Even more concretely, here is the implementation fo accept(2) in sentry:

    https://github.com/google/gvisor/blob/48b7308dcef150deacf42b62e9aea90451944946/pkg/sentry/socket/unix/unix.go#L164

Sentry actually supports multiple "stacks" only one of which is tcpip.Stack. It also supports using the host network stack directly:

    https://github.com/google/gvisor/blob/48b7308dcef150deacf42b62e9aea90451944946/pkg/sentry/socket/hostinet/stack.go#L171

The general "Stack" interface is implemented in sentry/inet:

    https://github.com/google/gvisor/blob/48b7308dcef150deacf42b62e9aea90451944946/pkg/sentry/inet/inet.go#L28

The implementation for tcpip.Stack is in "netstack":

    https://github.com/google/gvisor/blob/48b7308dcef150deacf42b62e9aea90451944946/pkg/sentry/socket/netstack/stack.go#L42

Great overview of many of the low-level ways of sending out raw packets in linux:

    https://toonk.io/sending-network-packets-in-go/index.html

XDP is the latest way -- you write a packet filter in C and load it directly into the kernel! There are some examples of how to do this in gvisor:

    https://pkg.go.dev/gvisor.dev/gvisor/tools/xdp#section-readme

How to create IPv4 packets with gopacket:

    https://github.com/atoonk/go-pktgen/blob/main/pktgen/packet.go#L79

Docker desktop solves this issue by intercepting everything and accepting all TCP connections, then dynamically creating a TCP connection to real host:

    https://www.docker.com/blog/how-docker-desktop-networking-works-under-the-hood/

This is docker desktop, but what about ordinary docker daemon?

Here is a very helpful tutorial showing how to do it from scratch with veth pairs:

    https://labs.iximiuz.com/tutorials/container-networking-from-scratch

    ip netns list                           # list available network namespace
    ip netns add netns0                     # create a network namespace
    nsenter --net=/run/netns/netns0 bash    # enter a network namespace
    sudo iptables -t nat --list-rules       # list rules in the NAT table

    iptables -t nat -A POSTROUTING -s 172.18.0.0/16 ! -o br0 -j MASQUERADE      # THIS IS WHAT I NEED

    "The command is fairly simple when you know how iptables work - we added a new rule to the nat table of the POSTROUTING chain asking to masquerade all the packets originated in 172.18.0.0/16 network, except those that are going to the bridge interface."

OK so to do it with veth pairs the steps are:

    - turn on IP forwarding                                             echo 1 > /proc/sys/net/ipv4/ip_forward

    - create the namespace                                              ip netns add httptap-ns
    - create the veth pair                                              ip link add httptap-veth type veth peer name httptap-ceth
    - put one side of the veth pair into the namespace                  ip link set httptap-ceth netns httptap-ns
    - assign an IP address to the outer part of the pair                ip addr add 10.1.2.1/24 dev httptap-veth
    - bring up the out part of the pair                                 ip link set httptap-veth up
    - in the namespace, assign an IP address                            nsenter --net=/run/netns/httptap-ns ip addr add 10.1.2.50/24 dev httptap-ceth
    - in the namespace, route everything to one side of the veth pair   nsenter --net=/run/netns/httptap-ns ip route add default via 10.1.2.1
    - in the namespace, bring the device up                             nsenter --net=/run/netns/httptap-ns ip link set httptap-ceth up
    - setup NAT                                                         iptables -t nat -A POSTROUTING -s 10.1.2.0/24 ! -o httptap-veth -j MASQUERADE

    - in the namespace, ping 8.8.8.8                                    

Doing it with bridges to allow multiple namespaces to coexist on the same network is more complex. You basically have to:

    - create bridge                                 ip link add br0 type bridge
    - activate bridge                               ip link set br0 up
    - assign the interface to the bridge            ip link set veth0 master br0
    - give the bridge an IP address                 ip addr add 172.18.0.1/16 dev br0
 
In his example he gave the following addresses:

    For the outer part of the veth pair:        ip addr add 172.18.0.11/16 dev veth0
    For the inner part of the ceth pair:        ip addr add 172.18.0.10/16 dev ceth0

    (For the second container outer part:       ip addr add 172.18.0.21/16 dev veth1)
    (For the second container inner part:       ip addr add 172.18.0.20/16 dev ceth1)

    For the bridge:                             ip addr add 172.18.0.1/16 dev br0


This is extremely helpful


Here is a very simple example of port forwarding using tun devices (title says its a vpn but it's not):

    https://www.nsl.cz/using-tun-tap-in-go-or-how-to-write-vpn/

Permanently turning on IP forwarding:

    echo net.ipv4.ip_forward=1 >> /etc/sysctl.d/enable-ip-forward.conf

Check whether IP forwarding is on:

    sysctl net.ipv4.ip_forward

In the end I did not get a veth pair to work correctly with iptables masquerade
