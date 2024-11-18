package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/alexflint/go-arg"
	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/joemiller/certin"
	"github.com/mdlayher/packet"
	"github.com/monasticacademy/httptap/pkg/certfile"
	"github.com/monasticacademy/httptap/pkg/opensslpaths"
	"github.com/monasticacademy/httptap/pkg/overlay"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/rawfile"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const dumpPacketsToSubprocess = false
const dumpPacketsFromSubprocess = false
const ttl = 10

type AddrPort struct {
	Addr net.IP
	Port uint16
}

func (ap AddrPort) String() string {
	return ap.Addr.String() + ":" + strconv.Itoa(int(ap.Port))
}

// copyToDevice copies packets from a channel to a tun device
func copyToDevice(ctx context.Context, dst *water.Interface, src chan []byte) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case packet := <-src:
			_, err := dst.Write(packet)
			if err != nil {
				errorf("error writing %d bytes to tun: %v, dropping and continuing...", len(packet), err)
			}

			if dumpPacketsToSubprocess {
				reply := gopacket.NewPacket(packet, layers.LayerTypeIPv4, gopacket.Default)
				verbose(strings.Repeat("\n", 3))
				verbose(strings.Repeat("=", 80))
				verbose("To subprocess:")
				verbose(reply.Dump())
			} else {
				verbosef("transmitting %v raw bytes to subprocess", len(packet))
			}
		}
	}
}

// readFromDevice parses packets from a tun device and delivers them to the TCP and UDP stacks
func readFromDevice(ctx context.Context, tun *water.Interface, tcpstack *tcpStack, udpstack *udpStack) error {
	// start reading raw bytes from the tunnel device and sending them to the appropriate stack
	buf := make([]byte, 1500)
	for {
		// read a packet (TODO: implement non-blocking read on the file descriptor, check for context cancellation)
		n, err := tun.Read(buf)
		if err != nil {
			errorf("error reading a packet from tun: %v, ignoring", err)
			continue
		}

		packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.Default)
		ipv4, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if !ok {
			continue
		}

		tcp, isTCP := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
		udp, isUDP := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !isTCP && !isUDP {
			continue
		}

		if dumpPacketsFromSubprocess {
			verbose(strings.Repeat("\n", 3))
			verbose(strings.Repeat("=", 80))
			verbose("From subprocess:")
			verbose(packet.Dump())
		}

		if isTCP {
			verbosef("received from subprocess: %v", summarizeTCP(ipv4, tcp, tcp.Payload))
			tcpstack.handlePacket(ipv4, tcp, tcp.Payload)
		}
		if isUDP {
			verbosef("received from subprocess: %v", summarizeUDP(ipv4, udp, udp.Payload))
			udpstack.handlePacket(ipv4, udp, udp.Payload)
		}
	}
}

// layernames makes a one-line list of layers in a packet
func layernames(packet gopacket.Packet) []string {
	var s []string
	for _, layer := range packet.Layers() {
		s = append(s, layer.LayerType().String())
	}
	return s
}

var isVerbose bool

func verbose(msg string) {
	if isVerbose {
		log.Print(msg)
	}
}

func verbosef(fmt string, parts ...interface{}) {
	if isVerbose {
		log.Printf(fmt, parts...)
	}
}

var errorColor = color.New(color.FgRed, color.Bold)

func errorf(fmt string, parts ...interface{}) {
	if !strings.HasSuffix(fmt, "\n") {
		fmt += "\n"
	}
	errorColor.Printf(fmt, parts...)
}

func Main() error {
	ctx := context.Background()
	var args struct {
		Verbose            bool     `arg:"-v,--verbose,env:HTTPTAP_VERBOSE"`
		NoNewUserNamespace bool     `arg:"--no-new-user-namespace,env:HTTPTAP_NO_NEW_USER_NAMESPACE" help:"do not create a new user namespace (must be run as root)"`
		Stderr             bool     `arg:"env:HTTPTAP_LOG_TO_STDERR" help:"log to stderr (default is stdout)"`
		Tun                string   `default:"httptap" help:"name of the network device to create"`
		Subnet             string   `default:"10.1.1.100/24" help:"IP address of the network interface that the subprocess will see"`
		Gateway            string   `default:"10.1.1.1" help:"IP address of the gateway that intercepts and proxies network packets"`
		WebUI              string   `arg:"env:HTTPTAP_WEB_UI" help:"address and port to serve API on"`
		User               string   `help:"run command as this user (username or id)"`
		NoOverlay          bool     `arg:"--no-overlay,env:HTTPTAP_NO_OVERLAY" help:"do not mount any overlay filesystems"`
		Stack              string   `arg:"env:HTTPTAP_STACK" default:"gvisor" help:"'gvisor' or 'homegrown'"`
		Dump               bool     `arg:"env:HTTPTAP_DUMP" help:"dump all packets sent and received"`
		Command            []string `arg:"positional"`
	}
	arg.MustParse(&args)

	if len(args.Command) == 0 {
		args.Command = []string{"/bin/sh"}
	}
	if args.Stderr {
		log.SetOutput(os.Stderr)
	}

	isVerbose = args.Verbose

	// first we re-exec ourselves in a new user namespace
	if os.Args[0] != "/proc/self/exe" && !args.NoNewUserNamespace {
		verbosef("re-execing in a new user namespace...")

		// Here we move to a new user namespace, which is an unpriveleged operation, and which
		// allows us to do everything else we need to do in unpriveleged mode.
		//
		// In a C program, we could run unshare(CLONE_NEWUSER) and directly be in a new user
		// namespace. In a Go program that is not possible because all Go programs are multithreaded
		// (even with GOMAXPROCS=1), and unshare(CLONE_NEWUSER) is only available to single-threaded
		// programs.
		//
		// Our best option is then to launch ourselves in a subprocess that is in a new user namespace,
		// using /proc/self/exe, which contains the executable code for the current process.

		cmd := exec.Command("/proc/self/exe")
		cmd.Args = append([]string{"/proc/self/exe"}, os.Args[1:]...)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Cloneflags: syscall.CLONE_NEWUSER,
			UidMappings: []syscall.SysProcIDMap{{
				ContainerID: 0,
				HostID:      os.Getuid(),
				Size:        1,
			}},
			GidMappings: []syscall.SysProcIDMap{{
				ContainerID: 0,
				HostID:      os.Getgid(),
				Size:        1,
			}},
		}
		err := cmd.Run()
		// if the subprocess exited with an error code then do not print any
		// extra information but do exit with the same code
		if exiterr, ok := err.(*exec.ExitError); ok {
			os.Exit(exiterr.ExitCode())
		}
		if err != nil {
			return fmt.Errorf("error re-exec'ing ourselves in a new user namespace: %w", err)
		}
		return nil
	}

	verbosef("running assuming we are in a user namespace...")

	// generate a root certificate authority
	ca, err := certin.NewCert(nil, certin.Request{CN: "root CA", IsCA: true})
	if err != nil {
		return fmt.Errorf("error creating root CA: %w", err)
	}

	// create a temporary directory
	tempdir, err := os.MkdirTemp("", "")
	if err != nil {
		return fmt.Errorf("error creating temporary directory: %w", err)
	}
	defer os.RemoveAll(tempdir)

	// write certificate authority to PEM file
	caPath := filepath.Join(tempdir, "ca-certificates.crt")
	err = certfile.WritePEM(caPath, ca.Certificate)
	if err != nil {
		return fmt.Errorf("error writing certificate authority to temporary PEM file: %w", err)
	}
	verbosef("created %v", caPath)

	// write certificate authority to another common PEM file
	caPath2 := filepath.Join(tempdir, "ca-bundle.crt")
	err = certfile.WritePEM(caPath2, ca.Certificate)
	if err != nil {
		return fmt.Errorf("error writing certificate authority to temporary PEM file: %w", err)
	}
	verbosef("created %v", caPath2)

	// write the certificate authority to a temporary PKCS12 file
	// write certificate authority to PEM file
	caPathPKCS12 := filepath.Join(tempdir, "ca-certificates.pkcs12")
	err = certfile.WritePKCS12(caPathPKCS12, ca.Certificate)
	if err != nil {
		return fmt.Errorf("error writing certificate authority to temporary PEM file: %w", err)
	}
	verbosef("created %v", caPathPKCS12)

	// lock the OS thread because network and mount namespaces are specific to a single OS thread
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// create a new network namespace
	if err := unix.Unshare(unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("error creating network namespace: %w", err)
	}

	// create a tun device in the new namespace
	tun, err := water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: args.Tun,
		},
	})
	if err != nil {
		return fmt.Errorf("error creating tun device: %w", err)
	}

	// find the link for the device we just created
	link, err := netlink.LinkByName(args.Tun)
	if err != nil {
		return fmt.Errorf("error finding link for new tun device %q: %w", args.Tun, err)
	}

	// bring the link up
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("error bringing up link for %q: %w", args.Tun, err)
	}

	// parse the subnet that we will assign to the interface within the namespace
	linksubnet, err := netlink.ParseIPNet(args.Subnet)
	if err != nil {
		return fmt.Errorf("error parsing subnet: %w", err)
	}

	// assign the address we just parsed to the link, which will change the routing table
	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: linksubnet,
	})
	if err != nil {
		return fmt.Errorf("error assign address to tun device: %w", err)
	}

	// parse the subnet that we will route to the tunnel
	catchall, err := netlink.ParseIPNet("0.0.0.0/0")
	if err != nil {
		return fmt.Errorf("error parsing global subnet: %w", err)
	}

	// parse the gateway that we will act as
	gateway := net.ParseIP(args.Gateway)
	if gateway == nil {
		return fmt.Errorf("error parsing gateway: %v", args.Gateway)
	}

	// add a route that sends all traffic going anywhere to our local address
	err = netlink.RouteAdd(&netlink.Route{
		Dst: catchall,
		Gw:  gateway,
	})
	if err != nil {
		return fmt.Errorf("error creating default route: %w", err)
	}

	// if --dump was provided then start watching everything
	if args.Dump {
		iface, err := net.InterfaceByName(args.Tun)
		if err != nil {
			return err
		}

		// packet.Raw means listen for raw IP packets (requires root permissions)
		// unix.ETH_P_ALL means listen for all packets
		conn, err := packet.Listen(iface, packet.Raw, unix.ETH_P_ALL, nil)
		if err != nil {
			if errors.Is(err, unix.EPERM) {
				return fmt.Errorf("you need root permissions to read raw packets (%w)", err)
			}
			return fmt.Errorf("error listening for raw packet: %w", err)
		}

		// set promiscuous mode so that we see everything
		err = conn.SetPromiscuous(true)
		if err != nil {
			return fmt.Errorf("error setting raw packet connection to promiscuous mode: %w", err)
		}

		go func() {
			// read packets forever
			buf := make([]byte, iface.MTU)
			for {
				n, _, err := conn.ReadFrom(buf)
				if err != nil {
					log.Printf("error reading raw packet: %w, aborting dump", err)
					return
				}

				// decode and dump
				packet := gopacket.NewPacket(buf[:n], layers.LayerTypeIPv4, gopacket.NoCopy)
				log.Println(packet.Dump())
			}
		}()
	}

	// if /etc/ is a directory then set up an overlay
	if st, err := os.Lstat("/etc"); err == nil && st.IsDir() && !args.NoOverlay {
		verbose("overlaying /etc ...")

		// overlay resolv.conf
		mount, err := overlay.Mount("/etc", overlay.File("resolv.conf", []byte("nameserver "+args.Gateway+"\n")))
		if err != nil {
			return fmt.Errorf("error setting up overlay: %w", err)
		}
		defer mount.Remove()
	}

	// switch user and group if requested
	if args.User != "" {
		u, err := user.Lookup(args.User)
		if err != nil {
			return fmt.Errorf("error looking up user %q: %w", args.User, err)
		}

		uid, err := strconv.Atoi(u.Uid)
		if err != nil {
			return fmt.Errorf("error parsing user id %q as a number: %w", u.Uid, err)
		}

		gid, err := strconv.Atoi(u.Gid)
		if err != nil {
			return fmt.Errorf("error parsing group id %q as a number: %w", u.Gid, err)
		}

		// there are three (!) user/group IDs for a process: the real, effective, and saved
		// they have the purpose of allowing the process to go "back" to them
		// here we set just the effective, which, when you are root, sets all three

		err = unix.Setgid(gid)
		if err != nil {
			return fmt.Errorf("error switching to group %q (gid %v): %w", args.User, gid, err)
		}

		err = unix.Setuid(uid)
		if err != nil {
			return fmt.Errorf("error switching to user %q (uid %v): %w", args.User, uid, err)
		}

		verbosef("now in uid %d, gid %d", unix.Getuid(), unix.Getgid())
	}

	// start a web server if request
	if args.WebUI != "" {
		// TODO: open listener first so that we can check that it works before proceeding
		go func() {
			http.HandleFunc("/api/calls", func(w http.ResponseWriter, r *http.Request) {
				verbose("at /api/calls")

				// listen for HTTP request/response pairs intercepted by the proxy
				ch, history := listenHTTP()
				_ = history

				// TODO: do not set cors headers like this by default
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Expose-Headers", "Content-Type")
				w.Header().Set("Content-Type", "text/event-stream")
				w.Header().Set("Content-Encoding", "none") // this is critical for the nextjs dev server to proxy this correctly
				w.Header().Set("Cache-Control", "no-cache")
				w.Header().Set("Connection", "keep-alive")
				w.WriteHeader(http.StatusOK)

				f := w.(http.Flusher)

			outer:
				for {
					select {
					case httpcall := <-ch:
						fmt.Fprint(w, "data: ")
						json.NewEncoder(w).Encode(httpcall)
						fmt.Fprint(w, "\n\n")
						f.Flush()
					case <-r.Context().Done():
						break outer
					}
				}
			})

			log.Printf("listening on %v ...", args.WebUI)
			err := http.ListenAndServe(args.WebUI, nil)
			if err != nil {
				log.Fatal(err) // TODO: gracefully shut down the whole app
			}
		}()
	}

	// set up environment variables for the subprocess
	env := append(
		os.Environ(),
		"PS1=HTTPTAP # ",
		"HTTPTAP=1",
		"CURL_CA_BUNDLE="+caPath,
		"REQUESTS_CA_BUNDLE="+caPath,
		"SSL_CERT_FILE="+caPath,
		"_JAVA_OPTIONS=-Djavax.net.ssl.trustStore="+caPathPKCS12,
		"JDK_JAVA_OPTIONS=-Djavax.net.ssl.trustStore="+caPathPKCS12,
		"NODE_EXTRA_CA_CERTS="+caPath,
	)

	// get the name of the environment variable that openssl is configured to read
	// if openssl is not installed or cannot be loaded then this gracefully fails with empty
	// return value
	if opensslenv := opensslpaths.DefaultCertFileEnv(); opensslenv != "" {
		env = append(env, opensslenv+"="+caPath)
		verbosef("openssl is installed and configured to read %q", opensslenv)
	}

	if opensslenv := opensslpaths.DefaultCertDirEnv(); opensslenv != "" {
		env = append(env, opensslenv+"="+tempdir)
		verbosef("openssl is installed and configured to read %q", opensslenv)
	}

	verbose("running subcommand now ================")

	// launch a subprocess -- we are already in the network namespace so nothing special here
	cmd := exec.Command(args.Command[0])
	cmd.Args = args.Command
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = env
	err = cmd.Start()
	if err != nil {
		return fmt.Errorf("error starting subprocess: %w", err)
	}

	// create a goroutine to facilitate sending packets to the process
	toSubprocess := make(chan []byte, 1000)
	go copyToDevice(ctx, tun, toSubprocess)

	// start a goroutine to process packets from the subprocess -- this will be killed
	// when the subprocess completes
	verbosef("listening on %v", args.Tun)

	// the application-level thing is the mux, which distributes new connections according to patterns
	var mux mux

	// handle DNS queries by calling net.Resolve
	mux.HandleUDP(":53", func(w udpResponder, p *udpPacket) {
		handleDNS(context.Background(), w, p.payload)
	})

	// set up a test TCP interceptor
	mux.HandleTCP(":11223", func(conn net.Conn) {
		fmt.Fprint(conn, "hello 11223\n")
		conn.Close()
	})

	// set up a test UDP interceptor
	mux.HandleUDP(":11223", func(w udpResponder, p *udpPacket) {
		verbosef("got udp packet: %q, replying", string(p.payload))
		_, err = w.Write([]byte("hello udp 11223!\n"))
		if err != nil {
			errorf("error writing udp packet back to sender: %v", err)
			return
		}
	})

	// TODO: proxy all other UDP packets to the public internet
	// go proxyUDP(udppstack.Listen("*"))

	// intercept all TCP connections on port 443 and treat as HTTPS
	mux.HandleTCP(":80", proxyHTTP)

	// intercept all TCP connections on port 443 and treat as HTTPS
	mux.HandleTCP(":443", func(conn net.Conn) {
		proxyHTTPS(conn, ca)
	})

	// start listening for TCP connections and proxy each one to the world
	mux.HandleTCP("*", func(conn net.Conn) {
		proxyTCP(conn)
	})

	switch strings.ToLower(args.Stack) {
	case "homegrown":
		// instantiate the tcp and udp stacks and start reading packets from the TUN device
		tcpstack := newTCPStack(&mux, toSubprocess)
		udpstack := newUDPStack(&mux, toSubprocess)
		go readFromDevice(ctx, tun, tcpstack, udpstack)
	case "gvisor":
		// create the stack with udp and tcp protocols
		s := stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
		})

		// get maximum transmission unit for the tun device
		mtu, err := rawfile.GetMTU(args.Tun)
		if err != nil {
			return fmt.Errorf("error getting MTU: %w", err)
		}

		// create a link endpoint based on the TUN device
		endpoint, err := fdbased.New(&fdbased.Options{
			FDs: []int{int(tun.ReadWriteCloser.(*os.File).Fd())},
			MTU: mtu,
		})
		if err != nil {
			return fmt.Errorf("error creating link from tun device file descriptor: %v", err)
		}

		// create the TCP forwarder, which accepts gvisor connections and notifies the mux
		const maxInFlight = 100 // maximum simultaneous connections
		tcpForwarder := tcp.NewForwarder(s, 0, maxInFlight, func(r *tcp.ForwarderRequest) {
			// remote address is the IP address of the subprocess
			// local address is IP address that the subprocess was trying to reach
			verbosef("at TCP forwarder: %v:%v => %v:%v",
				r.ID().RemoteAddress, r.ID().RemotePort,
				r.ID().LocalAddress, r.ID().LocalPort)

			// send a SYN+ACK in response to the SYN
			var wq waiter.Queue
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				errorf("error accepting connection: %v", err)
				r.Complete(true)
				return
			}
			defer r.Complete(false)

			// TODO: set keepalive count, keepalive interval, receive buffer size, send buffer size, like this:
			//   https://github.com/xjasonlyu/tun2socks/blob/main/core/tcp.go#L83

			// create an adapter that makes an adapter into a net.Conn
			mux.notifyTCP(gonet.NewTCPConn(&wq, ep))
		})

		// TODO: this UDP forwarder sometimes only ever processes one UDP packet, other times it keeps going... :/
		// create the UDP forwarder, which accepts UDP packets and notifies the mux
		udpForwarder := udp.NewForwarder(s, func(r *udp.ForwarderRequest) {
			// remote address is the IP address of the subprocess
			// local address is IP address that the subprocess was trying to reach
			verbosef("at UDP forwarder: %v:%v => %v:%v",
				r.ID().RemoteAddress, r.ID().RemotePort,
				r.ID().LocalAddress, r.ID().LocalPort)

			// create an endpoint for responding to this packet
			var wq waiter.Queue
			ep, err := r.CreateEndpoint(&wq)
			if err != nil {
				verbosef("error accepting connection: %v", err)
				return
			}

			// TODO: set keepalive count, keepalive interval, receive buffer size, send buffer size, like this:
			//   https://github.com/xjasonlyu/tun2socks/blob/main/core/tcp.go#L83

			// create a convenience adapter so that we can read and write using a net.Conn
			conn := gonet.NewUDPConn(&wq, ep)

			// so far as I can tell, we must read packets in a new goroutine or else packets on other connections
			// will never be processed
			go func() {
				defer conn.Close()

				buf := make([]byte, mtu)
				for {
					n, _, err := conn.ReadFrom(buf)
					if err == net.ErrClosed {
						verbosef("UDP connection closed, exiting the read loop", n)
						break
					}
					if err != nil {
						verbosef("error reading udp packet with conn.ReadFrom: %v, ignoring", err)
						continue
					}

					verbosef("read a UDP packet with %d bytes", n)

					mux.notifyUDP(conn, &udpPacket{
						conn.RemoteAddr(),
						conn.LocalAddr(),
						buf[:n],
					})

					verbose("mux returned, reading next packet...")
				}
			}()
		})

		// register the forwarders with the stack
		s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpForwarder.HandlePacket)
		s.SetTransportProtocolHandler(udp.ProtocolNumber, udpForwarder.HandlePacket)

		// create the network interface -- tun2socks says this must happen *after* registering the TCP forwarder
		nic := s.NextNICID()
		er := s.CreateNIC(nic, endpoint)
		if er != nil {
			return fmt.Errorf("error creating NIC: %v", er)
		}

		// set promiscuous mode so that the forwarder receives packets not addressed to us
		er = s.SetPromiscuousMode(nic, true)
		if er != nil {
			return fmt.Errorf("error activating promiscuous mode: %v", er)
		}

		// set spoofing mode so that we can send packets from any address
		er = s.SetSpoofing(nic, true)
		if er != nil {
			return fmt.Errorf("error activating spoofing mode: %v", er)
		}

		// set up the route table so that we can send packets to the subprocess
		s.SetRouteTable([]tcpip.Route{
			{
				Destination: header.IPv4EmptySubnet,
				NIC:         nic,
			},
			{
				Destination: header.IPv6EmptySubnet,
				NIC:         nic,
			},
		})

	default:
		return fmt.Errorf("invalid stack %q; valid choices are 'gvisor' or 'homegrown'", args.Stack)
	}

	// wait for the subprocess to complete
	err = cmd.Wait()
	if err != nil {
		exitError, isExitError := err.(*exec.ExitError)
		if isExitError {
			return fmt.Errorf("subprocess exited with code %d", exitError.ExitCode())
		} else {
			return fmt.Errorf("error running subprocess: %v", err)
		}
	}
	return nil
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(0)
	err := Main()
	if err != nil {
		log.Fatal(err)
	}
}
