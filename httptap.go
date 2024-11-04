package main

import (
	"context"
	"encoding/json"
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
	"github.com/monasticacademy/httptap/pkg/certfile"
	"github.com/monasticacademy/httptap/pkg/opensslpaths"
	"github.com/monasticacademy/httptap/pkg/overlay"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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
		Verbose            bool     `arg:"-v,--verbose"`
		NoNewUserNamespace bool     `arg:"--no-new-user-namespace" help:"do not create a new user namespace (must be run as root)"`
		Stderr             bool     `help:"log to stderr (default is stdout)"`
		Tun                string   `default:"httptap" help:"name of the network device to create"`
		Link               string   `default:"10.1.1.100/24" help:"IP address of the network interface that the subprocess will see"`
		Route              string   `default:"0.0.0.0/0" help:"IP address range to route to the internet"`
		Gateway            string   `default:"10.1.1.1" help:"IP address of the gateway that intercepts and proxies network packets"`
		WebUI              string   `help:"address and port to serve API on"`
		User               string   `help:"run command as this user (username or id)"`
		NoOverlay          bool     `arg:"--no-overlay" help:"do not mount any overlay filesystems"`
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
	linksubnet, err := netlink.ParseIPNet(args.Link)
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
	routesubnet, err := netlink.ParseIPNet(args.Route)
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
		Dst: routesubnet,
		Gw:  gateway,
	})
	if err != nil {
		return fmt.Errorf("error creating default route: %w", err)
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
				log.Println("at /api/calls")

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
						log.Println("sending an event")
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

	// get the name of the environment variable that openssl is configured for
	// if openssl is not installed or cannot be loaded then this gracefully fails with empty
	// return value
	if opensslenv := opensslpaths.DefaultCertDirEnv(); opensslenv != "" {
		env = append(env, opensslenv+"="+caPath)
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
	go func() {
		// instantiate the tcp and udp stacks
		tcpstack := newTCPStack(toSubprocess)
		udpstack := newUDPStack(toSubprocess)

		// handle DNS queries by calling net.Resolve
		udpstack.HandleFunc(":53", func(w udpResponder, p *udpPacket) {
			handleDNS(context.Background(), w, p.payload)
		})

		tcpstack.HandleFunc(":11223", func(conn net.Conn) {
			fmt.Fprint(conn, "hello 11223\n")
			conn.Close()
		})

		// TODO: proxy all other UDP packets to the public internet
		// go proxyUDP(udppstack.Listen("*"))

		// intercept all https connections on port 443
		go proxyHTTPS(tcpstack.Listen(":443"), ca)

		// start listening for TCP connections and proxy each one to the world
		go proxyTCP(tcpstack.Listen("*"))

		// start reading raw bytes from the tunnel device and sending them to the appropriate stack
		buf := make([]byte, 1500)
		for {
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
	}()

	// wait for subprocess completion
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
