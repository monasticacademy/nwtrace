<h1 align="center">
  <img src="./.github/banner.webp" alt="httptap" height="450px">
  <br>
  httptap
  </br>
</h1>
<h4 align="center">Application HTTP request inspector</h4>
<p align="center">
  <a href="https://pkg.go.dev/github.com/monasticacademy/httptap"><img src="https://img.shields.io/badge/go.dev-reference-007d9c?logo=go&logoColor=white&style=flat-square" alt="Documentation"></a>
  <a href="https://github.com/monasticacademy/httptap/actions"><img src="https://github.com/monasticacademy/httptap/workflows/Test/badge.svg" alt="Build Status"></a>
</p>
<br>

View the HTTP and HTTPS requests made by a linux program:

```shell
$ httptap -- curl https://monasticacademy.org
---> GET https://monasticacademy.org/
<--- 308 https://monasticacademy.org/ (15 bytes)
```

```shell
httptap -- python -c "import requests; requests.get('https://monasticacademy.org')"
---> GET https://monasticacademy.org/
<--- 308 https://monasticacademy.org/ (15 bytes)
---> GET https://www.monasticacademy.org/
<--- 200 https://www.monasticacademy.org/ (5796 bytes)
```

If you can run `<command>` on your shell, you can likely also run `httptap -- <command>`. You do not need to run it as the root user, nor set up any kind of daemon. When you run httptap, it does not create iptables rules or make any other global changes to your system. The `httptap` executable is a static Go binary that runs without dependencies. You can install it like this:

```shell
go install github.com/monasticacademy/httptap@latest
```

It works by running the requested subprocess in a network namespace containing a TUN device that it uses to intercept and proxy all network traffic. In order to inspect the contents of TLS connections, it creates a certificate authority and injects it into environment variables passed to the subprocess.

Httptap make extensive use of linux-specific system calls. It is unlikely to be ported to other operating systems.

# Install from releases

```shell
curl -L https://github.com/monasticacademy/httptap/releases/download/v0.0.3/httptap_Linux_x86_64.tar.gz | tar xzf -
./httptap -- curl https://www.example.com
```

For all versions and CPU architectures see the [releases page](https://github.com/monasticacademy/httptap/releases/).

# Install with Go

```shell
go install github.com/monasticacademy/httptap@latest
./httptap -- curl https://www.example.com
```

# How it works

In linux, there is a kernel API for creating and configuring network interfaces. Conventionally, a network interface would be a physical ethernet or WiFi controller in your computer, but it is possible to create a special kind of network interface called a TUN device. A TUN device shows up to the system in the way that any network interface shows up, but any traffic written to it will be delivered to a file descriptor held by the process that created it. Httptap creates a TUN device and runs the subprocess in an environment in which all network traffic is routed through that device.

There is also a kernel API in linux for creating network namespaces. A network namespace is a list of network interfaces and routing rules. When a process is started in linux, it can be run in a specified network namespace. By default, processes run in a root network namespace that we do not want to make chagnes to because doing so would affect all network traffic on the system. Instead, we create a network namespace in which there are only two network interfaces: a loopback device (127.0.0.1) and a TUN device that delivers traffic to us. Then we run the subprocess in that namespace.

The traffic from the network device is delivered to us as raw IP packets. We must parse the IP packets as well as the inner TCP and UDP packets, and write raw IP packets back to the subprocess. This requires a software implementation of the TCP/IP protocol, which is by far the most difficult part of httptap. The TCP/IP implementation in httptap is missing many aspects of the full TCP protocol, but still works reasonably well for its purpose.

Suppose the subprocess makes an HTTP request to www.example.com. The first thing we receive is a TCP SYN packet addressed to 93.184.215.14 (the current IP address of example.com). We respond with a SYN+ACK packet with source address 93.184.215.14, though in truth the packet did not come from 93.184.215.14, but from us. Separately, we establish our own TCP connection to 93.184.215.14 using the ordinary sockets API in the linux kernel. When the subprocess sends data to 93.184.215.14 we relay it over our separate TCP connection, and vice versa for return data. This is a traditional transparent TCP proxy, and in this way we can view all data flowing to and from the subprocess, though we won't be able to decrypt HTTPS traffic without a bit more work.

When a client makes an HTTPS request, it asks the server for evidence that it is who it says it is. If the server has a certificate signed by a certificate authority, it can use that certificate to prove that it is who it says it is. The client will only accept such a certificate if it trusts the certificate authority that signed the certificate. Operating systems, web browsers, and many other pieces of software come with a list of a few hundred certificate authorities that they trust. Many of these pieces of software have ways for users to add additional certificate authorities to this list. We make use of this.

When httptap starts, it creates a certificate authority (actually a private key plus a corresponding x509 certificate), writes it to a file on the filesystem visible only to the subprocess, and sets a few environment variables -- again only visible to the subprocess being run -- that add this certificate authority to the list of trusted certificate authorities. Since the subprocess trusts this certificate authority, and httptap holds the private key for the certificate authority, it can prove to the subprocess that it is the server which which the subprocess was trying to communicate. In this way we can read the plaintext HTTP requests.
