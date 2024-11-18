See https://github.com/xjasonlyu/tun2socks/blob/main/core/tcp.go#L78

I may be able to use tun2socks off-the-shelf. The core piece is very nicely designed:
  https://github.com/xjasonlyu/tun2socks/blob/main/engine/engine.go#L227-L234

I should be able to use both the tunnel _and_ the proxy from tun2socks. I'll probably always use the Direct proxy.

What I need to do is implement proxy.Dialer:

    type Dialer interface {
        DialContext(context.Context, *M.Metadata) (net.Conn, error)
        DialUDP(*M.Metadata) (net.PacketConn, error)
    }
    
    https://github.com/xjasonlyu/tun2socks/blob/main/proxy/proxy.go#L19-L22

and pass it in, ultimate to core.CreateStack in Config.TransportHandler:

    https://github.com/xjasonlyu/tun2socks/blob/main/core/stack.go#L25

but more specifically, the dialer goes into the tunnel via SetDialer:

	tunnel.T().SetDialer(_defaultProxy)

    https://github.com/xjasonlyu/tun2socks/blob/main/engine/engine.go#L195

and then the tunnel is the TransportHandler:

    stack, err = core.CreateStack(&core.Config{
        LinkEndpoint:     _defaultDevice,
        TransportHandler: tunnel.T(),
        MulticastGroups:  multicastGroups,
        Options:          opts,
    });

    https://github.com/xjasonlyu/tun2socks/blob/main/engine/engine.go#L227-L234