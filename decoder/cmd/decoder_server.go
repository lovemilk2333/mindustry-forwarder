package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"syscall"
	"time"

	"github.com/alexflint/go-arg"
)

const MIN_CONTEXT_LENGTH = 1 + 2 // flags (int8) + port (uint16 BE)
const IPV4_LENGTH = 4            // 32 bit = 4 Byte
const IPV6_LENGTH = 16           // 128 bit = 16 Byte

const IS_TCP_MASK = 1
const IS_IPV6_MASK = 128

// UDP over the TCP tunnel is length-prefixed: uint16 BE length + payload.
// Must stay in sync with encoder/encoder_server.py.
const UDP_FRAME_HEADER_SIZE = 2
const UDP_MAX_PAYLOAD = 65535

// Linux: IPV6_TRANSPARENT is not in older x/sys snapshots used by some Go toolchains.
const ipv6Transparent = 75 // include/uapi/linux/in6.h IPV6_TRANSPARENT

type Context struct {
	ip      netip.Addr
	is_ipv6 bool
	is_tcp  bool
	port    uint16
}

func (this *Context) String() string {
	proto := "UDP"
	if this.is_tcp {
		proto = "TCP"
	}
	return fmt.Sprintf("[%s %s:%d]", proto, this.ip.String(), this.port)
}

var args struct {
	Listen            string        `arg:"-l,--listen" default:":6568" help:"TCP tunnel listen host and port"`
	Mindustry         string        `arg:"-m,--mindustry" default:"127.0.0.1:6567" help:"Mindustry server host:port"`
	MindustryPortOnly uint16        `arg:"-p,--mindustry-port" help:"shorthand: use 127.0.0.1:<port> as Mindustry address (overrides --mindustry host)"`
	Timeout           time.Duration `default:"5s"`
	NoTransparent     bool          `arg:"--no-transparent" help:"never use IP_TRANSPARENT (always dial with local address)"`
}

func parse_context(data []byte) (int, *Context, error) {
	length := len(data)
	if length < MIN_CONTEXT_LENGTH {
		return 0, nil, errors.New("context too short")
	}

	used_length := 0
	flags := data[0]
	is_ipv6 := flags&IS_IPV6_MASK == IS_IPV6_MASK
	is_tcp := flags&IS_TCP_MASK == IS_TCP_MASK
	port := (uint16(data[1]) << 8) | uint16(data[2])

	var ip netip.Addr
	if is_ipv6 {
		if length < MIN_CONTEXT_LENGTH+IPV6_LENGTH {
			return 0, nil, errors.New("context too short")
		}
		ip = netip.AddrFrom16([IPV6_LENGTH]byte(data[3 : 3+IPV6_LENGTH]))
		used_length = MIN_CONTEXT_LENGTH + IPV6_LENGTH
	} else {
		if length < MIN_CONTEXT_LENGTH+IPV4_LENGTH {
			return 0, nil, errors.New("context too short")
		}
		ip = netip.AddrFrom4([IPV4_LENGTH]byte(data[3 : 3+IPV4_LENGTH]))
		used_length = MIN_CONTEXT_LENGTH + IPV4_LENGTH
	}

	return used_length, &Context{
		ip:      ip,
		is_ipv6: is_ipv6,
		is_tcp:  is_tcp,
		port:    port,
	}, nil
}

// read_context reads a variable-length context header from conn.
func read_context(conn net.Conn) (*Context, error) {
	head := make([]byte, MIN_CONTEXT_LENGTH)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}

	flags := head[0]
	is_ipv6 := flags&IS_IPV6_MASK == IS_IPV6_MASK
	addr_len := IPV4_LENGTH
	if is_ipv6 {
		addr_len = IPV6_LENGTH
	}

	addr := make([]byte, addr_len)
	if _, err := io.ReadFull(conn, addr); err != nil {
		return nil, err
	}

	_, ctx, err := parse_context(append(head, addr...))
	return ctx, err
}

func backend_host_is_loopback(backend_addr string) bool {
	host, _, err := net.SplitHostPort(backend_addr)
	if err != nil {
		host = backend_addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// hostname — resolve best-effort
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return false
		}
		return ips[0].IsLoopback()
	}
	return ip.IsLoopback()
}

func want_transparent(backend_addr string) bool {
	if args.NoTransparent {
		return false
	}
	// Spoofing a foreign source toward 127.0.0.1/::1 almost always fails
	// (SYN never completes → dial i/o timeout). Skip transparent on loopback
	// backends; client IP is still logged from the context header.
	if backend_host_is_loopback(backend_addr) {
		return false
	}
	return true
}

func set_ip_transparent(network string, c syscall.RawConn) error {
	var dial_err error
	err := c.Control(func(fd uintptr) {
		f := int(fd)
		// IPv4 transparent (also needed for dual-stack sockets in many setups)
		if e := syscall.SetsockoptInt(f, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); e != nil {
			// not fatal alone on pure IPv6 sockets; record and try IPv6
			dial_err = e
		}
		if network == "tcp6" || network == "udp6" {
			if e := syscall.SetsockoptInt(f, syscall.IPPROTO_IPV6, ipv6Transparent, 1); e != nil {
				dial_err = e
			} else {
				dial_err = nil
			}
		} else if dial_err != nil {
			// IPv4 path: SOL_IP failure is real
		} else {
			dial_err = nil
		}
	})
	if err != nil {
		return err
	}
	return dial_err
}

func base_network(is_tcp bool) string {
	if is_tcp {
		return "tcp"
	}
	return "udp"
}

func dial_backend(ctx *Context, backend_addr string) (net.Conn, error) {
	// "tcp"/"udp" lets Go pick family from backend_addr (correct for plain dial
	// to 127.0.0.1 even when the client context is IPv6).
	network := base_network(ctx.is_tcp)
	use_tproxy := want_transparent(backend_addr)

	dialer := net.Dialer{
		Timeout: args.Timeout,
	}

	if use_tproxy {
		// LocalAddr family must match the client IP we spoof.
		tnet := network
		if ctx.is_ipv6 {
			tnet = network + "6"
		} else {
			tnet = network + "4"
		}
		var local net.Addr
		if ctx.is_tcp {
			local, _ = net.ResolveTCPAddr(tnet, net.JoinHostPort(ctx.ip.String(), "0"))
		} else {
			local, _ = net.ResolveUDPAddr(tnet, net.JoinHostPort(ctx.ip.String(), "0"))
		}
		dialer.LocalAddr = local
		dialer.Control = func(network, address string, c syscall.RawConn) error {
			return set_ip_transparent(network, c)
		}
		network = tnet
	}

	conn, err := dialer.DialContext(context.Background(), network, backend_addr)
	if err != nil {
		// If transparent dial failed, fall back once without spoof so the
		// session still works (e.g. missing CAP_NET_ADMIN / route).
		if use_tproxy {
			log.Printf("%s transparent dial failed (%v), retry without IP_TRANSPARENT", ctx, err)
			plain := net.Dialer{Timeout: args.Timeout}
			return plain.DialContext(context.Background(), base_network(ctx.is_tcp), backend_addr)
		}
		return nil, err
	}
	return conn, nil
}

func copy_tcp(dst, src net.Conn, label string, session *Context) {
	_, err := io.Copy(dst, src)
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		log.Printf("%s %s unexpectedly closed: %v", session, label, err)
	}
	// unblock the peer direction
	_ = dst.SetReadDeadline(time.Now())
}

// relay_udp_c2s: tunnel TCP -> Mindustry UDP (length-prefixed frames)
func relay_udp_c2s(backend net.Conn, tunnel net.Conn, session *Context) {
	hdr := make([]byte, UDP_FRAME_HEADER_SIZE)
	for {
		if _, err := io.ReadFull(tunnel, hdr); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("%s UDP c2s frame header: %v", session, err)
			}
			return
		}
		length := binary.BigEndian.Uint16(hdr)
		if int(length) > UDP_MAX_PAYLOAD {
			log.Printf("%s UDP c2s frame too large: %d", session, length)
			return
		}
		buf := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(tunnel, buf); err != nil {
				log.Printf("%s UDP c2s frame body: %v", session, err)
				return
			}
		}
		if _, err := backend.Write(buf); err != nil {
			log.Printf("%s UDP c2s write to Mindustry: %v", session, err)
			return
		}
	}
}

// relay_udp_s2c: Mindustry UDP -> tunnel TCP (length-prefixed frames)
func relay_udp_s2c(tunnel net.Conn, backend net.Conn, session *Context) {
	buf := make([]byte, UDP_MAX_PAYLOAD)
	hdr := make([]byte, UDP_FRAME_HEADER_SIZE)
	for {
		n, err := backend.Read(buf)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				log.Printf("%s UDP s2c read from Mindustry: %v", session, err)
			}
			return
		}
		if n == 0 {
			continue
		}
		binary.BigEndian.PutUint16(hdr, uint16(n))
		if _, err := tunnel.Write(hdr); err != nil {
			log.Printf("%s UDP s2c frame header: %v", session, err)
			return
		}
		if _, err := tunnel.Write(buf[:n]); err != nil {
			log.Printf("%s UDP s2c frame body: %v", session, err)
			return
		}
	}
}

func forward_handler(backend_addr string, conn *net.TCPConn) {
	defer conn.Close()

	err := conn.SetReadDeadline(time.Now().Add(args.Timeout))
	if err != nil {
		log.Printf("cannot set read deadline: %v", err)
		return
	}

	ctx, err := read_context(conn)
	if err != nil {
		if net_err, ok := err.(net.Error); ok && net_err.Timeout() {
			log.Printf("read context header timed out after %s", args.Timeout.String())
		} else if errors.Is(err, os.ErrDeadlineExceeded) {
			log.Printf("read context header timed out")
		} else if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			log.Printf("cannot read context header: connection closed early")
		} else {
			log.Printf("cannot read/parse context header: %v", err)
		}
		return
	}
	// clear header deadline for the rest of the session
	_ = conn.SetReadDeadline(time.Time{})

	backend_conn, err := dial_backend(ctx, backend_addr)
	if err != nil {
		log.Printf("%s cannot connect to Mindustry Server: %v", ctx, err)
		return
	}
	defer backend_conn.Close()

	mode := "plain"
	if want_transparent(backend_addr) {
		mode = "transparent"
	}
	log.Printf("%s session opened (%s) -> %s", ctx, mode, backend_addr)

	if ctx.is_tcp {
		done := make(chan struct{})
		go func() {
			copy_tcp(backend_conn, conn, "Client to Mindustry Server", ctx)
			close(done)
		}()
		copy_tcp(conn, backend_conn, "Mindustry Server to Client", ctx)
		<-done
	} else {
		done := make(chan struct{})
		go func() {
			relay_udp_c2s(backend_conn, conn, ctx)
			close(done)
		}()
		relay_udp_s2c(conn, backend_conn, ctx)
		<-done
	}

	log.Printf("%s session closed", ctx)
}

func main() {
	log.SetFlags(log.Flags() | log.LUTC)
	log.SetPrefix("[Mindustry Forwarder] UTC::")

	arg.MustParse(&args)

	backend_addr := args.Mindustry
	if args.MindustryPortOnly != 0 {
		backend_addr = fmt.Sprintf("127.0.0.1:%d", args.MindustryPortOnly)
	}
	// validate host:port
	if _, _, err := net.SplitHostPort(backend_addr); err != nil {
		log.Fatalf("invalid --mindustry host:port %q: %v", backend_addr, err)
	}

	listen_addr, err := net.ResolveTCPAddr("tcp", args.Listen)
	if err != nil {
		log.Fatalf("invalid listen host and port: %v", err)
	}

	listener, err := net.ListenTCP("tcp", listen_addr)
	if err != nil {
		log.Fatalf("cannot listen tcp: %v", err)
	}
	defer listener.Close()

	tproxy := want_transparent(backend_addr)
	log.Printf("start to listen: `%s` -> mindustry `%s` (transparent=%v)",
		listen_addr.String(), backend_addr, tproxy)
	if !args.NoTransparent && backend_host_is_loopback(backend_addr) {
		log.Printf("note: backend is loopback — IP_TRANSPARENT disabled automatically; " +
			"use -m/--mindustry <lan-ip>:6567 if you need the real client IP on the game server")
	}

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			log.Printf("cannot accept tcp: %v", err)
			continue
		}
		go forward_handler(backend_addr, conn)
	}
}
