package main

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/alexflint/go-arg"
)

//go:embed setup-lo-transparent.sh
var setupLoTransparentScript []byte

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
	SetupLoIP         string        `arg:"--setup-lo-ip" default:"172.31.255.1" help:"lo alias IP used when backend is 127/8 (auto setup)"`
	NoAutoSetupLo     bool          `arg:"--no-auto-setup-lo" help:"do not auto-configure lo alias when backend is 127/8"`
}

// set when auto setup-lo succeeded; cleared by undo on exit.
var loAliasActive string

// client IPs we installed as `ip route local … dev lo` so SYN-ACK/UDP
// replies to the spoofed source stay on this host. Refcounted per session.
var (
	localRouteMu   sync.Mutex
	localRouteRefs = map[string]int{}
)

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

// ensure_client_local_route makes the kernel treat clientIP as a local
// address on lo. Without this, SYN-ACK/UDP replies to the spoofed source
// are routed off-box and the transparent handshake times out.
func ensure_client_local_route(clientIP string) error {
	localRouteMu.Lock()
	defer localRouteMu.Unlock()
	if localRouteRefs[clientIP] > 0 {
		localRouteRefs[clientIP]++
		return nil
	}
	// `ip route replace local <ip>/32 dev lo` — idempotent, needs root.
	cmd := exec.Command("ip", "route", "replace", "local", clientIP+"/32", "dev", "lo")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route replace local %s/32 dev lo: %v (%s)", clientIP, err, bytesTrim(out))
	}
	localRouteRefs[clientIP] = 1
	return nil
}

func release_client_local_route(clientIP string) {
	if clientIP == "" {
		return
	}
	localRouteMu.Lock()
	defer localRouteMu.Unlock()
	n := localRouteRefs[clientIP]
	if n <= 0 {
		return
	}
	if n > 1 {
		localRouteRefs[clientIP] = n - 1
		return
	}
	delete(localRouteRefs, clientIP)
	cmd := exec.Command("ip", "route", "del", "local", clientIP+"/32", "dev", "lo")
	_ = cmd.Run() // best-effort; may already be gone
}

func release_all_client_local_routes() {
	localRouteMu.Lock()
	ips := make([]string, 0, len(localRouteRefs))
	for ip := range localRouteRefs {
		ips = append(ips, ip)
	}
	localRouteRefs = map[string]int{}
	localRouteMu.Unlock()
	for _, ip := range ips {
		cmd := exec.Command("ip", "route", "del", "local", ip+"/32", "dev", "lo")
		_ = cmd.Run()
	}
}

func bytesTrim(b []byte) string {
	s := string(b)
	if len(s) > 200 {
		return s[:200]
	}
	return s
}

// dial_udp_unconnected binds a UDP socket (optionally spoofing client IP:port)
// and wraps it so Read/Write talk to backend_addr without connect().
//
// Why not DialUDP? Mindustry often replies from a different local IP than the
// dial target (e.g. dial 172.31.255.1:6567, reply from 10.0.0.100:6567 when
// the client IP is local on lo). A connected UDP socket drops those replies
// → s2c i/o timeout → looks like total UDP loss.
func dial_udp_unconnected(ctx *Context, backend_addr string, transparent bool) (net.Conn, string, error) {
	raddr, err := net.ResolveUDPAddr("udp", backend_addr)
	if err != nil {
		return nil, "", err
	}

	network := "udp4"
	if ctx.is_ipv6 || (raddr.IP != nil && raddr.IP.To4() == nil) {
		network = "udp6"
	}

	var routeIP string
	var laddr *net.UDPAddr
	lc := net.ListenConfig{}

	if transparent {
		clientIP := ctx.ip.String()
		if e := ensure_client_local_route(clientIP); e != nil {
			log.Printf("%s cannot install local route for spoofed source: %v", ctx, e)
		} else {
			routeIP = clientIP
		}
		// Bind the real client port so Mindustry sees the authentic 5-tuple.
		laddr, _ = net.ResolveUDPAddr(network, net.JoinHostPort(clientIP, fmt.Sprintf("%d", ctx.port)))
		lc.Control = func(network, address string, c syscall.RawConn) error {
			return set_ip_transparent(network, c)
		}
	}

	pkt, err := lc.ListenPacket(context.Background(), network, laddrString(laddr))
	if err != nil && transparent {
		// Port busy or bind failed — retry with ephemeral port, still spoofing IP.
		log.Printf("%s UDP bind %v failed (%v), retry ephemeral port", ctx, laddr, err)
		laddr, _ = net.ResolveUDPAddr(network, net.JoinHostPort(ctx.ip.String(), "0"))
		pkt, err = lc.ListenPacket(context.Background(), network, laddrString(laddr))
	}
	if err != nil {
		release_client_local_route(routeIP)
		return nil, "", err
	}

	uc, ok := pkt.(*net.UDPConn)
	if !ok {
		_ = pkt.Close()
		release_client_local_route(routeIP)
		return nil, "", fmt.Errorf("ListenPacket did not return *UDPConn")
	}
	return &udpBackendConn{conn: uc, raddr: raddr}, routeIP, nil
}

func laddrString(a *net.UDPAddr) string {
	if a == nil {
		return ":"
	}
	return a.String()
}

// udpBackendConn adapts an unconnected *UDPConn to net.Conn Read/Write
// directed at a fixed remote (Mindustry).
type udpBackendConn struct {
	conn  *net.UDPConn
	raddr *net.UDPAddr
}

func (u *udpBackendConn) Read(b []byte) (int, error) {
	for {
		n, _, err := u.conn.ReadFromUDP(b)
		if err != nil {
			return n, err
		}
		// Accept replies from any source (Mindustry may use a different
		// local IP than the dial target).
		return n, nil
	}
}

func (u *udpBackendConn) Write(b []byte) (int, error) {
	return u.conn.WriteToUDP(b, u.raddr)
}

func (u *udpBackendConn) Close() error                       { return u.conn.Close() }
func (u *udpBackendConn) LocalAddr() net.Addr                { return u.conn.LocalAddr() }
func (u *udpBackendConn) RemoteAddr() net.Addr               { return u.raddr }
func (u *udpBackendConn) SetDeadline(t time.Time) error      { return u.conn.SetDeadline(t) }
func (u *udpBackendConn) SetReadDeadline(t time.Time) error  { return u.conn.SetReadDeadline(t) }
func (u *udpBackendConn) SetWriteDeadline(t time.Time) error { return u.conn.SetWriteDeadline(t) }

// dial_backend returns the backend conn, whether the source IP was actually
// spoofed (transparent), and an optional clientIP that holds a local route
// (caller must release_client_local_route when the session ends).
func dial_backend(ctx *Context, backend_addr string) (conn net.Conn, transparent bool, routeIP string, err error) {
	network := base_network(ctx.is_tcp)
	use_tproxy := want_transparent(backend_addr)

	// UDP: always prefer unconnected socket (see dial_udp_unconnected).
	if !ctx.is_tcp {
		c, rip, e := dial_udp_unconnected(ctx, backend_addr, use_tproxy)
		if e != nil && use_tproxy {
			log.Printf("%s transparent UDP dial failed (%v), retry plain", ctx, e)
			c2, rip2, e2 := dial_udp_unconnected(ctx, backend_addr, false)
			return c2, false, rip2, e2
		}
		return c, use_tproxy && e == nil, rip, e
	}

	if !use_tproxy {
		plain := net.Dialer{Timeout: args.Timeout}
		c, e := plain.DialContext(context.Background(), network, backend_addr)
		return c, false, "", e
	}

	clientIP := ctx.ip.String()
	if e := ensure_client_local_route(clientIP); e != nil {
		log.Printf("%s cannot install local route for spoofed source: %v", ctx, e)
	} else {
		routeIP = clientIP
	}

	tnet := network + "4"
	if ctx.is_ipv6 {
		tnet = network + "6"
	}
	local, _ := net.ResolveTCPAddr(tnet, net.JoinHostPort(clientIP, "0"))

	dialer := net.Dialer{
		Timeout:   args.Timeout,
		LocalAddr: local,
		Control: func(network, address string, c syscall.RawConn) error {
			return set_ip_transparent(network, c)
		},
	}

	c, e := dialer.DialContext(context.Background(), tnet, backend_addr)
	if e != nil {
		log.Printf("%s transparent dial failed (%v), retry without IP_TRANSPARENT", ctx, e)
		release_client_local_route(routeIP)
		routeIP = ""
		plain := net.Dialer{Timeout: args.Timeout}
		c2, e2 := plain.DialContext(context.Background(), network, backend_addr)
		return c2, false, "", e2
	}
	return c, true, routeIP, nil
}

func copy_tcp(dst, src net.Conn, label string, session *Context) {
	_, err := io.Copy(dst, src)
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		log.Printf("%s %s unexpectedly closed: %v", session, label, err)
	}
	// unblock the peer direction
	_ = dst.SetReadDeadline(time.Now())
}

func set_tcp_nodelay(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
	}
}

func tune_udp_conn(conn net.Conn) {
	var uc *net.UDPConn
	switch c := conn.(type) {
	case *net.UDPConn:
		uc = c
	case *udpBackendConn:
		uc = c.conn
	}
	if uc != nil {
		_ = uc.SetReadBuffer(4 * 1024 * 1024)
		_ = uc.SetWriteBuffer(4 * 1024 * 1024)
	}
}

// write_udp_frame writes one length-prefixed frame in a single syscall when possible.
func write_udp_frame(w net.Conn, payload []byte) error {
	n := len(payload)
	if n > UDP_MAX_PAYLOAD {
		return fmt.Errorf("UDP payload too large: %d", n)
	}
	frame := make([]byte, UDP_FRAME_HEADER_SIZE+n)
	binary.BigEndian.PutUint16(frame[:UDP_FRAME_HEADER_SIZE], uint16(n))
	copy(frame[UDP_FRAME_HEADER_SIZE:], payload)
	_, err := w.Write(frame)
	return err
}

// relay_udp_c2s: tunnel TCP -> Mindustry UDP (length-prefixed frames)
func relay_udp_c2s(backend net.Conn, tunnel net.Conn, session *Context) {
	hdr := make([]byte, UDP_FRAME_HEADER_SIZE)
	// Reuse a max-sized body buffer to avoid per-datagram alloc churn.
	body := make([]byte, UDP_MAX_PAYLOAD)
	for {
		if _, err := io.ReadFull(tunnel, hdr); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.ErrUnexpectedEOF) {
				log.Printf("%s UDP c2s frame header: %v", session, err)
			}
			return
		}
		length := int(binary.BigEndian.Uint16(hdr))
		if length > UDP_MAX_PAYLOAD {
			log.Printf("%s UDP c2s frame too large: %d", session, length)
			return
		}
		if length > 0 {
			if _, err := io.ReadFull(tunnel, body[:length]); err != nil {
				log.Printf("%s UDP c2s frame body: %v", session, err)
				return
			}
		}
		if _, err := backend.Write(body[:length]); err != nil {
			log.Printf("%s UDP c2s write to Mindustry: %v", session, err)
			return
		}
	}
}

// relay_udp_s2c: Mindustry UDP -> tunnel TCP (length-prefixed frames)
func relay_udp_s2c(tunnel net.Conn, backend net.Conn, session *Context) {
	buf := make([]byte, UDP_MAX_PAYLOAD)
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
		if err := write_udp_frame(tunnel, buf[:n]); err != nil {
			log.Printf("%s UDP s2c frame: %v", session, err)
			return
		}
	}
}

func forward_handler(backend_addr string, conn *net.TCPConn) {
	defer conn.Close()
	set_tcp_nodelay(conn)

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

	backend_conn, transparent, routeIP, err := dial_backend(ctx, backend_addr)
	if err != nil {
		log.Printf("%s cannot connect to Mindustry Server: %v", ctx, err)
		return
	}
	defer backend_conn.Close()
	defer release_client_local_route(routeIP)

	if ctx.is_tcp {
		set_tcp_nodelay(backend_conn)
	} else {
		tune_udp_conn(backend_conn)
	}

	mode := "plain"
	if transparent {
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
		// Close either side when the other finishes so both relays exit.
		done := make(chan struct{}, 2)
		go func() {
			relay_udp_c2s(backend_conn, conn, ctx)
			_ = backend_conn.SetReadDeadline(time.Now())
			_ = conn.SetReadDeadline(time.Now())
			done <- struct{}{}
		}()
		go func() {
			relay_udp_s2c(conn, backend_conn, ctx)
			_ = backend_conn.SetReadDeadline(time.Now())
			_ = conn.SetReadDeadline(time.Now())
			done <- struct{}{}
		}()
		<-done
		<-done
	}

	log.Printf("%s session closed", ctx)
}

// run_embedded_setup_lo extracts the embedded script to a temp file, runs it,
// then deletes the temp tree (use-once). Returns the script exit code.
func run_embedded_setup_lo(undo bool, aliasIP string, quiet bool) int {
	dir, err := os.MkdirTemp("", "mindustry-forwarder-setup-lo-*")
	if err != nil {
		log.Printf("setup-lo: cannot create temp dir: %v", err)
		return 1
	}
	defer os.RemoveAll(dir)

	scriptPath := filepath.Join(dir, "setup-lo-transparent.sh")
	if err := os.WriteFile(scriptPath, setupLoTransparentScript, 0o700); err != nil {
		log.Printf("setup-lo: cannot write embedded script: %v", err)
		return 1
	}

	argv := []string{scriptPath}
	if undo {
		argv = append(argv, "--undo", aliasIP)
	} else {
		argv = append(argv, aliasIP)
	}

	cmd := exec.Command("/usr/bin/env", append([]string{"bash"}, argv...)...)
	if quiet {
		cmd.Env = append(os.Environ(), "MINDUSTRY_SETUP_LO_QUIET=1")
	} else {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		log.Printf("setup-lo failed: %v", err)
		return 1
	}
	return 0
}

func undo_lo_alias() {
	if loAliasActive == "" {
		return
	}
	ip := loAliasActive
	loAliasActive = ""
	code := run_embedded_setup_lo(true, ip, true)
	if code != 0 {
		log.Printf("setup-lo undo failed (exit %d) for %s", code, ip)
		return
	}
	log.Printf("setup-lo: removed lo alias %s", ip)
}

// maybe_auto_setup_lo: when backend is 127/8 and transparent is desired,
// add a non-127 alias on lo and rewrite backend_addr to that alias so
// IP_TRANSPARENT can work. Returns the (possibly rewritten) backend addr.
func maybe_auto_setup_lo(backend_addr string) string {
	if args.NoTransparent || args.NoAutoSetupLo {
		return backend_addr
	}
	if !backend_host_is_loopback(backend_addr) {
		return backend_addr
	}

	_, port, err := net.SplitHostPort(backend_addr)
	if err != nil {
		return backend_addr
	}

	alias := args.SetupLoIP
	if alias == "" {
		alias = "172.31.255.1"
	}
	if ip := net.ParseIP(alias); ip == nil || ip.IsLoopback() {
		log.Fatalf("invalid --setup-lo-ip %q (must be a non-127 IP)", alias)
	}

	log.Printf("setup-lo: backend is 127/8 — configuring lo alias %s (auto)", alias)
	code := run_embedded_setup_lo(false, alias, false)
	if code != 0 {
		log.Fatalf("setup-lo failed (exit %d); re-run as root, or use --no-auto-setup-lo / --no-transparent", code)
	}
	loAliasActive = alias

	rewritten := net.JoinHostPort(alias, port)
	log.Printf("setup-lo: mindustry backend rewritten %s -> %s", backend_addr, rewritten)
	return rewritten
}

func main() {
	log.SetFlags(log.Flags() | log.LUTC)
	log.SetPrefix("[Mindustry Forwarder Server] UTC::")

	arg.MustParse(&args)

	backend_addr := args.Mindustry
	if args.MindustryPortOnly != 0 {
		backend_addr = fmt.Sprintf("127.0.0.1:%d", args.MindustryPortOnly)
	}
	if _, _, err := net.SplitHostPort(backend_addr); err != nil {
		log.Fatalf("invalid --mindustry host:port %q: %v", backend_addr, err)
	}

	backend_addr = maybe_auto_setup_lo(backend_addr)
	defer release_all_client_local_routes()
	defer undo_lo_alias()

	// undo lo alias on SIGINT / SIGTERM as well as normal return
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

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

	go func() {
		sig := <-sigCh
		log.Printf("received %v, shutting down", sig)
		_ = listener.Close()
	}()

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			// listener closed on signal → exit accept loop; defer undoes lo
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("cannot accept tcp: %v", err)
			continue
		}
		go forward_handler(backend_addr, conn)
	}
}
