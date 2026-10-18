package main

import (
	"bytes"
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alexflint/go-arg"
)

//go:embed setup-lo-transparent.sh
var setup_lo_transparent_script []byte

// Protocol constants (shared with encoder/encoder_server.py).
const (
	MIN_CONTEXT_LENGTH    = 1 + 2 // flags + port (uint16 BE)
	IPV4_LENGTH           = 4
	IPV6_LENGTH           = 16
	IS_TCP_MASK           = 1
	IS_IPV6_MASK          = 128
	UDP_FRAME_HEADER_SIZE = 2
	UDP_MAX_PAYLOAD       = 65535
)

const FALLBACK_LO_IP = "172.31.255.1"

// Linux: IPV6_TRANSPARENT is not in older x/sys snapshots used by some Go toolchains.
const IPV6_TRANSPARENT = 75 // include/uapi/linux/in6.h IPV6_TRANSPARENT

// Context is the per-tunnel client description parsed from the encoder header.
// Exported name so logs / fmt treat it as a first-class type; fields are private.
type Context struct {
	ip      netip.Addr
	is_ipv6 bool
	is_tcp  bool
	port    uint16

	_cached_string string
}

func (this *Context) init() *Context {
	proto := "UDP"
	if this.is_tcp {
		proto = "TCP"
	}
	this._cached_string = fmt.Sprintf("[%s %s:%d]", proto, this.ip.String(), this.port)
	return this
}

// String implements fmt.Stringer (exported interface method).
func (this *Context) String() string {
	return this._cached_string
}

// CLI flags — field names must be PascalCase for go-arg reflection.
var args struct {
	Listen        string        `arg:"-l,--listen" default:":6568" help:"TCP tunnel listen host and port"`
	Mindustry     string        `arg:"-m,--mindustry" default:"127.0.0.1:6567" help:"Mindustry server host:port (bare :port or port -> 127.0.0.1:port)"`
	Timeout       time.Duration `default:"5s"`
	NoTransparent bool          `arg:"--no-transparent" help:"never use IP_TRANSPARENT (always dial with local address)"`
	SetupLoIP     string        `arg:"--setup-lo-ip" default:"172.31.255.1" help:"lo alias IP used when backend is 127.0.0.0/8 (auto setup)"`
	NoAutoSetupLo bool          `arg:"--no-auto-setup-lo" help:"do not auto-configure lo alias when backend is 127.0.0.0/8"`
}

// set when auto setup-lo succeeded; cleared by undo on exit.
var lo_alias_active string

// client IPs installed as `ip route local … dev lo` so SYN-ACK/UDP replies
// to the spoofed source stay on this host. Refcounted per session.
var (
	local_route_mu   sync.Mutex
	local_route_refs = map[string]int{}
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

	return used_length, (&Context{
		ip:      ip,
		is_ipv6: is_ipv6,
		is_tcp:  is_tcp,
		port:    port,
	}).init(), nil
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

// normalize_mindustry_addr turns CLI -m values into host:port.
// ":6567" or "6567" -> "127.0.0.1:6567"; otherwise must already be host:port.
func normalize_mindustry_addr(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty mindustry address")
	}

	// bare port: "6567"
	if port, err := strconv.ParseUint(value, 10, 16); err == nil && port > 0 {
		return net.JoinHostPort("127.0.0.1", strconv.FormatUint(port, 10)), nil
	}

	// ":6567"
	if strings.HasPrefix(value, ":") {
		port_s := value[1:]
		port, err := strconv.ParseUint(port_s, 10, 16)
		if err != nil || port == 0 {
			return "", fmt.Errorf("invalid mindustry port in %q", value)
		}
		return net.JoinHostPort("127.0.0.1", strconv.FormatUint(port, 10)), nil
	}

	// already host:port (including [ipv6]:port)
	if _, _, err := net.SplitHostPort(value); err != nil {
		return "", fmt.Errorf("invalid mindustry host:port %q: %w", value, err)
	}
	return value, nil
}

func backend_host_is_loopback(backend_addr string) bool {
	host, _, err := net.SplitHostPort(backend_addr)
	if err != nil {
		host = backend_addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
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
	// (SYN never completes -> dial i/o timeout). Skip transparent on loopback
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
		if e := syscall.SetsockoptInt(f, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); e != nil {
			dial_err = e
		}
		if network == "tcp6" || network == "udp6" {
			if e := syscall.SetsockoptInt(f, syscall.IPPROTO_IPV6, IPV6_TRANSPARENT, 1); e != nil {
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

// ensure_client_local_route makes the kernel treat client_ip as a local
// address on lo. Without this, SYN-ACK/UDP replies to the spoofed source
// are routed off-box and the transparent handshake times out.
func ensure_client_local_route(client_ip string) error {
	local_route_mu.Lock()
	defer local_route_mu.Unlock()
	if local_route_refs[client_ip] > 0 {
		local_route_refs[client_ip]++
		return nil
	}
	cmd := exec.Command("ip", "route", "replace", "local", client_ip+"/32", "dev", "lo")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip route replace local %s/32 dev lo: %v (%s)", client_ip, err, bytes_trim(out))
	}
	local_route_refs[client_ip] = 1
	return nil
}

func release_client_local_route(client_ip string) {
	if client_ip == "" {
		return
	}
	local_route_mu.Lock()
	defer local_route_mu.Unlock()
	n := local_route_refs[client_ip]
	if n <= 0 {
		return
	}
	if n > 1 {
		local_route_refs[client_ip] = n - 1
		return
	}
	delete(local_route_refs, client_ip)
	cmd := exec.Command("ip", "route", "del", "local", client_ip+"/32", "dev", "lo")
	_ = cmd.Run()
}

func release_all_client_local_routes() {
	local_route_mu.Lock()
	ips := make([]string, 0, len(local_route_refs))
	for ip := range local_route_refs {
		ips = append(ips, ip)
	}
	local_route_refs = map[string]int{}
	local_route_mu.Unlock()
	for _, ip := range ips {
		cmd := exec.Command("ip", "route", "del", "local", ip+"/32", "dev", "lo")
		_ = cmd.Run()
	}
}

func bytes_trim(b []byte) string {
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
// dial target (e.g. dial 172.31.255.1:6567, reply from 10.0.0.100:6567). A
// connected UDP socket drops those replies -> s2c i/o timeout.
func dial_udp_unconnected(ctx *Context, backend_addr string, transparent bool) (net.Conn, string, error) {
	raddr, err := net.ResolveUDPAddr("udp", backend_addr)
	if err != nil {
		return nil, "", err
	}

	network := "udp4"
	if ctx.is_ipv6 || (raddr.IP != nil && raddr.IP.To4() == nil) {
		network = "udp6"
	}

	var route_ip string
	var laddr *net.UDPAddr
	lc := net.ListenConfig{}

	if transparent {
		client_ip := ctx.ip.String()
		if e := ensure_client_local_route(client_ip); e != nil {
			log.Printf("%s cannot install local route for spoofed source: %v", ctx, e)
		} else {
			route_ip = client_ip
		}
		laddr, _ = net.ResolveUDPAddr(network, net.JoinHostPort(client_ip, fmt.Sprintf("%d", ctx.port)))
		lc.Control = func(network, address string, c syscall.RawConn) error {
			return set_ip_transparent(network, c)
		}
	}

	pkt, err := lc.ListenPacket(context.Background(), network, laddr_string(laddr))
	if err != nil && transparent {
		log.Printf("%s UDP bind %v failed (%v), retry ephemeral port", ctx, laddr, err)
		laddr, _ = net.ResolveUDPAddr(network, net.JoinHostPort(ctx.ip.String(), "0"))
		pkt, err = lc.ListenPacket(context.Background(), network, laddr_string(laddr))
	}
	if err != nil {
		release_client_local_route(route_ip)
		return nil, "", err
	}

	uc, ok := pkt.(*net.UDPConn)
	if !ok {
		_ = pkt.Close()
		release_client_local_route(route_ip)
		return nil, "", fmt.Errorf("ListenPacket did not return *UDPConn")
	}
	return &udp_backend_conn{conn: uc, raddr: raddr}, route_ip, nil
}

func laddr_string(a *net.UDPAddr) string {
	if a == nil {
		return ":"
	}
	return a.String()
}

// udp_backend_conn adapts an unconnected *UDPConn to net.Conn Read/Write
// directed at a fixed remote (Mindustry). Exported methods satisfy net.Conn.
type udp_backend_conn struct {
	conn  *net.UDPConn
	raddr *net.UDPAddr
}

func (u *udp_backend_conn) Read(b []byte) (int, error) {
	for {
		n, _, err := u.conn.ReadFromUDP(b)
		if err != nil {
			return n, err
		}
		return n, nil
	}
}

func (u *udp_backend_conn) Write(b []byte) (int, error) {
	return u.conn.WriteToUDP(b, u.raddr)
}

func (u *udp_backend_conn) Close() error                       { return u.conn.Close() }
func (u *udp_backend_conn) LocalAddr() net.Addr                { return u.conn.LocalAddr() }
func (u *udp_backend_conn) RemoteAddr() net.Addr               { return u.raddr }
func (u *udp_backend_conn) SetDeadline(t time.Time) error      { return u.conn.SetDeadline(t) }
func (u *udp_backend_conn) SetReadDeadline(t time.Time) error  { return u.conn.SetReadDeadline(t) }
func (u *udp_backend_conn) SetWriteDeadline(t time.Time) error { return u.conn.SetWriteDeadline(t) }

// dial_backend returns the backend conn, whether the source was spoofed, and
// an optional client IP holding a local route (caller must release it).
func dial_backend(ctx *Context, backend_addr string) (conn net.Conn, transparent bool, route_ip string, err error) {
	network := base_network(ctx.is_tcp)
	use_tproxy := want_transparent(backend_addr)

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

	client_ip := ctx.ip.String()
	if e := ensure_client_local_route(client_ip); e != nil {
		log.Printf("%s cannot install local route for spoofed source: %v", ctx, e)
	} else {
		route_ip = client_ip
	}

	tnet := network + "4"
	if ctx.is_ipv6 {
		tnet = network + "6"
	}
	local, _ := net.ResolveTCPAddr(tnet, net.JoinHostPort(client_ip, "0"))

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
		release_client_local_route(route_ip)
		route_ip = ""
		plain := net.Dialer{Timeout: args.Timeout}
		c2, e2 := plain.DialContext(context.Background(), network, backend_addr)
		return c2, false, "", e2
	}
	return c, true, route_ip, nil
}

func copy_tcp(dst, src net.Conn, label string, session *Context) {
	_, err := io.Copy(dst, src)
	if err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		log.Printf("%s %s unexpectedly closed: %v", session, label, err)
	}
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
	case *udp_backend_conn:
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
	_ = conn.SetReadDeadline(time.Time{})

	backend_conn, transparent, route_ip, err := dial_backend(ctx, backend_addr)
	if err != nil {
		log.Printf("%s cannot connect to Mindustry Server: %v", ctx, err)
		return
	}
	defer backend_conn.Close()
	defer release_client_local_route(route_ip)

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
// then deletes the temp tree (use-once).
//
// Always captures script stdout+stderr (nil Stdout would inherit the parent and
// bypass our logger). On success with quiet=false, lines are logged with the
// decoder prefix. On failure, detail is the trimmed script output (or the
// exec error) so callers can include it in Fatalf / log lines.
func run_embedded_setup_lo(undo bool, alias_ip string, quiet bool) (code int, detail string) {
	dir, err := os.MkdirTemp("", "mindustry-forwarder-setup-lo-*")
	if err != nil {
		return 1, fmt.Sprintf("cannot create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	script_path := filepath.Join(dir, "setup-lo-transparent.sh")
	if err := os.WriteFile(script_path, setup_lo_transparent_script, 0o700); err != nil {
		return 1, fmt.Sprintf("cannot write embedded script: %v", err)
	}

	// env bash <script> [--undo] [--quiet] <alias_ip>
	// --quiet only suppresses the script's own echo; we still capture everything.
	args := make([]string, 0, 4)
	if undo {
		args = append(args, "--undo")
	}
	if quiet {
		args = append(args, "--quiet")
	}
	args = append(args, alias_ip)

	cmd := exec.Command("/usr/bin/env", append([]string{"bash", script_path}, args...)...)
	var captured bytes.Buffer
	cmd.Stdout = &captured
	cmd.Stderr = &captured
	run_err := cmd.Run()
	out := strings.TrimSpace(captured.String())

	if run_err == nil {
		if !quiet && out != "" {
			for _, line := range strings.Split(out, "\n") {
				log.Printf("setup-lo: %s", line)
			}
		}
		return 0, out
	}

	detail = out
	if detail == "" {
		detail = run_err.Error()
	}
	if ee, ok := run_err.(*exec.ExitError); ok {
		return ee.ExitCode(), detail
	}
	return 1, detail
}

func undo_lo_alias() {
	if lo_alias_active == "" {
		return
	}
	ip := lo_alias_active
	lo_alias_active = ""
	code, detail := run_embedded_setup_lo(true, ip, true)
	if code != 0 {
		if detail != "" {
			log.Printf("setup-lo undo failed (exit %d) for %s: %s", code, ip, detail)
		} else {
			log.Printf("setup-lo undo failed (exit %d) for %s", code, ip)
		}
		return
	}
	log.Printf("setup-lo: removed lo alias %s", ip)
}

// maybe_auto_setup_lo: when backend is 127.0.0.0/8 and transparent is desired,
// add a non-127 alias on lo and rewrite backend_addr to that alias.
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
		alias = FALLBACK_LO_IP
	}
	if ip := net.ParseIP(alias); ip == nil || ip.IsLoopback() {
		log.Fatalf("invalid --setup-lo-ip %q (must be a non-127 IP)", alias)
	}

	log.Printf("setup-lo: configuring 127.0.0.0/8 backend interface `lo` alias: %s", alias)
	code, detail := run_embedded_setup_lo(false, alias, false)
	if code != 0 {
		if detail != "" {
			log.Fatalf("setup-lo failed (exit %d), use --no-auto-setup-lo / --no-transparent to disable setup: %s", code, detail)
		}
		log.Fatalf("setup-lo failed (exit %d), re-run as root, or use --no-auto-setup-lo / --no-transparent to disable setup", code)
	}
	lo_alias_active = alias

	rewritten := net.JoinHostPort(alias, port)
	log.Printf("setup-lo: mindustry backend rewritten %s -> %s", backend_addr, rewritten)
	return rewritten
}

func main() {
	log.SetFlags(log.Flags() | log.LUTC)
	log.SetPrefix("[Mindustry Forwarder Server] UTC::")

	arg.MustParse(&args)

	backend_addr, err := normalize_mindustry_addr(args.Mindustry)
	if err != nil {
		log.Fatalf("%v", err)
	}

	backend_addr = maybe_auto_setup_lo(backend_addr)
	defer release_all_client_local_routes()
	defer undo_lo_alias()

	sig_ch := make(chan os.Signal, 1)
	signal.Notify(sig_ch, syscall.SIGINT, syscall.SIGTERM)

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
		sig := <-sig_ch
		log.Printf("received %v, shutting down", sig)
		_ = listener.Close()
	}()

	for {
		conn, err := listener.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("cannot accept tcp: %v", err)
			continue
		}
		go forward_handler(backend_addr, conn)
	}
}
