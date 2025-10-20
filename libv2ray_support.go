package libv2ray

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
	v2net "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	v2internet "github.com/xtls/xray-core/transport/internet"
)

type protectSet interface {
	Protect(int) bool
}

type resolved struct {
	IPs  []net.IP
	Port int
}

// NewProtectedDialer ...
func NewProtectedDialer(p protectSet) *ProtectedDialer {
	d := &ProtectedDialer{
		// prefer native lookup on Android
		resolver:   &net.Resolver{PreferGo: false},
		protectSet: p,
	}
	return d
}

// ProtectedDialer ...
type ProtectedDialer struct {
	resolver *net.Resolver
	protectSet
}

// simplified version of golang: internetAddrList in src/net/ipsock.go
func (d *ProtectedDialer) lookupAddr(addr string) (*resolved, error) {

	var (
		err        error
		host, port string
		portnum    int
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if host, port, err = net.SplitHostPort(addr); err != nil {
		log.Printf("PrepareDomain SplitHostPort Err: %v", err)
		return nil, err
	}

	if portnum, err = d.resolver.LookupPort(ctx, "tcp", port); err != nil {
		log.Printf("PrepareDomain LookupPort Err: %v", err)
		return nil, err
	}

	addrs, err := d.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("domain %s Failed to resolve", addr)
	}

	IPs := make([]net.IP, 0, len(addrs))
	for _, ia := range addrs {
		IPs = append(IPs, ia.IP)
	}

	return &resolved{
		IPs:  IPs,
		Port: portnum,
	}, nil
}


func (d *ProtectedDialer) getFd(network v2net.Network) (fd int, err error) {
	switch network {
	case v2net.Network_TCP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_TCP)
	case v2net.Network_UDP:
		fd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	default:
		err = fmt.Errorf("unknown network")
	}
	return
}

// Init implement internet.SystemDialer
func (d *ProtectedDialer) Init(_ dns.Client, _ outbound.Manager) {
	// do nothing
}

// Dial exported as the protected dial method
func (d *ProtectedDialer) Dial(ctx context.Context,
	src v2net.Address, dest v2net.Destination, sockopt *v2internet.SocketConfig) (net.Conn, error) {

	// Get file descriptor for the connection
	fd, err := d.getFd(dest.Network)
	if err != nil {
		return nil, err
	}

	// For all connections, resolve and connect with protection
	Address := dest.NetAddr()
	resolved, err := d.lookupAddr(Address)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}

	// Create protected connection using the first resolved IP
	return d.fdConn(ctx, resolved.IPs[0], resolved.Port, dest.Network, fd)
}


func (d *ProtectedDialer) fdConn(ctx context.Context, ip net.IP, port int, network v2net.Network, fd int) (net.Conn, error) {

	defer unix.Close(fd)

	// call android VPN service to "protect" the fd connecting straight out
	if !d.Protect(fd) {
		log.Printf("fdConn fail to protect, Close Fd: %d", fd)
		return nil, errors.New("fail to protect")
	}

	sa := &unix.SockaddrInet6{
		Port: port,
	}
	copy(sa.Addr[:], ip.To16())

	if network == v2net.Network_UDP {
		if err := unix.Bind(fd, &unix.SockaddrInet6{}); err != nil {
			log.Printf("fdConn unix.Bind err, Close Fd: %d Err: %v", fd, err)
			return nil, err
		}
	} else {
		if err := unix.Connect(fd, sa); err != nil {
			log.Printf("fdConn unix.Connect err, Close Fd: %d Err: %v", fd, err)
			return nil, err
		}
	}

	file := os.NewFile(uintptr(fd), "Socket")
	if file == nil {
		// returned value will be nil if fd is not a valid file descriptor
		return nil, errors.New("fdConn fd invalid")
	}

	defer file.Close()
	//Closing conn does not affect file, and closing file does not affect conn.
	if network == v2net.Network_UDP {
		packetConn, err := net.FilePacketConn(file)
		if err != nil {
			log.Printf("fdConn FilePacketConn Close Fd: %d Err: %v", fd, err)
			return nil, err
		}
		return &v2internet.PacketConnWrapper{
			Conn: packetConn,
			Dest: &net.UDPAddr{
				IP:   ip,
				Port: port,
			},
		}, nil
	} else {
		conn, err := net.FileConn(file)
		if err != nil {
			log.Printf("fdConn FileConn Close Fd: %d Err: %v", fd, err)
			return nil, err
		}
		return conn, nil
	}
}
