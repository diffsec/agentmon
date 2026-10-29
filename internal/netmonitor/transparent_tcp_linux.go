//go:build linux

package netmonitor

import (
	"encoding/binary"
	"net"
	"unsafe"

	"github.com/diffsec/agentmon/internal/approvals"
	dbevents "github.com/diffsec/agentmon/internal/db/events"
	"github.com/diffsec/agentmon/internal/session"
	"golang.org/x/sys/unix"
)

func StartTransparentTCP(listenAddr string, sessionID string, sess *session.Session, dnsCache *DNSCache, engine EngineFunc, approvalsMgr *approvals.Manager, emit Emitter, dbBypass ...*dbevents.BypassEmitter) (*TransparentTCP, int, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, 0, err
	}
	t := &TransparentTCP{
		sessionID: sessionID,
		sess:      sess,
		dnsCache:  dnsCache,
		policy:    engine,
		approvals: approvalsMgr,
		emit:      emit,
		ln:        ln,
		done:      make(chan struct{}),
	}
	if len(dbBypass) > 0 {
		t.SetDBBypassEmitter(dbBypass[0])
	}
	t.wg.Add(1)
	go t.acceptLoop()
	return t, ln.Addr().(*net.TCPAddr).Port, nil
}

func (t *TransparentTCP) acceptLoop() {
	defer t.wg.Done()
	for {
		conn, err := t.ln.Accept()
		if err != nil {
			select {
			case <-t.done:
				return
			default:
				continue
			}
		}
		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			_ = t.handle(conn)
		}()
	}
}

func (t *TransparentTCP) handle(conn net.Conn) error {
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil
	}
	dstIP, dstPort, err := originalDst(tcp)
	if err != nil {
		_ = conn.Close()
		return nil
	}
	return t.serve(conn, gatewayFlow{dstIP: dstIP, dstPort: dstPort})
}

func originalDst(c *net.TCPConn) (net.IP, int, error) {
	f, err := c.File()
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	fd := int(f.Fd())

	var addr unix.RawSockaddrInet4
	size := uint32(unsafe.Sizeof(addr))
	_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), uintptr(unix.SOL_IP), uintptr(unix.SO_ORIGINAL_DST), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return nil, 0, errno
	}

	ip := net.IPv4(addr.Addr[0], addr.Addr[1], addr.Addr[2], addr.Addr[3])
	port := int(binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&addr.Port))[:]))
	return ip, port, nil
}
