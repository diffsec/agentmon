//go:build darwin && !cgo

package policysock

import (
	"net"
)

// ValidatePeer is a no-op when CGO is disabled (cross-compilation).
// The CGO build uses Unix socket credentials and code signing validation.
func ValidatePeer(conn *net.UnixConn, teamID string) error {
	return nil
}

// classifyPeer cannot check anything without cgo. Every peer keeps the access
// the no-op ValidatePeer always gave it, as roleUnverified, and that role can
// never resolve an approval. A build without cgo therefore has no working
// approval dialog, rather than one that any local process can answer.
func classifyPeer(conn *net.UnixConn, teamID string) (peerRole, error) {
	return roleUnverified, nil
}
