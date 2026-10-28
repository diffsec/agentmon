//go:build darwin && cgo

package policysock

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"unsafe"

	"golang.org/x/sys/unix"
)

/*
#include <libproc.h>
#include <sys/proc_info.h>
*/
import "C"

// ValidatePeer checks that a connected Unix socket peer is:
// 1. Running as root (UID 0)
// 2. Signed by the expected team ID
func ValidatePeer(conn *net.UnixConn, teamID string) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return fmt.Errorf("syscall conn: %w", err)
	}

	var peerUID uint32
	var peerPID int32
	var sockErr error

	err = raw.Control(func(fd uintptr) {
		// Layer 2: Peer UID check
		uid, err := getpeereid(int(fd))
		if err != nil {
			sockErr = fmt.Errorf("getpeereid: %w", err)
			return
		}
		peerUID = uid

		// Layer 3: Get peer PID (best-effort; system extensions may
		// not support LOCAL_PEERPID due to sandbox restrictions).
		pid, err := getPeerPID(int(fd))
		if err != nil {
			// If peer is root, skip PID-based code signing check.
			// The UID check is sufficient for system extension peers.
			if uid == 0 {
				return
			}
			sockErr = fmt.Errorf("LOCAL_PEERPID: %w", err)
			return
		}
		peerPID = pid
	})
	if err != nil {
		return fmt.Errorf("control: %w", err)
	}
	if sockErr != nil {
		return sockErr
	}

	// Layer 2: Reject non-root
	if peerUID != 0 {
		return fmt.Errorf("peer UID %d is not root", peerUID)
	}

	// Layer 3: Resolve binary path and validate code signing.
	// Skip if PID unavailable (system extension sandbox restriction).
	if peerPID > 0 {
		path, err := resolvePIDPath(peerPID)
		if err != nil {
			return fmt.Errorf("resolve pid %d path: %w", peerPID, err)
		}

		if err := validateCodeSignature(path, teamID); err != nil {
			return fmt.Errorf("code signing validation failed for %s (pid %d): %w", path, peerPID, err)
		}
	}

	return nil
}

// classifyPeer decides what a connected peer may ask for.
//
// A root peer goes through ValidatePeer unchanged and gets rolePrivileged:
// that is the system extension. Before roles existed, every non-root peer was
// rejected here, which also shut out the approval dialog, because the dialog
// runs as the logged-in user. A non-root peer is now admitted only as the
// dialog, and only when all three hold:
//
//   - it runs as the same user as this daemon, so another account on the
//     machine cannot answer this user's approvals;
//   - its PID is readable, so there is a binary to check;
//   - that binary's code signature carries the team ID and the dialog's
//     signing identifier.
//
// The identifier is the part that keeps an agent out. An agent can exec any
// binary in the bundle, including the team-signed agentmon CLI, so the team
// ID alone would admit a binary the agent controls the arguments of. The
// dialog resolves an approval only when a person clicks.
func classifyPeer(conn *net.UnixConn, teamID string) (peerRole, error) {
	uid, pid, err := peerCredentials(conn)
	if err != nil {
		return 0, err
	}
	if uid == 0 {
		if err := ValidatePeer(conn, teamID); err != nil {
			return 0, err
		}
		return rolePrivileged, nil
	}
	if euid := uint32(os.Geteuid()); uid != euid {
		return 0, fmt.Errorf("peer UID %d is neither root nor this daemon's user (UID %d)", uid, euid)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("peer UID %d: PID unavailable, so its code signature cannot be checked", uid)
	}
	path, err := resolvePIDPath(pid)
	if err != nil {
		return 0, fmt.Errorf("resolve pid %d path: %w", pid, err)
	}
	if err := verifyRequirement(path, approvalDialogRequirement(teamID)); err != nil {
		return 0, fmt.Errorf("non-root peer %s (pid %d) is not the signed approval dialog: %w", path, pid, err)
	}
	return roleApprovalDialog, nil
}

// peerCredentials returns the peer's effective UID and, when readable, PID.
func peerCredentials(conn *net.UnixConn) (uint32, int32, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("syscall conn: %w", err)
	}
	var uid uint32
	var pid int32
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		u, err := getpeereid(int(fd))
		if err != nil {
			sockErr = fmt.Errorf("getpeereid: %w", err)
			return
		}
		uid = u
		if p, err := getPeerPID(int(fd)); err == nil {
			pid = p
		}
	})
	if err != nil {
		return 0, 0, fmt.Errorf("control: %w", err)
	}
	return uid, pid, sockErr
}

// LOCAL_PEERPID is the socket option to get the peer's PID on macOS.
const LOCAL_PEERPID = 0x002

// getpeereid returns the effective UID of the peer.
func getpeereid(fd int) (uid uint32, err error) {
	xucred, err := unix.GetsockoptXucred(fd, unix.SOL_LOCAL, unix.LOCAL_PEERCRED)
	if err != nil {
		return 0, err
	}
	return xucred.Uid, nil
}

// getPeerPID returns the PID of the peer process.
func getPeerPID(fd int) (int32, error) {
	pid, err := unix.GetsockoptInt(fd, unix.SOL_LOCAL, LOCAL_PEERPID)
	if err != nil {
		return 0, err
	}
	return int32(pid), nil
}

// resolvePIDPath returns the executable path for a given PID.
func resolvePIDPath(pid int32) (string, error) {
	var buf [C.PROC_PIDPATHINFO_MAXSIZE]C.char
	ret := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if ret <= 0 {
		return "", fmt.Errorf("proc_pidpath failed for pid %d", pid)
	}
	return C.GoString(&buf[0]), nil
}

// validateCodeSignature verifies a binary is signed by the expected team ID.
func validateCodeSignature(path string, teamID string) error {
	return verifyRequirement(path, teamRequirement(teamID))
}

// verifyRequirement checks the binary at path against a code requirement.
func verifyRequirement(path, requirement string) error {
	cmd := exec.Command("codesign", "--verify", "-R="+requirement, path)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("codesign verification failed: %s: %w", string(output), err)
	}
	return nil
}
