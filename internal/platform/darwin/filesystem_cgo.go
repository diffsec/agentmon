//go:build darwin && cgo

package darwin

import (
	"fmt"

	"github.com/diffsec/agentmon/internal/platform"
	"github.com/diffsec/agentmon/internal/platform/fuse"
)

// Mount creates a FUSE mount.
func (fs *Filesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if _, exists := fs.mounts[cfg.MountPoint]; exists {
		return nil, fmt.Errorf("mount point %q already in use", cfg.MountPoint)
	}

	mount, err := fuse.Mount(fuse.Config{
		FSConfig:   cfg,
		VolumeName: "agentmon",
	})
	if err != nil {
		return nil, err
	}

	fs.mounts[cfg.MountPoint] = mount
	return mount, nil
}

const cgoEnabled = true
