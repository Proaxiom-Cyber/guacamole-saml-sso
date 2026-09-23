package session

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type mountedStorage struct {
	Target   string           `json:"target"`
	Source   string           `json:"source"`
	FSType   string           `json:"fstype"`
	Options  string           `json:"options"`
	Children []mountedStorage `json:"children"`
}

func mountedRecordingStorage(ctx context.Context) ([]mountedStorage, error) {
	data, err := exec.CommandContext(ctx, "findmnt", "--json", "--output", "TARGET,SOURCE,FSTYPE,OPTIONS").Output()
	if err != nil {
		return nil, fmt.Errorf("list mounted storage: %w", err)
	}
	mounts, err := parseMountedStorage(data)
	if err != nil {
		return nil, err
	}
	result := []mountedStorage{}
	for _, m := range mounts {
		if info, err := os.Stat(m.Target); err == nil && info.IsDir() {
			result = append(result, m)
		}
	}
	return result, nil
}
func parseMountedStorage(data []byte) ([]mountedStorage, error) {
	var tree struct {
		Filesystems []mountedStorage `json:"filesystems"`
	}
	if err := json.Unmarshal(data, &tree); err != nil {
		return nil, err
	}
	var result []mountedStorage
	var walk func([]mountedStorage)
	walk = func(nodes []mountedStorage) {
		for _, m := range nodes {
			switch m.FSType {
			case "xfs", "ext4", "ext3", "btrfs", "zfs", "nfs", "nfs4", "cifs":
				writable := false
				for _, option := range strings.Split(m.Options, ",") {
					if option == "rw" {
						writable = true
					}
				}
				if writable && filepath.IsAbs(m.Target) && m.Target != "/boot" && !strings.HasPrefix(m.Target, "/boot/") {
					m.Options = ""
					result = append(result, m)
				}
			}
			walk(m.Children)
		}
	}
	walk(tree.Filesystems)
	return result, nil
}
func (o *Options) recordingMounts(ctx context.Context) ([]mountedStorage, error) {
	if o.MountedStorage != nil {
		return o.MountedStorage(ctx)
	}
	return mountedRecordingStorage(ctx)
}
