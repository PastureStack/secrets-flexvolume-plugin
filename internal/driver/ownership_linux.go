//go:build linux

package driver

import "os"

func setOwnership(path string, uid, gid int) error {
	return os.Chown(path, uid, gid)
}
