package driver

import "errors"

var ErrMountUnsupported = errors.New("tmpfs mounting is supported only on Linux")

type MountManager interface {
	IsMounted(string) (bool, error)
	MountTmpfs(string, int64) error
	Unmount(string) error
}

func newMountManager() MountManager {
	return platformMountManager()
}
