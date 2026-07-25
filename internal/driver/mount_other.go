//go:build !linux

package driver

type unsupportedMountManager struct{}

func platformMountManager() MountManager {
	return unsupportedMountManager{}
}

func (unsupportedMountManager) IsMounted(string) (bool, error) {
	return false, ErrMountUnsupported
}

func (unsupportedMountManager) MountTmpfs(string, int64) error {
	return ErrMountUnsupported
}

func (unsupportedMountManager) Unmount(string) error {
	return ErrMountUnsupported
}
