//go:build !linux

package driver

func setOwnership(string, int, int) error {
	return nil
}
