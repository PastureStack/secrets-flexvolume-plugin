//go:build linux

package driver

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

type linuxMountManager struct{}

func platformMountManager() MountManager {
	return linuxMountManager{}
}

func (linuxMountManager) IsMounted(target string) (bool, error) {
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return false, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 && unescapeMountInfo(fields[4]) == target {
			return true, nil
		}
	}
	return false, scanner.Err()
}

func (linuxMountManager) MountTmpfs(target string, maximumBytes int64) error {
	if maximumBytes < 1 {
		return errors.New("tmpfs size must be positive")
	}
	flags := uintptr(syscall.MS_NODEV | syscall.MS_NOSUID | syscall.MS_NOEXEC)
	options := "size=" + strconv.FormatInt(maximumBytes, 10) + ",mode=0755"
	if err := syscall.Mount("tmpfs", target, "tmpfs", flags, options); err != nil {
		return fmt.Errorf("mounting isolated tmpfs: %w", err)
	}
	return nil
}

func (linuxMountManager) Unmount(target string) error {
	if err := syscall.Unmount(target, 0); err != nil {
		return fmt.Errorf("unmounting isolated tmpfs: %w", err)
	}
	return nil
}

func unescapeMountInfo(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}
