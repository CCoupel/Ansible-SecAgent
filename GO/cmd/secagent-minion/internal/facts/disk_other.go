//go:build !linux && !windows

package facts

import "fmt"

func diskTotalBytesOS(path string) (uint64, error) {
	return 0, fmt.Errorf("disk stat not implemented on this platform")
}
