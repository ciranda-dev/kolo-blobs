//go:build unix

package koloblobs

import (
	"os"
	"runtime"
	"syscall"
)

// maxRSS returns the peak resident size of an ended process in bytes.
func maxRSS(ps *os.ProcessState) uint64 {
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok {
		return 0
	}
	if runtime.GOOS == "darwin" {
		return uint64(ru.Maxrss) // bytes
	}
	return uint64(ru.Maxrss) << 10 // KiB
}
