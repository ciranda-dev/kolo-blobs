//go:build !unix

package koloblobs

import "os"

// maxRSS returns 0 where the peak resident size is not reported; the heap bound still applies.
func maxRSS(*os.ProcessState) uint64 { return 0 }
