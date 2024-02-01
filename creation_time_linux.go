//go:build linux

package nb9

import (
	"golang.org/x/sys/unix"
	"io/fs"
	"time"
)

func getCreationTime(filePath string, fileInfo fs.FileInfo) time.Time {
	var statx unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, filePath, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &statx)
	if err != nil {
		return time.Time{}
	}
	if statx.Mask&unix.STATX_BTIME != unix.STATX_BTIME {
		return time.Time{}
	}
	return time.Unix(statx.Btime.Sec, int64(statx.Btime.Nsec))
}
