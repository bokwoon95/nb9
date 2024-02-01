//go:build linux

package nb9

import (
	"golang.org/x/sys/unix"
	"io/fs"
	"time"
)

func getCreationTime(filePath string, fileInfo fs.FileInfo) (time.Time, error) {
	if fileInfo, ok := fileInfo.(*remoteFileInfo); ok {
		return fileInfo.creationTime, nil
	}
	var statx unix.Statx_t
	err := unix.Statx(unix.AT_FDCWD, filePath, unix.AT_STATX_SYNC_AS_STAT, unix.STATX_BTIME, &statx)
	if err != nil {
		return time.Time{}, nil
	}
	if statx.Mask&unix.STATX_BTIME != unix.STATX_BTIME {
		return time.Time{}, nil
	}
	return time.Unix(statx.Btime.Sec, int64(statx.Btime.Nsec)), nil
}
