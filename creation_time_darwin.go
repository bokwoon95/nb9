//go:build darwin || freebsd || netbsd

package nb9

import (
	"io/fs"
	"syscall"
	"time"
)

func getCreationTime(filePath string, fileInfo fs.FileInfo) time.Time {
	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return time.Time{}
	}
	return time.Unix(stat.Birthtimespec.Sec, stat.Birthtimespec.Nsec)
}
