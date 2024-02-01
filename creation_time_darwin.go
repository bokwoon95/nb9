//go:build darwin || freebsd || netbsd

package nb9

import (
	"io/fs"
	"syscall"
	"time"
)

func getCreationTime(filePath string, fileInfo fs.FileInfo) (time.Time, error) {
	if fileInfo, ok := fileInfo.(*remoteFileInfo); ok {
		return fileInfo.creationTime, nil
	}
	stat := fileInfo.Sys().(*syscall.Stat_t)
	return time.Unix(stat.Birthtimespec.Sec, stat.Birthtimespec.Nsec), nil
}
