//go:build windows

package nb9

import (
	"io/fs"
	"syscall"
	"time"
)

func getCreationTime(filePath string, fileInfo fs.FileInfo) (time.Time, error) {
	return time.Unix(0, fileInfo.Sys().(*syscall.Win32FileAttributeData).CreationTime.Nanoseconds()), nil
}
