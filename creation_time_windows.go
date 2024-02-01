//go:build windows

package nb9

import (
	"io/fs"
	"syscall"
	"time"
)

func CreationTime(absolutePath string, fileInfo fs.FileInfo) time.Time {
	fileAttributeData, ok := fileInfo.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return time.Time{}
	}
	return time.Unix(0, fileAttributeData.CreationTime.Nanoseconds())
}
