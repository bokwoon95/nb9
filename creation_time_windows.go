//go:build windows

package nb9

import (
	"io/fs"
	"syscall"
	"time"
)

func getCreationTime(filePath string, fileInfo fs.FileInfo) time.Time {
	fileAttributeData := fileInfo.Sys().(*syscall.Win32FileAttributeData)
	return time.Unix(0, fileAttributeData.CreationTime.Nanoseconds())
}
