//go:build !windows && !linux && !darwin && !freebsd && !netbsd

package nb9

import (
	"io/fs"
	"time"
)

func getCreationTime(filePath string, fileInfo fs.FileInfo) time.Time {
	return time.Time{}
}
