package nb9

import (
	"io/fs"
	"time"
)

func CreationTime(filePath string, fileInfo fs.FileInfo) (time.Time, error) {
	return time.Time{}, nil
}
