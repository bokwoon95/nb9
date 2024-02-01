package nb9

import (
	"io/fs"
	"time"
)

func CreationTime(filePath string, fileInfo fs.FileInfo) (time.Time, error) {
	if fileInfo, ok := fileInfo.(*remoteFileInfo); ok {
		return fileInfo.creationTime, nil
	}
	return time.Time{}, nil
}
