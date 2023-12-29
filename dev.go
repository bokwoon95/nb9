//go:build dev
// +build dev

package nb9

import (
	"os"
)

func init() {
	rootFS = os.DirFS(".")
}
