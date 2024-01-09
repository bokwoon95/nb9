//go:build dev
// +build dev

package nb9

import (
	"os"
)

func init() {
	RuntimeFS = os.DirFS(".")
}
