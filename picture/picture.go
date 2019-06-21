package picture

import (
	"os"
)

func fileExists(filename string) (bool, os.FileInfo) {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false, info
	}
	return !info.IsDir(), info
}
