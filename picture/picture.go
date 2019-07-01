package picture

import (
	"os"
)

// Picture file
type Picture struct {
	Name        string
	Path        string
	Description string
	URL         string
	Type        string
	ModTime     string
	Size        int64
	Owner       string
}

func fileExists(filename string) (bool, os.FileInfo) {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false, info
	}
	return !info.IsDir(), info
}
