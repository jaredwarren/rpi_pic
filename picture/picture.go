package picture

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"
)

func init() {
	rand.Seed(time.Now().Unix())
}

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
	//
	previous  []string
	nextTimer *time.Timer
}

func fileExists(filename string) (bool, os.FileInfo) {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false, info
	}
	return !info.IsDir(), info
}

// Set current picture
func (p *Picture) Set(path string) (err error) {

	info, _ := os.Stat(path)
	p.Name = path // TODO: base
	p.Path = path
	p.Size = info.Size()

	fmt.Println(" >>> ", path)

	// TODO: stack file

	// show picture, bash or web????

	// restart timer...

	return nil
}

// Next current picture
func (p *Picture) Next() (err error) {
	// get all files
	files := []string{}
	err = filepath.Walk("./pictures", func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		// skip current picture
		if path == p.Path {
			return nil
		}
		if path == "pictures/broken.png" {
			return nil
		}
		if path == "pictures/default.png" {
			return nil
		}

		ext := filepath.Ext(path)
		if ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || ext == ".png" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return
	}
	if len(files) == 0 {
		return errors.New("No files found")
	}

	randFile := files[rand.Intn(len(files))]

	info, _ := os.Stat(randFile)
	p.Name = randFile // TODO: base
	p.Path = randFile
	p.Size = info.Size()

	fmt.Println(" >>> ", randFile)

	// TODO: stack file

	// show picture, bash or web????

	// restart timer...

	return nil
}

// Previous current picture
func (p *Picture) Previous() (err error) {
	// get file
	// update data...
	return nil
}

// Start current picture
func (p *Picture) Start(picTime int) (err error) {
	p.Next()

	// TODO: get config,
	ticker := time.NewTicker(time.Duration(picTime) * time.Second)
	go func() {
		for range ticker.C {
			p.Next()
		}
	}()
	return nil
}
