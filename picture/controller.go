package picture

import (
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/jaredwarren/rpi_pic/app"
)

// Controller implements the home resource.
type Controller struct {
}

// NewPictureController creates a home controller.
func NewPictureController(service *app.Service) *Controller {
	return &Controller{}
}

// MountPictureController "mounts" a Home resource controller on the given service.
func MountPictureController(service *app.Service, ctrl *Controller) {

	// //
	// service.Mux.HandleFunc("/picture/{id}", user.Login(ctrl.Update)).Methods("POST")

	// // list all pictures
	// service.Mux.HandleFunc("/picture", user.Login(ctrl.ListAll)).Methods("GET")

	// // show picture in browser
	// service.Mux.HandleFunc("/picture/{id}", user.Login(ctrl.Show)).Methods("GET")

	// // show user pictures
	// service.Mux.HandleFunc("/user/{id}/picture", user.Login(ctrl.ListUser)).Methods("GET")
}

// ListAll shows all pictures
func (c *Controller) ListAll(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	// TODO:
	// get all pictures

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("pictures.html", "base.html"))
	templates.ExecuteTemplate(w, "base", nil)
}

// Show picture in browser
func (c *Controller) Show(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	vars := mux.Vars(r)
	fmt.Printf("Category: %v\n", vars["id"])

	// TODO:
	// get all user pictures
	// if picture not found show new form

	// w.WriteHeader(http.StatusOK)

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("pictures.html", "base.html"))
	templates.ExecuteTemplate(w, "base", nil)
}

// ListUser show all user pictures
func (c *Controller) ListUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	// TODO:
	// get all user pictures

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/picture/picture.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", nil)
}

// Update shows all pictures
func (c *Controller) Update(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	// TODO: create token for security

	// 32 MB files max.
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("FILE_TOO_BIG"))
		return
	}

	file, handler, err := r.FormFile("picFile")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "INVALID_FILE", err)
		return
	}
	defer file.Close()

	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "INVALID_FILE", err)
		return
	}

	// check file type, detectcontenttype only needs the first 512 bytes
	filetype := http.DetectContentType(fileBytes)
	switch filetype {
	case "image/jpeg", "image/jpg":
	case "image/gif", "image/png":
		break
	default:
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(w, "INVALID_FILE")
		return
	}

	// setup dir, maybe I want to add to user dir
	os.Mkdir("pics/", os.ModePerm)

	// clean file name
	cleanFileName := filepath.Clean(handler.Filename)

	// add date to make file unique
	ext := filepath.Ext(cleanFileName)
	cleanFileName = fmt.Sprintf("%s.%s%s", strings.TrimSuffix(filepath.Base(cleanFileName), ext), time.Now().Format("2006.01.02.15.04.05"), ext)
	cleanFileName = filepath.Join("pics/", cleanFileName)

	// write file
	newFile, err := os.Create(cleanFileName)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "CANT_WRITE_FILE", err)
		return
	}
	defer newFile.Close()
	if _, err := newFile.Write(fileBytes); err != nil || newFile.Close() != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintln(w, "CANT_WRITE_FILE", err)
		return
	}

	// return that we have successfully uploaded our file!
	fmt.Fprintf(w, "Successfully Uploaded File\n")
}
