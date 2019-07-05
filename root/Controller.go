package root

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/sessions"
	"github.com/jaredwarren/rpi_pic/app"
	"github.com/jaredwarren/rpi_pic/user"
)

// Controller implements the home resource.
type Controller struct {
	udb         *user.Store
	service     *app.Service
	cookieStore *sessions.CookieStore
}

// NewRootController creates a home controller.
func NewRootController(service *app.Service, udb *user.Store, cookieStore *sessions.CookieStore) *Controller {
	// force create root user
	rootUser := &user.User{
		Username: "root",
		Admin:    true,
		Root:     true,
		Token:    "",
	}
	// TODO: get password from env
	hash, err := bcrypt.GenerateFromPassword([]byte("root"), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}
	rootUser.Password = string(hash)

	// Save user to db
	err = udb.Save(rootUser)
	if err != nil {
		panic(err)
	}

	return &Controller{
		udb:         udb,
		service:     service,
		cookieStore: cookieStore,
	}
}

// MountRootController "mounts" a Home resource controller on the given service.
func MountRootController(service *app.Service, ctrl *Controller) {
	service.Mux.HandleFunc("/root", ctrl.Root(ctrl.Home)).Methods("GET")

	service.Mux.HandleFunc("/root/restart", user.CsrfForm(ctrl.Root(ctrl.RestartHandler)))

	service.Mux.HandleFunc("/root/update", ctrl.Root(ctrl.Update)).Methods("GET")
	service.Mux.HandleFunc("/root/update", ctrl.Root(ctrl.UpdateHandler)).Methods("POST")
}

// RestartHandler ...
func (c *Controller) RestartHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("RestartHandler", r.URL.String())

	// TODO: show reload animation, or something...

	// parse every time to make updates easier, and save memory
	tpl := template.Must(template.New("base").Funcs(template.FuncMap{"CsrfToken": user.CsrfToken}).ParseFiles("templates/root/restart.html", "templates/base.html"))
	tpl.ExecuteTemplate(w, "base", &struct {
		Title string
		// Messages []string
	}{
		Title: "User List",
		// Messages: messages,
	})
}

// Update ...
func (c *Controller) Update(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Update", r.URL.String())
	session, _ := c.cookieStore.Get(r, "user-session")
	// Check for duplicate username
	messages := user.GetMessages(session)

	// parse every time to make updates easier, and save memory
	tpl := template.Must(template.New("base").Funcs(template.FuncMap{"CsrfToken": user.CsrfToken}).ParseFiles("templates/root/update.html", "templates/base.html"))
	tpl.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
	}{
		Title:    "User List",
		Messages: messages,
	})
	session.Save(r, w)
}

// UpdateHandler ...
func (c *Controller) UpdateHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("UpdateHandler", r.URL.String())

	// get session
	session, _ := c.cookieStore.Get(r, "user-session")

	// 32 MB files max.
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		session.AddFlash(err.Error())
		session.Save(r, w)
		http.Redirect(w, r, "/root/update", http.StatusFound)
		return
	}

	// // make sure user pic dir exists
	packagePath := "updates/"
	os.RemoveAll(packagePath)
	os.MkdirAll(packagePath, os.ModePerm)

	// // process each file

	file, _, err := r.FormFile("package")
	defer file.Close()
	if err != nil {
		session.AddFlash(err.Error())
		session.Save(r, w)
		http.Redirect(w, r, "/root/update", http.StatusFound)
		return
	}

	zr, err := zip.NewReader(file, r.ContentLength)
	if err != nil {
		session.AddFlash(err.Error())
		session.Save(r, w)
		http.Redirect(w, r, "/root/update", http.StatusFound)
		return
	}
	for _, zf := range zr.File {
		dst, err := os.Create("updates/" + zf.Name)
		if err != nil {
			// err
		}
		defer dst.Close()
		src, err := zf.Open()
		if err != nil {
			// err
		}
		defer src.Close()

		io.Copy(dst, src)
	}

	// redirect back to picture list
	http.Redirect(w, r, "/root/restart", http.StatusFound)
}

// Home ...
func (c *Controller) Home(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())
	session, _ := c.cookieStore.Get(r, "user-session")
	// parse every time to make updates easier, and save memory
	tpl := template.Must(template.New("base").Funcs(template.FuncMap{"CsrfToken": user.CsrfToken}).ParseFiles("templates/root/home.html", "templates/base.html"))
	tpl.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
	}{
		Title:    "Home",
		Messages: user.GetMessages(session),
	})
	session.Save(r, w)
}

// RunBash ...
func RunBash(commandString string, env []string) (stdOut, stdErr string) {
	cmd := exec.Command("bash", "-c", commandString)
	if len(env) > 0 {
		cmd.Env = env
	}
	var stdOutBuf bytes.Buffer
	var stdErrBuf bytes.Buffer
	cmd.Stdout = &stdOutBuf
	cmd.Stderr = &stdErrBuf
	cmd.Run()
	stdOut = strings.TrimSuffix(stdOutBuf.String(), "\n")
	stdErr = strings.TrimSuffix(stdErrBuf.String(), "\n")
	return
}

// Unzip will decompress a zip archive, moving all files and folders
// within the zip file (parameter 1) to an output directory (parameter 2).
func Unzip(src string, dest string) ([]string, error) {

	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()

	for _, f := range r.File {

		// Store filename/path for returning and using later on
		fpath := filepath.Join(dest, f.Name)

		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}

		filenames = append(filenames, fpath)

		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		// Make File
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}

		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}

		_, err = io.Copy(outFile, rc)

		// Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()

		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}
