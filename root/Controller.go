package root

import (
	"bytes"
	"fmt"
	"net/http"
	"os/exec"
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

	//
	service.Mux.HandleFunc("/root/restart", ctrl.Root(ctrl.RestartHandler))

	service.Mux.HandleFunc("/root/update", ctrl.Root(ctrl.Update)).Methods("GET")
	service.Mux.HandleFunc("/root/update", ctrl.Root(ctrl.UpdateHandler)).Methods("POST")
}

// RestartHandler ...
func (c *Controller) RestartHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("RestartHandler", r.URL.String())
	w.Write([]byte("TODO: figure out how to restart...."))
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

	// unzip package
	// copy files
	// restart if needed

	w.Write([]byte("TODO: figure out how to update files, and restart self"))
}

// Home ...
func (c *Controller) Home(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())
	session, _ := c.cookieStore.Get(r, "user-session")
	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/root/home.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
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
