package root

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/jaredwarren/rpi_pic/picture"

	"github.com/jaredwarren/rpi_pic/form"
	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
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

	// service.Mux.HandleFunc("/root/login", ctrl.Login).Methods("GET")
	// service.Mux.HandleFunc("/root/login", ctrl.LoginHandler).Methods("POST")
	// service.Mux.HandleFunc("/root/logout", ctrl.LogoutHandler).Methods("GET")

	// admin list users
	service.Mux.HandleFunc("/root/user", ctrl.Root(ctrl.ListUsers)).Methods("GET")

	// invite user to register
	// service.Mux.HandleFunc("/root/user/invite", ctrl.Root(ctrl.Invite)).Methods("GET")
	// service.Mux.HandleFunc("/root/user/invite", user.CsrfForm(ctrl.Root(ctrl.InviteHandler))).Methods("POST")

	service.Mux.HandleFunc("/root/user/{username}/delete", user.CsrfForm(ctrl.Root(ctrl.DeleteUser))).Methods("GET")
	service.Mux.HandleFunc("/root/user/{username}", ctrl.Root(ctrl.UpdateUser)).Methods("POST")

	// admin user update, add this one last
	service.Mux.HandleFunc("/root/user/{username}", ctrl.Root(ctrl.ShowUser)).Methods("GET")
	// service.Mux.HandleFunc("/admin/user/{id}", admin(ctrl.ShowUser)).Methods("POST")

	// admin delete user
	// service.Mux.HandleFunc("/admin/user/{id}", admin(ctrl.TODO)).Methods("DELETE")

	// ## Picture management
	// picture list
	service.Mux.HandleFunc("/root/picture", ctrl.Root(ctrl.ListPictures)).Methods("GET")
	// // picture show in browser
	// service.Mux.HandleFunc("/admin/picture/{id}", admin(ctrl.TODO)).Methods("GET")
	// // display picture on device
	// service.Mux.HandleFunc("/admin/picture/{id}/display", admin(ctrl.TODO)).Methods("GET")
	// // picture delete
	// service.Mux.HandleFunc("/admin/picture/{id}", admin(ctrl.TODO)).Methods("DELETE")

	// // list picture tags
	// service.Mux.HandleFunc("/admin/picture/{id}/tag", admin(ctrl.TODO)).Methods("GET")
	// // tag picture
	// service.Mux.HandleFunc("/admin/picture/{pid}/tag/{tid}", admin(ctrl.TODO)).Methods("POST")
	// // delete picture tag
	// service.Mux.HandleFunc("/admin/picture/{pid}/tag/{tid}", admin(ctrl.TODO)).Methods("DELETE")
	// // list pictures with tag
	// service.Mux.HandleFunc("/admin/tag/{id}/picture", admin(ctrl.TODO)).Methods("GET")

	// // show settings
	// service.Mux.HandleFunc("/admin/settings", admin(ctrl.TODO)).Methods("GET")
	// // update settings
	// service.Mux.HandleFunc("/admin/settings", admin(ctrl.TODO)).Methods("POST")
}

// ListUsers ...
func (c *Controller) ListUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ListUsers", r.URL.String())
	session, _ := c.cookieStore.Get(r, "user-session")
	// Check for duplicate username
	messages := user.GetMessages(session)

	users, err := c.udb.FetchAll()
	if err != nil {
		messages = append(messages, "error loading users:"+err.Error())
		return
	}

	// TODO: count pictures
	for _, user := range users {
		picturePath := fmt.Sprintf("pictures/%s", filepath.Clean(user.Username))
		files, _ := ioutil.ReadDir(picturePath)
		user.PicCount = len(files)
	}

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/root/listUsers.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title     string
		CsrfToken string
		Messages  []string
		Users     []*user.User
	}{
		Title:     "User List",
		Messages:  messages,
		Users:     users,
		CsrfToken: form.New(),
	})
	session.Save(r, w)
}

// ListPictures ...
func (c *Controller) ListPictures(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ListPictures", r.URL.String())
	// Check for duplicate username
	session, _ := c.cookieStore.Get(r, "user-session")
	messages := user.GetMessages(session)

	users, err := c.udb.FetchAll()
	if err != nil {
		messages = append(messages, "error loading users:"+err.Error())
		return
	}

	// picture url base
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = fmt.Sprintf("http://%s/", r.Host)
	}

	pictures := []*picture.Picture{}

	// TODO: count pictures
	for _, user := range users {
		picturePath := fmt.Sprintf("pictures/%s", filepath.Clean(user.Username))

		// get lis of all user photos
		filepath.Walk(picturePath, func(path string, info os.FileInfo, err error) error {
			if !info.IsDir() {
				pictures = append(pictures, &picture.Picture{
					Name:    info.Name(),
					Path:    path,
					URL:     fmt.Sprintf("%s%s", origin, path),
					ModTime: info.ModTime().Format("Mon Jan _2 15:04:05 2006"),
					Size:    info.Size(),
					Owner:   user.Username,
				})
			}
			return nil
		})

		files, _ := ioutil.ReadDir(picturePath)
		user.PicCount = len(files)
	}

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/admin/listPictures.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title     string
		CsrfToken string
		Messages  []string
		Pictures  []*picture.Picture
	}{
		Title:     "User List",
		Messages:  messages,
		CsrfToken: form.New(),
		Pictures:  pictures,
	})
	session.Save(r, w)
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

// ShowUser ...
func (c *Controller) ShowUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ShowUser", r.URL.String())
	// get session, ignore errors
	session, _ := c.cookieStore.Get(r, "user-session")

	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		fmt.Println("missing username")
		session.AddFlash("Missing username")
		session.Save(r, w)
		http.Redirect(w, r, "/admin/user", http.StatusFound)
		return
	}

	u, err := c.udb.Get(username)
	if err != nil {
		fmt.Println("couldn't get user:" + err.Error())
		// session.AddFlash("couldn't get user:" + err.Error())
		// session.Save(r, w)
		// http.Redirect(w, r, "/admin/user", http.StatusFound)
		return
	}
	if u == nil {
		fmt.Println("User not found")
		// session.AddFlash("User not found")
		// session.Save(r, w)
		// http.Redirect(w, r, "/admin/user", http.StatusFound)
		return
	}

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/admin/user.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
		User     *user.User
	}{
		Title:    username,
		Messages: user.GetMessages(session),
		User:     u,
	})
}

// DeleteUser ...
func (c *Controller) DeleteUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("DeleteUser", r.URL.String())
	// get session, ignore errors
	session, _ := c.cookieStore.Get(r, "user-session")

	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		fmt.Println("missing username")
		session.AddFlash("Missing username")
		session.Save(r, w)
		http.Redirect(w, r, "/admin/user", http.StatusFound)
		return
	}

	u, err := c.udb.Get(username)
	if err != nil {
		fmt.Println("couldn't get user:" + err.Error())
		// session.AddFlash("couldn't get user:" + err.Error())
		// session.Save(r, w)
		// http.Redirect(w, r, "/admin/user", http.StatusFound)
		return
	}
	if u == nil {
		fmt.Println("User not found")
		// session.AddFlash("User not found")
		// session.Save(r, w)
		// http.Redirect(w, r, "/admin/user", http.StatusFound)
		return
	}

	fmt.Println("TOOD: delete User", username)

}

// UpdateUser ...
func (c *Controller) UpdateUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("UpdateUser", r.URL.String())
	// get session, ignore errors
	session, _ := c.cookieStore.Get(r, "user-session")

	r.ParseForm()

	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		fmt.Println("missing username")
		session.AddFlash("Missing username")
		session.Save(r, w)
		http.Redirect(w, r, "/admin/user", http.StatusFound)
		return
	}

	u, err := c.udb.Get(username)
	if err != nil {
		fmt.Println("couldn't get user:" + err.Error())
		// session.AddFlash("couldn't get user:" + err.Error())
		// session.Save(r, w)
		// http.Redirect(w, r, "/admin/user", http.StatusFound)
		return
	}
	if u == nil {
		fmt.Println("User not found")
		// session.AddFlash("User not found")
		// session.Save(r, w)
		// http.Redirect(w, r, "/admin/user", http.StatusFound)
		return
	}

	fmt.Println("TOOD: update User", username, r.Form)
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

// // Register form
// func (c *Controller) Register(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println(r.URL.String())

// 	username := r.URL.Query().Get("username")
// 	if username == "" {
// 		w.Write([]byte("invalid username"))
// 		return
// 	}
// 	token := r.URL.Query().Get("token")
// 	if token == "" {
// 		w.Write([]byte("invalid token"))
// 		return
// 	}

// 	// parse every time to make updates easier, and save memory
// 	templates := template.Must(template.ParseFiles("templates/admin/user/invite.html", "templates/base.html"))
// 	templates.ExecuteTemplate(w, "base", &struct {
// 		Title    string
// 		Messages []string
// 		Username string
// 		Token    string
// 	}{
// 		Title:    fmt.Sprintf("Register: %s", username),
// 		Messages: getMessages(r),
// 		Username: username,
// 		Token:    token,
// 	})
// }

// // RegisterHandler on submit form
// func (c *Controller) RegisterHandler(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println(r.URL.String())

// 	// get session
// 	session, err := c.cookieStore.Get(r, "user-session")
// 	if err != nil {
// 		fmt.Println("[E]", err)
// 		session.AddFlash("Please try again.")
// 		http.Redirect(w, r, "/admin/user/invite", http.StatusFound) /// for now
// 		return
// 	}

// 	r.ParseForm()
// 	username := r.FormValue("username")

// 	// validate token
// 	// for now don't validate token, because it's not implemented
// 	validateToken := false
// 	if validateToken {
// 		dbToken, _ := c.udb.GetToken(username)
// 		formToken := r.FormValue("token")
// 		if dbToken != formToken {
// 			fmt.Println("[E]", err)
// 			session.AddFlash("Unable to register.")
// 			http.Redirect(w, r, "/admin/user/invite", http.StatusFound) /// for now
// 			return
// 		}
// 	}

// 	// verify user
// 	if username == "" {
// 		fmt.Println("Empty username")
// 		session.AddFlash("Invalid username.")
// 		http.Redirect(w, r, "/admin/user/invite", http.StatusFound) /// for now
// 		return
// 	}

// 	// Check for duplicate username
// 	user, err := c.udb.Get(username)
// 	if err != nil {
// 		fmt.Println("[E]", err)
// 		session.AddFlash("Please try again.")
// 		http.Redirect(w, r, "/admin/user/invite", http.StatusFound) /// for now
// 		return
// 	}
// 	if user != nil {
// 		fmt.Println("[E]", err)
// 		session.AddFlash("User already registered.")
// 		http.Redirect(w, r, "/user/login", http.StatusFound) /// for now
// 		return
// 	}
// 	user = &User{
// 		Username: username,
// 	}

// 	// Verify password
// 	password1 := r.FormValue("password1")
// 	password2 := r.FormValue("password2")
// 	if password1 == "" || password2 == "" || password1 != password2 {
// 		fmt.Println("Passwords don't match, or are emtpy", password1, password2)
// 		session.AddFlash("Passwords doesn't match.")
// 		http.Redirect(w, r, "/admin/user/invite", http.StatusFound) /// for now
// 		return
// 	}

// 	user.Authenticated = true
// 	user.Password = password1

// 	// Save user to db
// 	_, err = c.udb.Save(user)
// 	if err != nil {
// 		fmt.Println("[E]", err)
// 		session.AddFlash("Please try again.")
// 		http.Redirect(w, r, "/admin/user/invite", http.StatusFound) /// for now
// 		return
// 	}

// 	// Save user session
// 	session.Values["user"] = user
// 	err = session.Save(r, w)
// 	if err != nil {
// 		fmt.Println("[E]", err)
// 		session.AddFlash("Please try again.")
// 		http.Redirect(w, r, "/admin/user/invite", http.StatusFound) /// for now
// 		return
// 	}

// 	// redirect
// 	http.Redirect(w, r, fmt.Sprintf("/user/%s/picture", user.ID), http.StatusFound)
// }

// // Login form
// func (c *Controller) Login(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println(r.URL.String())

// 	// parse every time to make updates easier, and save memory
// 	templates := template.Must(template.ParseFiles("templates/user/login.html", "templates/base.html"))
// 	templates.ExecuteTemplate(w, "base", &struct {
// 		Title    string
// 		Messages []string
// 	}{
// 		Title:    "login",
// 		Messages: getMessages(r),
// 	})
// }

// // LoginHandler form submit
// func (c *Controller) LoginHandler(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println(r.URL.String())

// 	// get session
// 	session, err := c.cookieStore.Get(r, "user-session")
// 	if err != nil {
// 		fmt.Println("[E] session missing", err)
// 		session.AddFlash("Login Failed, Please try again.")
// 		http.Redirect(w, r, "/user/login", http.StatusFound) /// for now
// 		return
// 	}

// 	// already logged in
// 	u, ok := session.Values["user"].(User)
// 	if ok && u.Authenticated {
// 		http.Redirect(w, r, fmt.Sprintf("/user/%s/picture", u.ID), http.StatusFound)
// 		return
// 	}

// 	// Get user from db
// 	username := r.FormValue("username")
// 	user, err := c.udb.Get(username)
// 	if err != nil {
// 		fmt.Println("[E] failed to get user", err)
// 		session.AddFlash("Login Failed, Please try again.")
// 		http.Redirect(w, r, "/user/login", http.StatusFound) /// for now
// 		return
// 	}
// 	if user == nil {
// 		fmt.Println("[E] no user", err)
// 		session.AddFlash("Login Failed, Please try again.")
// 		http.Redirect(w, r, "/user/login", http.StatusFound) /// for now
// 		return
// 	}

// 	// Verify password
// 	password := r.FormValue("password")
// 	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
// 	if err != nil {
// 		fmt.Println("[E] password failed", err)
// 		session.AddFlash("Login Failed, Please try again.")
// 		http.Redirect(w, r, "/user/login", http.StatusFound) /// for now
// 		return
// 	}
// 	if password != string(hash) {
// 		session.AddFlash("Invalid Password")
// 		http.Error(w, "Invalid Password", http.StatusBadRequest)
// 		return
// 	}
// 	user.Authenticated = true

// 	// Save user session
// 	session.Values["user"] = user
// 	err = session.Save(r, w)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	http.Redirect(w, r, fmt.Sprintf("/user/%s/picture", user.ID), http.StatusFound)
// }

// // LogoutHandler revokes authentication for a user
// func (c *Controller) LogoutHandler(w http.ResponseWriter, r *http.Request) {
// 	session, err := c.cookieStore.Get(r, "user-session")
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	session.Values["user"] = User{}
// 	session.Options.MaxAge = -1

// 	err = session.Save(r, w)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	http.Redirect(w, r, "/", http.StatusFound)
// }

// // Forgot form submit
// func (c *Controller) Forgot(w http.ResponseWriter, r *http.Request) {
// 	fmt.Println(r.URL.String())

// 	// TODO:
// 	// validate/create session
// 	// redirect to /user/{id}/picture
// }

// // Forbidden ...
// func (c *Controller) Forbidden(w http.ResponseWriter, r *http.Request) {
// 	session, err := c.cookieStore.Get(r, "user-session")
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}

// 	flashMessages := session.Flashes()
// 	err = session.Save(r, w)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	tpl.ExecuteTemplate(w, "forbidden.gohtml", flashMessages)
// }

// func getMessages(r *http.Request) (messages []string) {
// 	messages = []string{}

// 	// get session
// 	session, err := c.cookieStore.Get(r, "user-session")
// 	if err != nil {
// 		return
// 	} else if flashes := session.Flashes(); len(flashes) > 0 {
// 		messages = make([]string, len(flashes))
// 		for i, f := range flashes {
// 			messages[i] = f.(string)
// 		}
// 	}
// 	return
// }
