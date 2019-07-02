package user

import (
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/jaredwarren/rpi_pic/app"
	"github.com/jaredwarren/rpi_pic/form"
	"github.com/jaredwarren/rpi_pic/picture"
	"golang.org/x/crypto/bcrypt"
)

// Controller implements the home resource.
type Controller struct {
	udb         *Store
	cookieStore *sessions.CookieStore
	service     *app.Service
}

// NewUserController creates a home controller.
func NewUserController(service *app.Service, udb *Store, cookieStore *sessions.CookieStore) *Controller {
	return &Controller{
		udb:         udb,
		service:     service,
		cookieStore: cookieStore,
	}
}

// MountUserController "mounts" a Home resource controller on the given service.
func MountUserController(service *app.Service, ctrl *Controller) {
	// user register form
	service.Mux.HandleFunc("/register", ctrl.Register).Methods("GET")
	service.Mux.HandleFunc("/register", CsrfForm(ctrl.RegisterHandler)).Methods("POST")

	// user login form
	service.Mux.HandleFunc("/login", ctrl.Login).Methods("GET")
	service.Mux.HandleFunc("/login", CsrfForm(ctrl.LoginHandler)).Methods("POST")
	service.Mux.HandleFunc("/logout", ctrl.LogoutHandler).Methods("GET")

	// forgot password
	service.Mux.HandleFunc("/forgot", ctrl.Forgot).Methods("GET")

	// other
	service.Mux.HandleFunc("/forbidden", ctrl.Forbidden).Methods("GET")

	// my pictures
	service.Mux.HandleFunc("/pictures", ctrl.LoggedIn(ctrl.ListPictures)).Methods("GET")
	service.Mux.HandleFunc("/my/pictures", ctrl.LoggedIn(ctrl.ListPictures)).Methods("GET")
	service.Mux.HandleFunc("/my/pictures/upload", ctrl.LoggedIn(ctrl.UploadPicture)).Methods("GET")
	service.Mux.HandleFunc("/my/pictures/upload", CsrfForm(ctrl.LoggedIn(ctrl.UploadPictureHandler))).Methods("POST")
	service.Mux.HandleFunc("/my/pictures/delete", CsrfForm(ctrl.LoggedIn(ctrl.DeletePicture))).Methods("GET")
	service.Mux.HandleFunc("/pictures/{username}/{file}", ctrl.LoggedIn(ctrl.ServePicture)).Methods("GET")

	// pictures
	service.Mux.HandleFunc("/picture", ctrl.LoggedIn(ctrl.Current)).Methods("GET")
	service.Mux.HandleFunc("/picture/current", ctrl.LoggedIn(ctrl.Current)).Methods("GET")
}

// CsrfToken returns token
func CsrfToken() string {
	return form.New()
}

// GetHash returns random string
func GetHash() string {
	return form.GetHash(32)
}

// Current ...
func (c *Controller) Current(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Current:", r.URL.String())

	// picture url base
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = fmt.Sprintf("http://%s/", r.Host)
	}

	// find file, or default
	filename := c.service.CurrentPicture.Path
	info, err := os.Stat(filename)
	if os.IsNotExist(err) || info.IsDir() {
		filename = "pictures/default.png"
	}

	fmt.Println("  current:", filename)

	w.Header().Set("Cache-Control", "no-cache, private, max-age=0")
	w.Header().Set("Pragma", "no-cache")

	http.ServeFile(w, r, filename)
}

// DeletePicture ...
func (c *Controller) DeletePicture(w http.ResponseWriter, r *http.Request) {
	fmt.Println("DeletePicture:", r.URL.String())

	// get user session
	session, _ := c.cookieStore.Get(r, "user-session")
	username, _ := session.Values["user"].(string)
	if username == "" {
		session.AddFlash("redirect", "/my/pictures")
		session.AddFlash("Please Login.")
		session.Save(r, w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	r.ParseForm()
	file := r.FormValue("file")
	if file == "" {
		session.AddFlash("Access Denied.")
		session.Save(r, w)
		http.Redirect(w, r, "/my/pictures", http.StatusNotFound)
		return
	}

	// make sure user owns file
	if !strings.Contains(file, username) {
		session.AddFlash("Access Denied.")
		session.Save(r, w)
		http.Redirect(w, r, "/forbidden", http.StatusNotFound)
		return
	}

	// delete the file
	err := os.Remove(file)
	if err != nil {
		session.AddFlash("Cannot delete file")
		session.Save(r, w)
		http.Redirect(w, r, "/my/pictures", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/my/pictures", http.StatusFound)
}

// ServePicture ...
func (c *Controller) ServePicture(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ServePicture:", r.URL.String())

	// get session
	session, _ := c.cookieStore.Get(r, "user-session")

	currentUser, err := GetCurrentUser(r, session, c.udb)
	if err != nil {
		session.AddFlash("Username not found, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// picture access
	if !currentUser.Admin && !currentUser.Root {
		// get path username
		vars := mux.Vars(r)
		username, _ := vars["username"]
		if username == "" {
			session.AddFlash("Access Denied.")
			session.Save(r, w)
			http.Redirect(w, r, "/forbidden", http.StatusNotFound)
			return
		}

		// make sure user has access to image
		if currentUser.Username != username {
			session.AddFlash("Access Denied.")
			session.Save(r, w)
			http.Redirect(w, r, "/forbidden", http.StatusNotFound)
			return
		}
	}

	// find file, or default
	filename := "." + r.URL.String()
	info, err := os.Stat(filename)
	if os.IsNotExist(err) || info.IsDir() {
		filename = "pictures/broken.png"
	}
	fmt.Println("  sp:", filename)

	http.ServeFile(w, r, filename)
}

// ListPictures ...
func (c *Controller) ListPictures(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ListPictures:", r.URL.String())

	// get user session
	session, _ := c.cookieStore.Get(r, "user-session")
	currentUser, err := GetCurrentUser(r, session, c.udb)
	if err != nil {
		session.AddFlash("Username not found, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// init user picture path
	picturePath := fmt.Sprintf("pictures/%s", filepath.Clean(currentUser.Username))
	os.MkdirAll(picturePath, os.ModePerm)

	// picture url base
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = fmt.Sprintf("http://%s/", r.Host)
	}

	// get lis of all user photos
	pictures := []*picture.Picture{}
	filepath.Walk(picturePath, func(path string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			pictures = append(pictures, &picture.Picture{
				Name:    info.Name(),
				Path:    path,
				URL:     fmt.Sprintf("%s%s", origin, path),
				ModTime: info.ModTime().Format("Mon Jan _2 15:04:05 2006"),
				Size:    info.Size(),
			})
		}
		return nil
	})

	home := ""
	if currentUser.Admin {
		home = "/admin"
	} else if currentUser.Root {
		home = "/root"
	}

	// parse every time to make updates easier, and save memory
	tpl := template.Must(template.New("base").Funcs(template.FuncMap{"CsrfToken": CsrfToken, "GetHash": GetHash}).ParseFiles("templates/user/pictures.html", "templates/base.html"))
	tpl.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
		Username string
		Home     string
		Pictures []*picture.Picture
	}{
		Title:    "My Photo",
		Messages: GetMessages(session),
		Username: currentUser.Username,
		Pictures: pictures,
		Home:     home,
	})
	session.Save(r, w)
}

// UploadPicture ...
func (c *Controller) UploadPicture(w http.ResponseWriter, r *http.Request) {
	fmt.Println("UploadPicture:", r.URL.String())

	// get user session
	session, _ := c.cookieStore.Get(r, "user-session")
	username, _ := session.Values["user"].(string)
	if username == "" {
		session.AddFlash("redirect", "/my/pictures/upload")
		session.AddFlash("Please Login.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/login"), http.StatusFound)
		return
	}

	// parse every time to make updates easier, and save memory
	tpl := template.Must(template.New("base").Funcs(template.FuncMap{"CsrfToken": CsrfToken}).ParseFiles("templates/user/upload.html", "templates/base.html"))
	tpl.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
		Username string
	}{
		Title:    "Upload Photo",
		Messages: GetMessages(session),
		Username: username,
	})
	session.Save(r, w)
}

// UploadPictureHandler ...
func (c *Controller) UploadPictureHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("UploadPictureHandler:", r.URL.String())

	// get session
	session, _ := c.cookieStore.Get(r, "user-session")

	currentUser, err := GetCurrentUser(r, session, c.udb)
	if err != nil {
		session.AddFlash("Username not found, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// 32 MB files max.
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	if err := r.ParseMultipartForm(32 << 20); err != nil {
		http.Error(w, "file too big", http.StatusBadRequest)
		return
	}

	// make sure user pic dir exists
	picturePath := fmt.Sprintf("pictures/%s", filepath.Clean(currentUser.Username))
	os.MkdirAll(picturePath, os.ModePerm)

	// process each file
	m := r.MultipartForm
	if m == nil {
		session.AddFlash("form data error")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/my/pictures/upload"), http.StatusFound)
		return
	}
	for _, fileHeader := range m.File["picture[]"] {
		// get pictures
		file, err := fileHeader.Open()
		if err != nil {
			session.AddFlash("Invalid file:" + fileHeader.Filename)
			continue
		}
		defer file.Close()

		fileBytes, err := ioutil.ReadAll(file)
		if err != nil {
			session.AddFlash("Invalid file:" + fileHeader.Filename)
			continue
		}

		// check file type, detectcontenttype only needs the first 512 bytes
		filetype := http.DetectContentType(fileBytes)
		switch filetype {
		case "image/jpeg", "image/jpg":
		case "image/gif", "image/png":
			break
		// TODO: allow videos?????
		default:
			session.AddFlash("Invalid file Type:" + fileHeader.Filename)
			continue
		}

		// clean file name
		cleanFileName := filepath.Clean(fileHeader.Filename)
		fullPath := filepath.Join(picturePath, cleanFileName)

		// write file
		newFile, err := os.Create(fullPath)
		if err != nil {
			session.AddFlash("Can't write file:" + fileHeader.Filename)
			continue
		}
		defer newFile.Close()
		if _, err := newFile.Write(fileBytes); err != nil || newFile.Close() != nil {
			session.AddFlash("Can't write file:" + fileHeader.Filename)
			continue
		}
	}
	session.Save(r, w)

	// redirect back to picture list
	http.Redirect(w, r, "/my/pictures", http.StatusFound)
}

// Register form
func (c *Controller) Register(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Register:", r.URL.String())

	// get new session
	session, _ := c.cookieStore.Get(r, "user-session")

	username := r.URL.Query().Get("username")
	if username == "" {
		session.AddFlash("Invalid username.")
		session.Save(r, w)
		http.Redirect(w, r, "/forbidden", http.StatusFound)
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		session.AddFlash("Invalid token.")
		session.Save(r, w)
		http.Redirect(w, r, "/forbidden", http.StatusFound)
		return
	}

	// validate token
	user, err := c.udb.Get(username)
	if user == nil || err != nil {
		session.AddFlash("Not Invited.")
		session.Save(r, w)
		http.Redirect(w, r, "/forbidden", http.StatusFound)
		return
	}
	if user.Token == "" {
		session.AddFlash("Not invited.")
		session.Save(r, w)
		http.Redirect(w, r, "/forbidden", http.StatusFound)
		return
	}

	// parse every time to make updates easier, and save memory
	tpl := template.Must(template.New("base").Funcs(template.FuncMap{"CsrfToken": CsrfToken}).ParseFiles("templates/user/register.html", "templates/base.html"))
	tpl.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
		Username string
		Token    string
	}{
		Title:    fmt.Sprintf("Register: %s", username),
		Messages: GetMessages(session),
		Username: username,
		Token:    token,
	})
	session.Save(r, w)
}

// RegisterHandler on submit form
func (c *Controller) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("RegisterHandler:", r.URL.String())

	r.ParseForm()

	// get session
	session, _ := c.cookieStore.Get(r, "user-session")

	// verify user
	username := r.FormValue("username")
	if username == "" {
		session.AddFlash("Invalid username.")
		session.Save(r, w)
		http.Redirect(w, r, "/forbidden", http.StatusFound)
		return
	}

	// get user from db
	user, err := c.udb.Get(username)
	if err != nil {
		fmt.Println("[E] get user err", err)
		session.AddFlash("Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, "/forbidden", http.StatusFound)
		return
	}
	if user == nil {
		fmt.Println("[E] no user")
		session.AddFlash("Unable to set password")
		session.Save(r, w)
		http.Redirect(w, r, "/forbidden", http.StatusFound)
		return
	}

	// check if user is already registered and is not resetting password
	if user.Password != "" && user.Token == "" {
		fmt.Printf("[E] user found, %s, %+v\n", err, user)
		session.AddFlash("User already registered.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/login?username=%s", username), http.StatusFound)
		return
	}

	// check register token
	formToken := r.FormValue("token")
	if user.Token != formToken {
		fmt.Println("[E] no token", user.Token, formToken)
		session.AddFlash("Unable to register.")
		session.Save(r, w)
		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	// Verify password
	password1 := r.FormValue("password1")
	password2 := r.FormValue("password2")
	if password1 == "" || password2 == "" || password1 != password2 {
		fmt.Println("Passwords don't match, or are emtpy", password1, password2)
		session.AddFlash("Passwords doesn't match.")
		session.Save(r, w)
		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	// hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password1), bcrypt.MinCost)
	if err != nil {
		fmt.Println("failed to hash", err)
		session.AddFlash("Invalid Password.")
		session.Save(r, w)
		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}
	user.Password = string(hash)

	// delete register token
	user.Token = ""

	// Save user to db
	err = c.udb.Save(user)
	if err != nil {
		fmt.Println("[E] db save error", err)
		session.AddFlash("Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, "/register", http.StatusFound)
		return
	}

	// Save user session
	session.Values["user"] = user.Username
	err = session.Save(r, w)
	if err != nil {
		fmt.Println("[E] session save error", err)
		http.Redirect(w, r, fmt.Sprintf("/login?username=%s", username), http.StatusFound)
		return
	}

	// redirect
	http.Redirect(w, r, "/my/pictures", http.StatusFound)
}

// Login form
func (c *Controller) Login(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Login:", r.URL.String())
	session, _ := c.cookieStore.Get(r, "user-session")

	r.ParseForm()
	username := r.FormValue("username")

	// parse every time to make updates easier, and save memory
	tpl := template.Must(template.New("base").Funcs(template.FuncMap{"CsrfToken": CsrfToken}).ParseFiles("templates/user/login.html", "templates/base.html"))
	tpl.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
		Username string
	}{
		Title:    "login",
		Messages: GetMessages(session),
		Username: username,
	})
	session.Save(r, w)
}

// LoginHandler form submit
func (c *Controller) LoginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LoginHandler:", r.URL.String())

	// get session
	session, _ := c.cookieStore.Get(r, "user-session")

	r.ParseForm()
	username := r.FormValue("username")
	if username == "" {
		session.AddFlash("Login Failed, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/login?username=%s", username), http.StatusFound)
		return
	}

	// already logged in
	sessionUsername, _ := session.Values["user"].(string)
	if sessionUsername != "" && sessionUsername == username {
		http.Redirect(w, r, "/my/pictures", http.StatusFound)
		return
	}

	// Get user from db
	user, err := c.udb.Get(username)
	if err != nil {
		session.AddFlash("Login Failed, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/login?username=%s", username), http.StatusFound)
		return
	}
	if user == nil {
		session.AddFlash("Login Failed, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/login?username=%s", username), http.StatusFound)
		return
	}

	// Verify password
	password := r.FormValue("password")
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		session.AddFlash("Invalid Password")
		session.Save(r, w)
		http.Error(w, "Invalid Password", http.StatusBadRequest)
		return
	}

	// Save user session
	session.Values["user"] = user.Username
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// get redirects if any
	redirectURL := "/pictures"
	if user.Root {
		redirectURL = "/root"
	} else if user.Admin {
		redirectURL = "/admin"
	}
	flashes := session.Flashes("redirect")
	for _, f := range flashes {
		redirectURL = f.(string)
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// LogoutHandler revokes authentication for a user
func (c *Controller) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LogoutHandler:", r.URL.String())

	session, _ := c.cookieStore.Get(r, "user-session")
	session.Values["user"] = ""
	session.Options.MaxAge = -1

	err := session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// Forgot form submit
func (c *Controller) Forgot(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Forgot:", r.URL.String())
	r.ParseForm()

	// get session
	session, _ := c.cookieStore.Get(r, "user-session")

	username := r.FormValue("username")
	if username == "" {
		session.AddFlash("Username not found, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Get user from db
	user, err := c.udb.Get(username)
	if err != nil {
		session.AddFlash("Username not found, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/login?username=%s", username), http.StatusFound)
		return
	}

	// for now just use the same "password"
	hash, err := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	if err != nil {
		fmt.Println("[E] token gen error", err)
		session.AddFlash("Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/login?username=%s", username), http.StatusFound)
		return
	}
	user.Token = string(hash)

	// save user with token
	err = c.udb.Save(user)
	if err != nil {
		fmt.Println("[E] user save error", err)
		session.AddFlash("Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/login?username=%s", username), http.StatusFound)
		return
	}

	session.Save(r, w)
	http.Redirect(w, r, fmt.Sprintf("/register?username=%s&token=%s", user.Username, user.Token), http.StatusFound) /// TODO: add query
}

// Forbidden ...
func (c *Controller) Forbidden(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Forbidden:", r.URL.String())

	session, _ := c.cookieStore.Get(r, "user-session")

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/user/forbidden.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
	}{
		Title:    "Error",
		Messages: GetMessages(session),
	})
	session.Save(r, w)
}

// GetMessages returns list of flash messages, be sure to call Save(w, r), or flash messages will not be removed
func GetMessages(session *sessions.Session) (messages []string) {
	messages = []string{}
	if flashes := session.Flashes(); len(flashes) > 0 {
		messages = make([]string, len(flashes))
		for i, f := range flashes {
			messages[i] = f.(string)
		}
	}
	return
}

// GetCurrentUser ...
func GetCurrentUser(r *http.Request, session *sessions.Session, udb *Store) (*User, error) {
	fmt.Println("GetCurrentUser:", r.URL.String())

	// not logged in
	username, _ := session.Values["user"].(string)
	if username == "" {
		return nil, errors.New("user session missing")
	}

	// get user from db
	user, err := udb.Get(username)
	if err != nil {
		return nil, err
	}
	return user, nil
}
