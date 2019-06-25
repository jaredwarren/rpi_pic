package user

import (
	"encoding/gob"
	"fmt"
	"html/template"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/jaredwarren/rpi_pic/app"
	"github.com/jaredwarren/rpi_pic/form"
	"golang.org/x/crypto/bcrypt"
)

// store will hold all session data
var store *sessions.CookieStore

// tpl holds all parsed templates
var tpl *template.Template

func init() {
	authKeyOne := securecookie.GenerateRandomKey(64)
	encryptionKeyOne := securecookie.GenerateRandomKey(32)

	store = sessions.NewCookieStore(
		authKeyOne,
		encryptionKeyOne,
	)

	store.Options = &sessions.Options{
		MaxAge:   60 * 15,
		HttpOnly: true,
	}

	gob.Register(User{})
}

// Controller implements the home resource.
type Controller struct {
	udb *Store
}

// NewUserController creates a home controller.
func NewUserController(service *app.Service, udb *Store) *Controller {
	return &Controller{
		udb: udb,
	}
}

// MountUserController "mounts" a Home resource controller on the given service.
func MountUserController(service *app.Service, ctrl *Controller) {
	// user register form
	service.Mux.HandleFunc("/user/register", ctrl.Register).Methods("GET")
	// submit user register form
	service.Mux.HandleFunc("/user/register", CsrfForm(ctrl.RegisterHandler)).Methods("POST")

	// user login form
	service.Mux.HandleFunc("/user/login", ctrl.Login).Methods("GET")
	// submit user login
	service.Mux.HandleFunc("/user/login", CsrfForm(ctrl.LoginHandler)).Methods("POST")

	service.Mux.HandleFunc("/user/logout", ctrl.LogoutHandler).Methods("GET")

	// forgot password
	service.Mux.HandleFunc("/user/forgot", ctrl.Forgot).Methods("GET")

	service.Mux.HandleFunc("/user/forbidden", ctrl.Forbidden).Methods("GET")
}

// TODO ...
func TODO(w http.ResponseWriter, r *http.Request) {
	msg := "TODO..." + r.URL.String()
	fmt.Println(msg)
	w.Write([]byte(msg))
}

// Register form
func (c *Controller) Register(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	username := r.URL.Query().Get("username")
	if username == "" {
		w.Write([]byte("invalid username"))
		return
	}

	token := r.URL.Query().Get("token")
	if token == "" {
		w.Write([]byte("invalid token"))
		return
	}

	session, _ := store.Get(r, "user-session")

	// validate token
	dbToken := c.udb.GetToken(username)
	if dbToken == "" {
		fmt.Println("[E] no user token")
		session.AddFlash("Not invited.")
		session.Save(r, w)
		http.Redirect(w, r, "/user/forbidden", http.StatusFound)
		return
	}

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/user/register.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title     string
		Messages  []string
		Username  string
		Token     string
		CsrfToken string
	}{
		Title:     fmt.Sprintf("Register: %s", username),
		Messages:  GetMessages(w, r),
		Username:  username,
		Token:     token,
		CsrfToken: form.New(),
	})
}

// RegisterHandler on submit form
func (c *Controller) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	r.ParseForm()

	// get session
	session, _ := store.Get(r, "user-session")

	// verify user
	username := r.FormValue("username")
	if username == "" {
		fmt.Println("Empty username")
		session.AddFlash("Invalid username.")
		session.Save(r, w)
		http.Redirect(w, r, "/user/register", http.StatusFound) /// TODO: add query
		return
	}

	// get user from db
	user, err := c.udb.Get(username)
	if err != nil {
		fmt.Println("[E] get user err", err)
		session.AddFlash("Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, "/user/register", http.StatusFound) /// TODO: add query
		return
	}
	if user == nil {
		fmt.Println("[E] no user")
		session.AddFlash("Unable to set password")
		session.Save(r, w)
		http.Redirect(w, r, "/user/register", http.StatusFound) /// TODO: add query
		return
	}

	// check if user is already registered and is not resetting password
	if user.Password != "" && user.Token == "" {
		fmt.Printf("[E] user found, %s, %+v\n", err, user)
		session.AddFlash("User already registered.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound) /// TODO: add query
		return
	}

	// check register token
	formToken := r.FormValue("token")
	if user.Token != formToken {
		fmt.Println("[E] no token", user.Token, formToken)
		session.AddFlash("Unable to register.")
		session.Save(r, w)
		http.Redirect(w, r, "/user/register", http.StatusFound) /// TODO: add query
		return
	}

	// Verify password
	password1 := r.FormValue("password1")
	password2 := r.FormValue("password2")
	if password1 == "" || password2 == "" || password1 != password2 {
		fmt.Println("Passwords don't match, or are emtpy", password1, password2)
		session.AddFlash("Passwords doesn't match.")
		session.Save(r, w)
		http.Redirect(w, r, "/user/register", http.StatusFound) /// TODO: add query
		return
	}

	// hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password1), bcrypt.MinCost)
	if err != nil {
		fmt.Println("failed to hash", err)
		session.AddFlash("Invalid Password.")
		session.Save(r, w)
		http.Redirect(w, r, "/user/register", http.StatusFound)
		return
	}
	user.Authenticated = true
	user.Password = string(hash)

	// delete register token
	user.Token = ""

	// Save user to db
	err = c.udb.Save(user)
	if err != nil {
		fmt.Println("[E] db save error", err)
		session.AddFlash("Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, "/user/register", http.StatusFound) /// TODO: add query
		return
	}

	// Save user session
	session.Values["user"] = user
	err = session.Save(r, w)
	if err != nil {
		fmt.Println("[E] session save error", err)
		http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound)
		return
	}

	// redirect
	http.Redirect(w, r, fmt.Sprintf("/user/%s/picture", user.ID), http.StatusFound)
}

// Login form
func (c *Controller) Login(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	r.ParseForm()
	username := r.FormValue("username")

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/user/login.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
		Token    string
		Username string
	}{
		Title:    "login",
		Messages: GetMessages(w, r),
		Token:    form.New(),
		Username: username,
	})
}

// LoginHandler form submit
func (c *Controller) LoginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	r.ParseForm()
	username := r.FormValue("username")

	// get session
	session, err := store.Get(r, "user-session")
	if err != nil {
		// not sure if error is important here...
		// fmt.Println("[E] session missing", err)
		// session.AddFlash("Login Failed, Please try again.")
		// session.Save(r, w)
		// http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound) /// TODO: add query
		// return
	}

	// already logged in
	u, ok := session.Values["user"].(User)
	if ok && u.Authenticated {
		http.Redirect(w, r, fmt.Sprintf("/user/%s/picture", u.ID), http.StatusFound)
		return
	}

	// Get user from db
	user, err := c.udb.Get(username)
	if err != nil {
		fmt.Println("[E] failed to get user", err)
		session.AddFlash("Login Failed, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound)
		return
	}
	if user == nil {
		fmt.Println("[E] no user")
		session.AddFlash("Login Failed, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound)
		return
	}

	// Verify password
	password := r.FormValue("password")
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		fmt.Println("Invalid Password:", password, err)
		session.AddFlash("Invalid Password")
		session.Save(r, w)
		http.Error(w, "Invalid Password", http.StatusBadRequest)
		return
	}
	user.Authenticated = true

	// Save user session
	session.Values["user"] = user
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/user/%s/picture", user.ID), http.StatusFound)
}

// LogoutHandler revokes authentication for a user
func (c *Controller) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "user-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	session.Values["user"] = nil
	session.Options.MaxAge = -1

	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusFound)
}

// Forgot form submit
func (c *Controller) Forgot(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	r.ParseForm()
	username := r.FormValue("username")

	// get session
	session, err := store.Get(r, "user-session")
	if err != nil {
		fmt.Println("[E] session missing", err)
		session.AddFlash("Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound)
		return
	}

	// already logged in
	u, ok := session.Values["user"].(User)
	if ok && u.Authenticated {
		http.Redirect(w, r, fmt.Sprintf("/user/%s/picture", u.ID), http.StatusFound)
		return
	}

	// Get user from db
	user, err := c.udb.Get(username)
	if err != nil {
		fmt.Println("[E] failed to get user", err)
		session.AddFlash("Username not found, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound)
		return
	}
	if user == nil {
		fmt.Println("[E] no user", err)
		session.AddFlash("Username not found, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound)
		return
	}

	// for now just use the same "password"
	hash, err := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	if err != nil {
		fmt.Println("[E] token gen error", err)
		session.AddFlash("Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound)
		return
	}
	user.Token = string(hash)

	// save user with token
	err = c.udb.Save(user)
	if err != nil {
		fmt.Println("[E] user save error", err)
		session.AddFlash("Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/user/register?username=%s&token=%s", user.Username, user.Token), http.StatusFound) /// TODO: add query
}

// Forbidden ...
func (c *Controller) Forbidden(w http.ResponseWriter, r *http.Request) {
	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/user/forbidden.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
	}{
		Title:    "login",
		Messages: GetMessages(w, r),
	})
	session, _ := store.Get(r, "user-session")
	session.Save(r, w)
}

// GetMessages returns list of flash messages
func GetMessages(w http.ResponseWriter, r *http.Request) (messages []string) {
	messages = []string{}

	// get session
	session, err := store.Get(r, "user-session")
	if err != nil {
		// if error assume no messages
		return
	} else if flashes := session.Flashes(); len(flashes) > 0 {
		messages = make([]string, len(flashes))
		for i, f := range flashes {
			messages[i] = f.(string)
		}
	}
	session.Save(r, w)
	return
}
