package user

import (
	"encoding/gob"
	"fmt"
	"html/template"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/jaredwarren/rpi_pic/app"
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
	service.Mux.HandleFunc("/user/register", ctrl.RegisterHandler).Methods("POST")

	// user login form
	service.Mux.HandleFunc("/user/login", ctrl.Login).Methods("GET")
	// submit user login
	service.Mux.HandleFunc("/user/login", ctrl.LoginHandler).Methods("POST")

	service.Mux.HandleFunc("/user/logout", ctrl.LogoutHandler).Methods("GET")

	// forgot password
	service.Mux.HandleFunc("/user/forgot", ctrl.Forgot).Methods("GET")
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

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/user/register.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
		Username string
		Token    string
	}{
		Title:    fmt.Sprintf("Register: %s", username),
		Messages: getMessages(r),
		Username: username,
		Token:    token,
	})
}

// RegisterHandler on submit form
func (c *Controller) RegisterHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	// get session
	session, err := store.Get(r, "user-session")
	if err != nil {
		fmt.Println("[E] no session", err)
		session.AddFlash("Please try again.")
		http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
		return
	}

	r.ParseForm()
	username := r.FormValue("username")

	// validate token
	// for now don't validate token, because it's not implemented
	validateToken := false
	if validateToken {
		dbToken, _ := c.udb.GetToken(username)
		formToken := r.FormValue("token")
		if dbToken != formToken {
			fmt.Println("[E] no token", err)
			session.AddFlash("Unable to register.")
			http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
			return
		}
	}

	// verify user
	if username == "" {
		fmt.Println("Empty username")
		session.AddFlash("Invalid username.")
		http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
		return
	}

	// Check for duplicate username
	user, err := c.udb.Find("username", username)
	if err != nil {
		fmt.Println("[E] no user", err)
		session.AddFlash("Please try again.")
		http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
		return
	}
	if user != nil {
		fmt.Printf("[E] user found, %s, %+v\n", err, user)
		session.AddFlash("User already registered.")
		http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound) /// for now
		return
	}
	user = &User{
		Username: username,
	}

	// Verify password
	password1 := r.FormValue("password1")
	password2 := r.FormValue("password2")
	if password1 == "" || password2 == "" || password1 != password2 {
		fmt.Println("Passwords don't match, or are emtpy", password1, password2)
		session.AddFlash("Passwords doesn't match.")
		http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password1), bcrypt.MinCost)
	if err != nil {
		fmt.Println("failed to hash", err)
		session.AddFlash("Invalid Password.")
		http.Redirect(w, r, "/user/register", http.StatusFound)
		return
	}
	user.Authenticated = true
	user.Password = string(hash)

	// Save user to db
	_, err = c.udb.Save(user)
	if err != nil {
		fmt.Println("[E] db save error", err)
		session.AddFlash("Please try again.")
		http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
		return
	}

	// Save user session
	session.Values["user"] = user
	err = session.Save(r, w)
	if err != nil {
		fmt.Println("[E] session save error", err)
		session.AddFlash("Please try again.")
		http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
		return
	}

	// redirect
	http.Redirect(w, r, fmt.Sprintf("/user/%s/picture", user.ID), http.StatusFound)
}

// Login form
func (c *Controller) Login(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/user/login.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
	}{
		Title:    "login",
		Messages: getMessages(r),
	})
}

// LoginHandler form submit
func (c *Controller) LoginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	// get session
	session, err := store.Get(r, "user-session")
	if err != nil {
		fmt.Println("[E] session missing", err)
		session.AddFlash("Login Failed, Please try again.")
		http.Redirect(w, r, "/user/login", http.StatusFound) /// for now
		return
	}

	// already logged in
	u, ok := session.Values["user"].(User)
	if ok && u.Authenticated {
		http.Redirect(w, r, fmt.Sprintf("/user/%s/picture", u.ID), http.StatusFound)
		return
	}

	// Get user from db
	username := r.FormValue("username")
	user, err := c.udb.Find("username", username)
	if err != nil {
		fmt.Println("[E] failed to get user", err)
		session.AddFlash("Login Failed, Please try again.")
		http.Redirect(w, r, "/user/login", http.StatusFound) /// for now
		return
	}
	if user == nil {
		fmt.Println("[E] no user", err)
		session.AddFlash("Login Failed, Please try again.")
		http.Redirect(w, r, "/user/login", http.StatusFound) /// for now
		return
	}

	// Verify password
	password := r.FormValue("password")
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		fmt.Println("Invalid Password:", password, err)
		session.AddFlash("Invalid Password")
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

	// TODO:
	// validate/create session
	// redirect to /user/{id}/picture
}

// Forbidden ...
func (c *Controller) Forbidden(w http.ResponseWriter, r *http.Request) {
	session, err := store.Get(r, "user-session")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	flashMessages := session.Flashes()
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tpl.ExecuteTemplate(w, "forbidden.gohtml", flashMessages)
}

func getMessages(r *http.Request) (messages []string) {
	messages = []string{}

	// get session
	session, err := store.Get(r, "user-session")
	if err != nil {
		return
	} else if flashes := session.Flashes(); len(flashes) > 0 {
		messages = make([]string, len(flashes))
		for i, f := range flashes {
			messages[i] = f.(string)
		}
	}
	return
}
