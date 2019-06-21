package admin

import (
	"fmt"
	"net/http"

	"github.com/jaredwarren/rpi_pic/app"
	"github.com/jaredwarren/rpi_pic/user"
)

// Controller implements the home resource.
type Controller struct {
	udb *user.Store
}

// NewAdminController creates a home controller.
func NewAdminController(service *app.Service, udb *user.Store) *Controller {
	return &Controller{
		udb: udb,
	}
}

// MountAdminController "mounts" a Home resource controller on the given service.
func MountAdminController(service *app.Service, ctrl *Controller) {
	// admin list users
	service.Mux.HandleFunc("/admin/user", admin(ctrl.ListUsers)).Methods("GET")
	// admin user update
	service.Mux.HandleFunc("/admin/user/{id}", admin(ctrl.TODO)).Methods("POST")
	// admin delete user
	service.Mux.HandleFunc("/admin/user/{id}", admin(ctrl.TODO)).Methods("DELETE")
	// invite user to register
	service.Mux.HandleFunc("/admin/user/invite", admin(ctrl.TODO)).Methods("GET")

	// ## Picture management
	// picture list
	service.Mux.HandleFunc("/admin/picture", admin(ctrl.TODO)).Methods("GET")
	// picture show in browser
	service.Mux.HandleFunc("/admin/picture/{id}", admin(ctrl.TODO)).Methods("GET")
	// display picture on device
	service.Mux.HandleFunc("/admin/picture/{id}/display", admin(ctrl.TODO)).Methods("GET")
	// picture delete
	service.Mux.HandleFunc("/admin/picture/{id}", admin(ctrl.TODO)).Methods("DELETE")

	// list picture tags
	service.Mux.HandleFunc("/admin/picture/{id}/tag", admin(ctrl.TODO)).Methods("GET")
	// tag picture
	service.Mux.HandleFunc("/admin/picture/{pid}/tag/{tid}", admin(ctrl.TODO)).Methods("POST")
	// delete picture tag
	service.Mux.HandleFunc("/admin/picture/{pid}/tag/{tid}", admin(ctrl.TODO)).Methods("DELETE")
	// list pictures with tag
	service.Mux.HandleFunc("/admin/tag/{id}/picture", admin(ctrl.TODO)).Methods("GET")

	// show settings
	service.Mux.HandleFunc("/admin/settings", admin(ctrl.TODO)).Methods("GET")
	// update settings
	service.Mux.HandleFunc("/admin/settings", admin(ctrl.TODO)).Methods("POST")
}

// TODO ...
func (c *Controller) TODO(w http.ResponseWriter, r *http.Request) {
	msg := "TODO..." + r.URL.String()
	fmt.Println(msg)
	w.Write([]byte(msg))
}

// ListUsers ...
func (c *Controller) ListUsers(w http.ResponseWriter, r *http.Request) {
	// Check for duplicate username
	users, err := c.udb.FetchAll()
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, user := range users {
		fmt.Printf("%+v\n", user)
	}
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
// 	templates := template.Must(template.ParseFiles("templates/user/register.html", "templates/base.html"))
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
// 	session, err := store.Get(r, "user-session")
// 	if err != nil {
// 		fmt.Println("[E]", err)
// 		session.AddFlash("Please try again.")
// 		http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
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
// 			http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
// 			return
// 		}
// 	}

// 	// verify user
// 	if username == "" {
// 		fmt.Println("Empty username")
// 		session.AddFlash("Invalid username.")
// 		http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
// 		return
// 	}

// 	// Check for duplicate username
// 	user, err := c.udb.Get(username)
// 	if err != nil {
// 		fmt.Println("[E]", err)
// 		session.AddFlash("Please try again.")
// 		http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
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
// 		http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
// 		return
// 	}

// 	user.Authenticated = true
// 	user.Password = password1

// 	// Save user to db
// 	_, err = c.udb.Save(user)
// 	if err != nil {
// 		fmt.Println("[E]", err)
// 		session.AddFlash("Please try again.")
// 		http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
// 		return
// 	}

// 	// Save user session
// 	session.Values["user"] = user
// 	err = session.Save(r, w)
// 	if err != nil {
// 		fmt.Println("[E]", err)
// 		session.AddFlash("Please try again.")
// 		http.Redirect(w, r, "/user/register", http.StatusFound) /// for now
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
// 	session, err := store.Get(r, "user-session")
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
// 	session, err := store.Get(r, "user-session")
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
// 	session, err := store.Get(r, "user-session")
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
// 	session, err := store.Get(r, "user-session")
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
