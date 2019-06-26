package admin

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"text/template"

	"github.com/jaredwarren/rpi_pic/form"
	"golang.org/x/crypto/bcrypt"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/jaredwarren/rpi_pic/app"
	"github.com/jaredwarren/rpi_pic/user"
	"gopkg.in/gomail.v2"
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

	gob.Register(user.User{})
}

// Controller implements the home resource.
type Controller struct {
	udb     *user.Store
	service *app.Service
}

// NewAdminController creates a home controller.
func NewAdminController(service *app.Service, udb *user.Store) *Controller {
	return &Controller{
		udb:     udb,
		service: service,
	}
}

// MountAdminController "mounts" a Home resource controller on the given service.
func MountAdminController(service *app.Service, ctrl *Controller) {
	service.Mux.HandleFunc("/admin/login", ctrl.Login).Methods("GET")
	service.Mux.HandleFunc("/admin/login", ctrl.LoginHandler).Methods("POST")
	service.Mux.HandleFunc("/admin/logout", ctrl.LogoutHandler).Methods("GET")

	// admin list users
	service.Mux.HandleFunc("/admin/user", LoggedIn(ctrl.ListUsers)).Methods("GET")

	// invite user to register
	service.Mux.HandleFunc("/admin/user/invite", LoggedIn(ctrl.Invite)).Methods("GET")
	service.Mux.HandleFunc("/admin/user/invite", user.CsrfForm(LoggedIn(ctrl.InviteHandler))).Methods("POST")

	service.Mux.HandleFunc("/admin/user/{username}/delete", LoggedIn(ctrl.DeleteUser)).Methods("GET")
	service.Mux.HandleFunc("/admin/user/{username}", LoggedIn(ctrl.UpdateUser)).Methods("POST")

	// admin user update, add this one last
	service.Mux.HandleFunc("/admin/user/{username}", LoggedIn(ctrl.ShowUser)).Methods("GET")
	// service.Mux.HandleFunc("/admin/user/{id}", admin(ctrl.ShowUser)).Methods("POST")

	// admin delete user
	// service.Mux.HandleFunc("/admin/user/{id}", admin(ctrl.TODO)).Methods("DELETE")

	// ## Picture management
	// picture list
	// service.Mux.HandleFunc("/admin/picture", admin(ctrl.TODO)).Methods("GET")
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

// Login ...
func (c *Controller) Login(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())
	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/admin/login.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
	}{
		Title:    "User List",
		Messages: user.GetMessages(w, r),
	})
}

// LoginHandler ...
func (c *Controller) LoginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LoginHandler", r.URL.String())

	r.ParseForm()
	username := r.FormValue("username")

	// get session, ignore session
	session, _ := store.Get(r, "admin-session")

	// already logged in
	u, ok := session.Values["user"].(*user.User)
	if ok && u != nil {
		http.Redirect(w, r, fmt.Sprintf("/admin/picture"), http.StatusFound)
		return
	}

	// Get user from db
	u, err := c.udb.Get(username)
	if err != nil {
		fmt.Println("[E] failed to get user", err)
		session.AddFlash("Login Failed, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/admin/login?username=%s", username), http.StatusFound)
		return
	}
	if u == nil {
		fmt.Println("[E] no user")
		session.AddFlash("Login Failed, Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/admin/login?username=%s", username), http.StatusFound)
		return
	}

	if !u.Admin && !u.Root {
		session.AddFlash("Access Denied.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound)
		return
	}

	// Verify password
	password := r.FormValue("password")
	err = bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password))
	if err != nil {
		fmt.Println("Invalid Password:", password, err)
		session.AddFlash("Invalid Password")
		session.Save(r, w)
		http.Error(w, "Invalid Password", http.StatusBadRequest)
		return
	}

	// Save user session
	session.Values["user"] = u
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("/user/%s/picture", u.ID), http.StatusFound)
}

// LogoutHandler revokes authentication for a user
func (c *Controller) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LogoutHandler", r.URL.String())
	session, err := store.Get(r, "admin-session")
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

// ListUsers ...
func (c *Controller) ListUsers(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ListUsers", r.URL.String())
	// Check for duplicate username
	messages := user.GetMessages(w, r)

	users, err := c.udb.FetchAll()
	if err != nil {
		messages = append(messages, "error loading users:"+err.Error())
		return
	}

	// TODO: count pictures

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/admin/listUsers.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
		Users    []*user.User
	}{
		Title:    "User List",
		Messages: messages,
		Users:    users,
	})
}

// ShowUser ...
func (c *Controller) ShowUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("ShowUser", r.URL.String())
	// get session, ignore errors
	session, _ := store.Get(r, "user-session")

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
		Messages: user.GetMessages(w, r),
		User:     u,
	})
}

// DeleteUser ...
func (c *Controller) DeleteUser(w http.ResponseWriter, r *http.Request) {
	fmt.Println("DeleteUser", r.URL.String())
	// get session, ignore errors
	session, _ := store.Get(r, "user-session")

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
	session, _ := store.Get(r, "user-session")

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

// Invite ...
func (c *Controller) Invite(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Invite:", r.URL.String())

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/admin/invite.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
		Token    string
	}{
		Title:    "login",
		Messages: user.GetMessages(w, r),
		Token:    form.New(),
	})
}

// InviteHandler ...
func (c *Controller) InviteHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("InviteHandler:", r.URL.String())

	// get session, ignore errors
	session, _ := store.Get(r, "user-session")

	r.ParseForm()
	username := r.FormValue("username")

	// verify user
	if username == "" {
		fmt.Println("Empty username")
		session.AddFlash("Invalid username.")
		session.Save(r, w)
		http.Redirect(w, r, "/admin/user/invite", http.StatusFound)
		return
	}

	// look for current user
	// Check for duplicate username
	u, err := c.udb.Get(username)
	if err != nil {
		fmt.Println("[E] no user", err)
		session.AddFlash("Please Try Again")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/admin/user/invite?username=%s", username), http.StatusFound)
		return
	}
	if u != nil {
		// What do I want to do if user is already registered?????
		session.AddFlash("Please Try Again")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/admin/user/%s", u.ID), http.StatusFound)
		return
	} else {
		u = &user.User{
			Username: username,
		}
	}

	// get random token
	u.Token = form.New()

	err = c.udb.Save(u)
	if err != nil {
		fmt.Println("[E] user gen error", err)
		session.AddFlash("Please try again.")
		session.Save(r, w)
		http.Redirect(w, r, fmt.Sprintf("/admin/user/invite?username=%s", username), http.StatusFound) /// for now
		return
	}

	subject := fmt.Sprintf("Message...")

	// Generate register url
	url := fmt.Sprintf("%s/user/register?username=%s&token=%s", r.Header.Get("Origin"), username, u.Token)

	// Email template
	emailTemplates := template.Must(template.ParseFiles("templates/email/invite.html", "templates/email/base.html"))
	var tpl bytes.Buffer
	emailTemplates.ExecuteTemplate(&tpl, "base", &struct {
		URL string
	}{
		URL: url,
	})
	body := tpl.String()

	if c.service.Config.GetBool("email") {
		panic("not working yet")
		// test mail
		m := gomail.NewMessage()
		m.SetHeader("From", "alex@example.com")
		m.SetHeader("To", "jlwarren1@gmail.com")
		// m.SetAddressHeader("Cc", "dan@example.com", "Dan")
		m.SetHeader("Subject", subject)
		// m.SetBody("text/html", "Hello <b>Bob</b> and <i>Cora</i>!")
		m.SetBody("text/html", body)

		// cmd := exec.Command("/usr/sbin/sendmail", "-t")
		// var stdOutBuf bytes.Buffer
		// var stdErrBuf bytes.Buffer
		// cmd.Stdout = &stdOutBuf
		// cmd.Stderr = &stdErrBuf

		// pw, err := cmd.StdinPipe()
		// if err != nil {
		// 	fmt.Println("EEE:", err)
		// 	return
		// }

		// err = cmd.Run()
		// if err != nil {
		// 	fmt.Println("EEE:", err)
		// 	return
		// }

		// stdOut := strings.TrimSuffix(stdOutBuf.String(), "\n")
		// stdErr := strings.TrimSuffix(stdErrBuf.String(), "\n")

		// var errs [3]error
		// _, errs[0] = m.WriteTo(pw)
		// errs[1] = pw.Close()
		// errs[2] = cmd.Wait()
		// for _, err = range errs {
		// 	if err != nil {
		// 		fmt.Println("...", err)
		// 		// return
		// 	}
		// }

		// fmt.Println("OUt:", stdOut)
		// fmt.Println("ERR:", stdErr)

		// fromEmail := "test@example.com"
		// toEmail := "jlwarren1@gmail.com"
		// msg := "Subject: Sendmail Using Go"

		// sendmail := exec.Command("/usr/sbin/sendmail", "-f", fromEmail, toEmail)
		// stdin, err := sendmail.StdinPipe()
		// if err != nil {
		// 	panic(err)
		// }

		// stdout, err := sendmail.StdoutPipe()
		// if err != nil {
		// 	panic(err)
		// }

		// sendmail.Start()
		// stdin.Write([]byte(msg))
		// stdin.Close()
		// sentBytes, _ := ioutil.ReadAll(stdout)
		// sendmail.Wait()

		// fmt.Println("Send Command Output\n")
		// fmt.Println(string(sentBytes))

		// TODO: figure out how to send mail on pi
		// TODO: make sure port:25 is open
		// (echo >/dev/tcp/localhost/25) &>/dev/null && echo "TCP port 25 opened" || echo "TCP port 25 closed"
		http.Redirect(w, r, "/admin/user", http.StatusFound)
	} else {
		// parse every time to make updates easier, and save memory
		templates := template.Must(template.ParseFiles("templates/admin/inviteEmail.html", "templates/base.html"))
		templates.ExecuteTemplate(w, "base", &struct {
			Title    string
			Messages []string
			Subject  string
			Body     string
		}{
			Title:    "login",
			Messages: user.GetMessages(w, r),
			Subject:  subject,
			Body:     body,
		})
	}
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
// 	session, err := store.Get(r, "user-session")
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
