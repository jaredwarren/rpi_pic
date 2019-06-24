package admin

import (
	"bytes"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"text/template"

	"github.com/jaredwarren/rpi_pic/app"
	"github.com/jaredwarren/rpi_pic/user"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

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
	// admin list users
	service.Mux.HandleFunc("/admin/user", admin(ctrl.ListUsers)).Methods("GET")
	// admin user update
	service.Mux.HandleFunc("/admin/user/{id}", admin(ctrl.TODO)).Methods("POST")
	// admin delete user
	service.Mux.HandleFunc("/admin/user/{id}", admin(ctrl.TODO)).Methods("DELETE")
	// invite user to register
	service.Mux.HandleFunc("/admin/user/invite", admin(ctrl.Invite)).Methods("GET")
	service.Mux.HandleFunc("/admin/user/invite", user.CsrfForm(admin(ctrl.InviteHandler))).Methods("POST")

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
	msg := "TODO...." + r.URL.String()
	fmt.Printf("TODO: %+v\n", r)
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

// Invite ...
func (c *Controller) Invite(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	// parse every time to make updates easier, and save memory
	templates := template.Must(template.ParseFiles("templates/admin/invite.html", "templates/base.html"))
	templates.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
		Token    string
	}{
		Title:    "login",
		Messages: user.GetMessages(r),
		Token:    "",
	})
}

// InviteHandler ...
func (c *Controller) InviteHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.String())

	// // get session
	// session, err := store.Get(r, "user-session")
	// if err != nil {
	// 	fmt.Println("[E] no session", err)
	// 	session.AddFlash("Please try again.")
	// 	http.Redirect(w, r, "/admin/user/invite", http.StatusFound) /// for now
	// 	return
	// }

	r.ParseForm()
	username := r.FormValue("username")

	// verify user
	if username == "" {
		fmt.Println("Empty username")
		// session.AddFlash("Invalid username.")
		http.Redirect(w, r, "/admin/user/invite", http.StatusFound) /// for now
		return
	}

	// look for current user
	// Check for duplicate username
	u, err := c.udb.Find("username", username)
	if err != nil {
		fmt.Println("[E] no user", err)
		// session.AddFlash("Please try again.")
		http.Redirect(w, r, "/admin/user/invite", http.StatusFound) /// for now
		return
	}
	if u != nil {
		// check if user is already registered
		if u.Password != "" {
			fmt.Printf("[E] user found, %s, %+v\n", err, u)
			// session.AddFlash("User already registered.")
			http.Redirect(w, r, fmt.Sprintf("/user/login?username=%s", username), http.StatusFound) /// for now
			return
		}
	} else {
		u = &user.User{
			Username: username,
		}
	}

	// for now just use the same "password"
	hash, err := bcrypt.GenerateFromPassword([]byte("password1"), bcrypt.MinCost)
	if err != nil {
		fmt.Println("[E] pass gen error", err)
		// session.AddFlash("Please try again.")
		http.Redirect(w, r, "/admin/user/invite", http.StatusFound) /// for now
		return
	}
	c.udb.SetToken([]byte(username), hash)

	id, err := c.udb.Save(u)
	if err != nil {
		fmt.Println("[E] user gen error", err)
		// session.AddFlash("Please try again.")
		http.Redirect(w, r, "/admin/user/invite", http.StatusFound) /// for now
		return
	}
	u.ID = id

	subject := fmt.Sprintf("Message...")

	// TODO: get current public url.....
	url := fmt.Sprintf("http://localhost/user/register?username=%s&token=%s", username, hash)

	emailTemplates := template.Must(template.ParseFiles("templates/email/invite.html", "templates/email/base.html"))
	var tpl bytes.Buffer
	emailTemplates.ExecuteTemplate(&tpl, "base", &struct {
		URL string
	}{
		URL: url,
	})
	body := tpl.String()

	// TODO: make template
	// body := fmt.Sprintf(`Register Here: <a href="%s">Link</a>`, url)
	// templates.

	if c.service.Config.GetBool("email") {
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
			Messages: user.GetMessages(r),
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
