package user

import (
	"fmt"
	"html/template"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

// Login form
func (c *Controller) Login(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Login:", r.URL.String())

	r.ParseForm()
	username := r.FormValue("username")

	session, _ := c.cookieStore.Get(r, "user-session")

	// parse every time to make updates easier, and save memory
	tpl := template.Must(template.New("base").Funcs(template.FuncMap{"CsrfToken": CsrfToken}).ParseFiles("templates/user/login.html", "templates/base.html"))
	tpl.ExecuteTemplate(w, "base", &struct {
		Title    string
		Messages []string
		Username string
	}{
		Title: "login",
		// Messages: GetMessages(session),
		Username: username,
	})
	session.Save(r, w)
}

// LoginHandler form submit
func (c *Controller) LoginHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println("LoginHandler:", r.URL.String())

	// get session
	session, err := c.cookieStore.Get(r, "user-session")
	if err != nil {
		fmt.Printf("  %+v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

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

	err = session.Save(r, w)
	if err != nil {
		panic(err)
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

	http.SetCookie(w, &http.Cookie{
		Name:   "user-session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})
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
