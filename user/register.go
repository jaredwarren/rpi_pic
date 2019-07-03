package user

import (
	"fmt"
	"html/template"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

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
