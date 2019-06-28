package admin

import (
	"fmt"
	"net/http"
)

// TODO ...
func TODO(w http.ResponseWriter, r *http.Request) {
	msg := "TODO..." + r.URL.String()
	fmt.Println(msg)
	w.Write([]byte(msg))
}

// Admin middleware require admin session
func (c *Controller) Admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Admin:", r.URL.String())
		// get session
		session, err := c.cookieStore.Get(r, "user-session")
		if err != nil {
			fmt.Println("  [E]", err)
			session.AddFlash("Please try again.")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// not logged in
		username, _ := session.Values["user"].(string)
		if username == "" {
			fmt.Println("  [E] user session missing")
			session.AddFlash("Please log in again.")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// get user from db
		user, err := c.udb.Get(username)
		if err != nil {
			fmt.Println("  [E] user error", err)
			session.AddFlash("Please try again.")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if user == nil {
			fmt.Println("  [E] user missing")
			session.AddFlash("Please try again.")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// verify credentials
		if !user.Admin && !user.Root {
			fmt.Println("  [E] user not admin")
			session.AddFlash("Access Denied.")
			http.Redirect(w, r, "/forbidden", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	}
}
