package root

import (
	"fmt"
	"net/http"
)

// Root middleware require root session
func (c *Controller) Root(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Root:", r.URL.String())
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
		if !user.Root {
			fmt.Println("  [E] user not root")
			session.AddFlash("Access Denied.")
			http.Redirect(w, r, "/forbidden", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	}
}
