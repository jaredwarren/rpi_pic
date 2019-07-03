package root

import (
	"fmt"
	"net/http"
)

// Root middleware require root session
func (c *Controller) Root(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetURL := r.URL.String()
		fmt.Println("Root:", targetURL)
		// get session
		session, err := c.cookieStore.Get(r, "user-session")
		if err != nil {
			fmt.Println("  [E]", err)
			if targetURL != "/login" {
				fmt.Println("    ->  set redirect:", targetURL)
				session.AddFlash(targetURL, "redirect")
			}
			session.AddFlash("Please try again.")
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// not logged in
		username, _ := session.Values["user"].(string)
		if username == "" {
			fmt.Println("  [E] user session missing")
			if targetURL != "/login" {
				fmt.Println("    ->  set redirect:", targetURL)
				session.AddFlash(targetURL, "redirect")
			}
			session.AddFlash("Please log in again.")
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// get user from db
		user, err := c.udb.Get(username)
		if err != nil {
			fmt.Println("  [E] user error", err)
			session.AddFlash("Please try again.")
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if user == nil {
			fmt.Println("  [E] user missing")
			session.AddFlash("Please try again.")
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// verify credentials
		if !user.Root {
			fmt.Println("  [E] user not root")
			session.AddFlash("Access Denied.")
			session.Save(r, w)
			http.Redirect(w, r, "/forbidden", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	}
}
