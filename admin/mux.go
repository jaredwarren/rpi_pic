package admin

import (
	"fmt"
	"net/http"
)

// Admin middleware require admin session
func (c *Controller) Admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Admin:", r.URL.String())
		targetURL := r.URL.String()
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
			err = session.Save(r, w)
			if err != nil {
				panic(err)
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8") // For some reason this "fixes" flash redirect
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
		if !user.Admin && !user.Root {
			fmt.Println("  [E] user not admin")
			session.AddFlash("Access Denied.")
			session.Save(r, w)
			http.Redirect(w, r, "/forbidden", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	}
}
