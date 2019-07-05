package user

import (
	"fmt"
	"net/http"

	"github.com/jaredwarren/rpi_pic/form"
)

// middleware provides a convenient mechanism for filtering HTTP requests
// entering the application. It returns a new handler which performs various
// operations and finishes with calling the next HTTP handler.
type middleware func(http.HandlerFunc) http.HandlerFunc

// chainMiddleware provides syntactic sugar to create a new middleware
// which will be the result of chaining the ones received as parameters.
func chainMiddleware(mw ...middleware) middleware {
	return func(final http.HandlerFunc) http.HandlerFunc {
		last := final
		for i := len(mw) - 1; i >= 0; i-- {
			last = mw[i](last)
		}

		return func(w http.ResponseWriter, r *http.Request) {
			last(w, r)
		}
	}
}

func withLogging(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Logged connection from %s", r.RemoteAddr)
		next.ServeHTTP(w, r)
	}
}

// LoggedIn valid user
func (c *Controller) LoggedIn(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		targetURL := r.URL.String()
		fmt.Println("Login:", targetURL)
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

		// already logged in
		username, ok := session.Values["user"].(string)
		if !ok || username == "" {
			fmt.Println("  [E] user session missing")
			if targetURL != "/login" {
				fmt.Println("    ->  set redirect:", targetURL)
				session.AddFlash(targetURL, "redirect")
			}
			session.AddFlash("Please try again.")
			session.Save(r, w)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	}
}

// CsrfForm validate form with csrf token
func CsrfForm(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("csrf:", r.URL.String())
		r.ParseMultipartForm(32 << 20)

		// validate session token
		tokenHash := r.FormValue("csrf_token")
		_, ok := form.GetForm(tokenHash)
		if !ok {
			fmt.Println("  [E] form expired:", tokenHash)
			// session.AddFlash("Login Failed, Please try again.")

			// TODO: how to detect recirect loops
			if r.RequestURI != r.URL.String() {
				http.Redirect(w, r, r.URL.String(), http.StatusFound)
			} else {
				http.Redirect(w, r, "/", http.StatusFound)
			}

			return
		}

		next.ServeHTTP(w, r)
	}
}
