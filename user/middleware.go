package user

import (
	"fmt"
	"net/http"
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

// Login valid user
func Login(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// get session
		session, err := store.Get(r, "user-session")
		if err != nil {
			fmt.Println("[E]", err)
			session.AddFlash("Please try again.")
			http.Redirect(w, r, "/user/login", http.StatusFound)
			return
		}

		// already logged in
		u, ok := session.Values["user"].(User)
		if !ok || !u.Authenticated {
			session.AddFlash("Please try again.")
			http.Redirect(w, r, "/user/login", http.StatusFound)
			return
		}

		next.ServeHTTP(w, r)
	}
}
