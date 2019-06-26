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

// LoggedIn middleware require admin session
func LoggedIn(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("TODO: check for admin session %s\n", r.URL)
		next.ServeHTTP(w, r)
	}
}
