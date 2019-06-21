package root

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
)

// TODO ...
func TODO(w http.ResponseWriter, r *http.Request) {
	msg := "TODO..." + r.URL.String()
	fmt.Println(msg)
	w.Write([]byte(msg))
}

// root middleware require root session
func root(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		fmt.Printf("Logged connection from %s", r.RemoteAddr)
		next.ServeHTTP(w, r)
	}
}

// MountRoot ...
func MountRoot(router *mux.Router) {
	// root menu
	router.HandleFunc("/root", root(TODO)).Methods("GET")

	router.HandleFunc("/root/restart", root(TODO)).Methods("GET")
	router.HandleFunc("/root/update", root(TODO)).Methods("GET")

	// list all user (including admins)
	router.HandleFunc("/root/user", root(TODO)).Methods("GET")
	// show user info
	router.HandleFunc("/root/user/{id}", root(TODO)).Methods("GET")
	// update/create user
	router.HandleFunc("/root/user/{id}", root(TODO)).Methods("POST")
	// delete user
	router.HandleFunc("/root/user/{id}", root(TODO)).Methods("DELETE")
}
