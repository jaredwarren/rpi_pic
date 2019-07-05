package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"

	"github.com/jaredwarren/rpi_pic/email"

	"github.com/gorilla/sessions"
	"github.com/jaredwarren/rpi_pic/admin"
	"github.com/jaredwarren/rpi_pic/app"
	"github.com/jaredwarren/rpi_pic/root"
	"github.com/jaredwarren/rpi_pic/user"
)

func main() {
	// setup db
	userStore, err := user.NewStore("./user.db")
	if err != nil {
		panic(err.Error())
	}

	// setup session
	var cookieStore *sessions.CookieStore
	// authKeyOne := securecookie.GenerateRandomKey(64)
	// TODO: store these as env vars
	authKey := os.Getenv("AUTH_KEY")
	if authKey == "" {
		panic("AUTH_KEY required")
	}
	// authKeyOne := []byte("nLgrBC6QDqmKnUmYeS7AdUXvVD6EAb7SnLgrBC6QDqmKnUmYeS7AdUXvVD6EAb7S")
	authKeyOne := []byte(authKey)

	// fmt.Printf(":authKeyOne:%s\n", authKeyOne)
	// encryptionKeyOne := securecookie.GenerateRandomKey(32)
	// fmt.Printf(":encryptionKeyOne:%s\n", encryptionKeyOne)

	encKey := os.Getenv("ENC_KEY")
	if encKey == "" {
		panic("ENC_KEY required")
	}
	// encryptionKeyOne := []byte("nLgrBC6QDqmKnUmYeS7AdUXvVD6EAb7S")
	encryptionKeyOne := []byte(encKey)
	cookieStore = sessions.NewCookieStore(
		authKeyOne,
		encryptionKeyOne,
	)
	cookieStore.Options = &sessions.Options{
		// MaxAge: 0,
		MaxAge:   604800,
		HttpOnly: true,
		Path:     "/",
		// Domain:   "localhost",
		// Secure:   true,
	}

	// service paths
	service := app.New("Shipping")

	service.Mux.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	uc := user.NewUserController(service, userStore, cookieStore)
	user.MountUserController(service, uc)

	// pc := picture.NewPictureController(service)
	// picture.MountPictureController(service, pc)

	ac := admin.NewAdminController(service, userStore, cookieStore, &email.Email{})
	admin.MountAdminController(service, ac)

	rc := root.NewRootController(service, userStore, cookieStore)
	root.MountRootController(service, rc)

	// signal handler
	errc := make(chan error)

	// Interrupt handler
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt)
		errc <- fmt.Errorf("%s", <-c)
	}()

	// Start Server
	srv := &http.Server{
		Addr:    ":8081",
		Handler: service.Mux,
	}
	go func() {
		fmt.Printf("HTTP server listening on %q\n", srv.Addr)
		errc <- srv.ListenAndServe()
	}()

	// Wait for signal.
	fmt.Printf("\nexiting (%v)\n", <-errc)
	fmt.Println("exited")
}
