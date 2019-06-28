package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"

	"github.com/jaredwarren/rpi_pic/admin"
	"github.com/jaredwarren/rpi_pic/app"
	"github.com/jaredwarren/rpi_pic/picture"
	"github.com/jaredwarren/rpi_pic/user"
)

func main() {

	userStore, err := user.NewStore("./user.db")
	if err != nil {
		panic(err.Error())
	}

	service := app.New("Shipping")

	service.Mux.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

	uc := user.NewUserController(service, userStore)
	user.MountUserController(service, uc)

	pc := picture.NewPictureController(service)
	picture.MountPictureController(service, pc)

	ac := admin.NewAdminController(service, userStore)
	admin.MountAdminController(service, ac)

	// Paths
	// router := mux.NewRouter()
	// user.MountUser(router)
	// admin.MountAdmin(router)
	// root.MountRoot(router)
	// picture.MountPicture(router)

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
