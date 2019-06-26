package main

import (
	"crypto/tls"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/gorilla/mux"

	"github.com/goadesign/goa"
	"github.com/jaredwarren/printer/app"
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
		log.Printf("Logged connection from %s", r.RemoteAddr)
		next.ServeHTTP(w, r)
	}
}

func withTracing(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Tracing request for %s", r.RequestURI)
		next.ServeHTTP(w, r)
	}
}

func myLoggingHandler(h http.Handler) http.Handler {
	logFile, err := os.OpenFile("server.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0666)
	if err != nil {
		panic(err)
	}
	return handlers.LoggingHandler(logFile, h)
}

func final(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("OK"))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Do stuff here
		log.Println(r.RequestURI)
		// Call the next handler, which can be another middleware in the chain, or the final handler.
		next.ServeHTTP(w, r)
	})
}

// Display a single data
func GetPerson(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	for _, item := range people {
		if item.ID == params["id"] {
			json.NewEncoder(w).Encode(item)
			return
		}
	}
	json.NewEncoder(w).Encode(&Person{})
}

func main() {

	router := mux.NewRouter()

	// dash := router.PathPrefix("/user").Subrouter()

	// r := router.HandleFunc("/user", loggingMiddleware(GetPeople)).Methods("GET")

	// r.U
	// r.Use(loggingMiddleware)
	lt := chainMiddleware(withLogging, withTracing)
	router.HandleFunc("/user/{id}", lt(GetPerson)).Methods("GET")

	router.HandleFunc("/user/{id}", lt(GetPerson)).Methods("GET")
	router.HandleFunc("/user/{id}", lt(GetPerson)).Methods("GET")

	// router.HandleFunc("/people/{id}", CreatePerson).Methods("POST")
	// router.HandleFunc("/people/{id}", DeletePerson).Methods("DELETE")
	log.Fatal(http.ListenAndServe(":8000", router))
	return

	//
	//
	//
	//

	// // Create Windows Service
	// binaryPathName, err := os.Getwd()
	// if err != nil {
	// 	log.Fatal(err)
	// 	os.Exit(1)
	// }

	// // make sure we're using the right dir
	// if err := os.Chdir(filepath.Dir(binaryPathName)); err != nil {
	// 	log.Fatal(err)
	// 	os.Exit(1)
	// }

	// Paths
	// User
	/// invite(admin +)
	/// login(none)
	/// login(none)

	//
	//
	finalHandler := http.HandlerFunc(final)

	http.Handle("/", myLoggingHandler(finalHandler))
	http.ListenAndServe(":3000", nil)
	//
	//

	//
	//
	mw := chainMiddleware(withLogging, withTracing)
	http.Handle("/", mw(home))
	log.Fatal(http.ListenAndServe(":8080", nil))
	//
	//

	// Create service
	service := goa.New("Shipping")

	// Mount middleware
	service.Use(middleware.RequestID())
	service.Use(middleware.LogRequest(true))
	service.Use(middleware.ErrorHandler(service, true))
	service.Use(middleware.Recover())

	// Mount "home" controller
	hc := NewHomeController(service)
	app.MountHomeController(service, hc)
	// Mount "printer" controller
	pc := NewPrinterController(service)
	app.MountPrinterController(service, pc)
	// Mount "scale" controller
	c3 := NewScaleController(service)
	app.MountScaleController(service, c3)

	// initialize default printers
	err = pc.InitializeDefault()
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	// Use http.Server instead of goa default
	httpsServer := &http.Server{
		Addr:    ":8443",
		Handler: service.Mux,
		TLSConfig: &tls.Config{
			//InsecureSkipVerify: true,
			InsecureSkipVerify: false,
		},
	}

	basePath := filepath.Dir(binaryPathName) + "/printer"
	println(basePath)
	err = httpsServer.ListenAndServeTLS(basePath+"/auth/localhost.crt", basePath+"/auth/localhost.key")
	if err != nil {
		log.Fatalf("Fail: \"%s\"", err)
		os.Exit(1)
	}
}
