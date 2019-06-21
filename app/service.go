package app

import (
	"github.com/gorilla/mux"
)

// Service ...
type Service struct {
	Name string
	Mux  *mux.Router
}

// New instantiates a service with the given name.
func New(name string) *Service {
	mux := mux.NewRouter()
	var service = &Service{
		Name: name,
		Mux:  mux,
	}

	return service
}
