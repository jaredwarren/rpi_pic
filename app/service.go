package app

import (
	"fmt"

	"github.com/gorilla/mux"
	"github.com/jaredwarren/rpi_pic/config"
)

// Service ...
type Service struct {
	Name   string
	Mux    *mux.Router
	Config *config.Config
}

// New instantiates a service with the given name.
func New(name string) *Service {
	mux := mux.NewRouter()

	config, _ := config.Load(fmt.Sprintf("./%s_config.db", name))

	var service = &Service{
		Name:   name,
		Mux:    mux,
		Config: config,
	}

	return service
}
