package app

import (
	"fmt"

	"github.com/gorilla/mux"
	"github.com/jaredwarren/rpi_pic/config"
	"github.com/jaredwarren/rpi_pic/picture"
)

// Service ...
type Service struct {
	Name           string
	Mux            *mux.Router
	Config         *config.Config
	CurrentPicture *picture.Picture
}

// New instantiates a service with the given name.
func New(name string) *Service {
	mux := mux.NewRouter()

	config, _ := config.Load(fmt.Sprintf("./%s_config.db", name))

	currentPicture := &picture.Picture{}
	currentPicture.Start()

	var service = &Service{
		Name:           name,
		Mux:            mux,
		Config:         config,
		CurrentPicture: currentPicture,
	}

	return service
}
