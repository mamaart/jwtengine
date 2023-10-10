package main

import (
	"crypto"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/mamaart/jwtengine/middleware"
	"github.com/mamaart/jwtengine/middleware/httpware"
)

type ValidatorService struct {
	handler http.Handler
}

func NewValidatorService(publicKey crypto.PublicKey) (*ValidatorService, error) {
	midlwr, err := httpware.NewMiddleware(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate new validator from publicKey: %s", err)
	}
	router := mux.NewRouter()
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		claims, err := middleware.ContextGetClaims(r.Context())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
		}

		if claims != nil {
			w.Write(
				[]byte(
					fmt.Sprintf("Authorized... and the claims from the context is: %+v", claims),
				),
			)
		} else {
			w.Write([]byte("Authorized... and token from context is: nil"))
		}

	})
	return &ValidatorService{handler: midlwr.HandleHTTP(router)}, nil
}

func (s *ValidatorService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}
