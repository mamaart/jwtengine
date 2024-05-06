package main

import (
	"crypto"
	"fmt"
	"net/http"

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
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		claims, err := middleware.ContextGetClaims(r.Context())
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if claims != nil {
			fmt.Fprintf(w, "Authorized... and the claims from the context is: %+v", claims)
		} else {
			fmt.Fprint(w, "Authorized... and token from context is: nil")
		}
	})
	return &ValidatorService{handler: midlwr.HandleHTTP(mux)}, nil
}

func (s *ValidatorService) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}
