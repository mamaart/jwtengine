package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/mamaart/jwtengine/issuer"
	"github.com/mamaart/jwtengine/middleware/httpware"
)

type IssuerServer struct {
	issuer  *issuer.Issuer[*MyClaims]
	handler http.Handler
}

func NewIssuerServer(issuer *issuer.Issuer[*MyClaims]) (*IssuerServer, error) {
	router := mux.NewRouter()

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tokens, err := issuer.IssueTokens(&MyClaims{
			user: "hello",
		})
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Could not create refresh tokens: %s", err)))
			return
		}
		json.NewEncoder(w).Encode(tokens)
	})

	router.HandleFunc("/publickey", func(w http.ResponseWriter, r *http.Request) {
		pem, err := issuer.PublicKeyPEM()
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(fmt.Sprintf("Failed to get publicKey PEM from issuer: %s", err)))
		}
		w.Write(pem)
	})

	router.HandleFunc("/refresh", func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := httpware.GetBearerToken(r)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(err.Error()))
			return
		}
		tokens, err := issuer.Refresh(tokenString)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(fmt.Sprintf("Could not create refresh tokens: %s", err)))
			return
		}
		json.NewEncoder(w).Encode(tokens)
	})
	return &IssuerServer{issuer, router}, nil
}

func (s *IssuerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}
