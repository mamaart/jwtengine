package main

import (
	"encoding/json"
	"net/http"

	"github.com/mamaart/jwtengine/issuer"
	"github.com/mamaart/jwtengine/middleware/httpware"
)

type IssuerServer struct {
	issuer  *issuer.Issuer[*MyClaims]
	handler http.Handler
}

func NewIssuerServer(issuer *issuer.Issuer[*MyClaims]) (*IssuerServer, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /", func(w http.ResponseWriter, _ *http.Request) {
		tokens, err := issuer.IssueTokens(&MyClaims{
			user: "hello",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(tokens)
	})

	mux.HandleFunc("GET /publickey", func(w http.ResponseWriter, _ *http.Request) {
		pem, err := issuer.PublicKeyPEM()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write(pem)
	})

	mux.HandleFunc("GET /refresh", func(w http.ResponseWriter, r *http.Request) {
		tokenString, err := httpware.GetBearerToken(r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		tokens, err := issuer.Refresh(tokenString)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(tokens)
	})
	return &IssuerServer{issuer, mux}, nil
}

func (s *IssuerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}
