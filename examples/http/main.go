package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mamaart/jwtengine/issuer"
	"github.com/mamaart/jwtengine/models"
)

func main() {
	startServers()
	makeRequests()
}

func startServers() {
	issuer, _ := issuer.NewIssuer[*MyClaims](&RefreshValidator{})
	issuerServer, _ := NewIssuerServer(issuer)
	go http.ListenAndServe(":8080", issuerServer)

	validatorServer, _ := NewValidatorService(issuer.PublicKeyRAW())
	go http.ListenAndServe(":8081", validatorServer)

	time.Sleep(1 * time.Second)
}

func makeRequests() {
	cli := http.DefaultClient

	//Get tokens

	var tokens models.Tokens
	{
		resp, _ := cli.Get("http://127.0.0.1:8080")
		json.NewDecoder(resp.Body).Decode(&tokens)
		fmt.Println(tokens.AccessToken)
		fmt.Println(tokens.RefreshToken)
	}

	//Try validation server
	{
		req, _ := http.NewRequest("GET", "http://127.0.0.1:8081", nil)
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokens.AccessToken))
		resp, _ := cli.Do(req)
		data, _ := io.ReadAll(resp.Body)
		fmt.Println(string(data))
	}

	//Get public key as PEM
	{
		resp, _ := cli.Get("http://127.0.0.1:8080/publickey")
		data, _ := io.ReadAll(resp.Body)
		fmt.Println(string(data))
	}

	//Try using RefreshToken to get new tokens
	{
		time.Sleep(time.Second) // Wait a bit else the token will be the same as before
		req, _ := http.NewRequest("GET", "http://127.0.0.1:8080/refresh", nil)
		req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", tokens.RefreshToken))
		resp, _ := cli.Do(req)

		if resp.StatusCode == 200 {
			// Because RefreshValidator{fail: false}
			var tokens models.Tokens
			json.NewDecoder(resp.Body).Decode(&tokens)
			fmt.Println(tokens.AccessToken)
			fmt.Println(tokens.RefreshToken)
		} else {
			// Because RefreshValidator{fail: true}
			fmt.Println(resp.Status)
			data, _ := io.ReadAll(resp.Body)
			fmt.Println(string(data))
		}
	}

}
