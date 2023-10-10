package main

import (
	"fmt"
	"log"

	"github.com/mamaart/jwtengine/issuer"
	"github.com/mamaart/jwtengine/models"
	"github.com/mamaart/jwtengine/validator"
)

func main() {
	//Setup
	var (
		myIssuer, _    = issuer.NewIssuer[*MyClaims](&RefreshValidator{})
		myValidator, _ = validator.NewValidator(myIssuer.PublicKeyRAW())
	)

	//Print publicKey
	pem, _ := myIssuer.PublicKeyPEM()
	fmt.Println(string(pem))

	//Issue
	tokens, _ := myIssuer.IssueTokens(&MyClaims{user: "martin"})

	//Validate
	token, _ := myValidator.GetToken(tokens.AccessToken)

	//Print
	print(tokens, token.Valid)

	//Issue
	newTokens, _ := myIssuer.Refresh(tokens.RefreshToken)

	//Validate
	newToken, _ := myValidator.GetToken(newTokens.AccessToken)

	//Print
	print(newTokens, newToken.Valid)
}

func print(tokens *models.Tokens, valid bool) {
	fmt.Print("AccessToken: ")
	fmt.Println(tokens.AccessToken)
	fmt.Print("RefreshToken: ")
	fmt.Println(tokens.RefreshToken)
	fmt.Println()

	if valid {
		fmt.Println("Token is valid")
	} else {
		log.Fatal("Token is not valid")
	}
	fmt.Println()
}
