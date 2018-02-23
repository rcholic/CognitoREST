package api

import (
	"errors"

	cogIdp "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/rcholic/CognitoREST/services"
)

// corelog "log"

var (
	ErrUnauthorized = errors.New("Unauthorized")
)

var cognitoClient = new(services.CognitoClient)

type UserService interface {
	SignUp(username, password, confirmPass, email string) (*cogIdp.SignUpOutput, error) // register user
	SignIn(username, password string) (*cogIdp.InitiateAuthOutput, error)               // InitiateAuth or AdminInitiateAuth ? TODO: return token string
	GetUser(username string) (*cogIdp.AdminGetUserOutput, error)                        // AdminGetUser or GetUser ?
	ConfirmSingUp(code, username string) (*cogIdp.ConfirmSignUpOutput, error)
}

type localUserService struct{}

func NewUserService() UserService {
	return &localUserService{}
}

func init() {
	cognitoClient.Init()
}

func (s *localUserService) SignUp(username, password, confirmPass, email string) (*cogIdp.SignUpOutput, error) {
	if username == "" || password == "" || email == "" || password != confirmPass {
		return &cogIdp.SignUpOutput{}, ErrUnauthorized // TODO: correct the err type here
	}
	return cognitoClient.SignUp(username, password, confirmPass, email)
}

func (s *localUserService) SignIn(username, password string) (*cogIdp.InitiateAuthOutput, error) {
	return cognitoClient.SignIn(username, password)
}

func (s *localUserService) GetUser(username string) (*cogIdp.AdminGetUserOutput, error) {
	// TODO: get user and handle error
	return cognitoClient.GetUser(username)
}

func (s *localUserService) ConfirmSingUp(code, username string) (*cogIdp.ConfirmSignUpOutput, error) {
	return cognitoClient.ConfirmSignUp(code, username)
}
