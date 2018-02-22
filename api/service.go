package api

import (
	"errors"

	"github.com/rcholic/CognitoREST/models"
	"github.com/rcholic/CognitoREST/services"
)

// corelog "log"

var (
	ErrUnauthorized = errors.New("Unauthorized")
)

var cognitoClient = new(services.CognitoClient)

type UserService interface {
	SignUp(username, password, confirmPass, email string) (models.User, error) // register user
	SignIn(email, password string) (models.User, error)                        // InitiateAuth or AdminInitiateAuth ? TODO: return token string
	GetUser(username string) (models.User, error)                              // AdminGetUser or GetUser ?
	ConfirmSingUp(code string) (models.User, error)
}

type localUserService struct{}

func NewUserService() UserService {
	return &localUserService{}
}

func init() {
	cognitoClient.Init()
}

func (s *localUserService) SignUp(username, password, confirmPass, email string) (models.User, error) {
	if username == "" || password == "" || email == "" || password != confirmPass {
		return models.User{}, ErrUnauthorized // TODO: correct the err type here
	}
	return cognitoClient.SignUp(username, password, confirmPass, email)
}

func (s *localUserService) SignIn(email, password string) (models.User, error) {
	return models.User{}, nil // TODO:
}

func (s *localUserService) GetUser(username string) (models.User, error) {
	// TODO: get user and handle error
	u, _ := cognitoClient.GetUser(username)

	u.Sanitize()

	return u, nil
}

func (s *localUserService) ConfirmSingUp(code string) (models.User, error) {
	return models.User{}, nil
}
