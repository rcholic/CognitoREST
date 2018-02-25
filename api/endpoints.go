package api

import (
	"context"

	"github.com/go-kit/kit/endpoint"
)

type EndPoints struct {
	SignUpEndpoint                endpoint.Endpoint
	SignInEndpoint                endpoint.Endpoint
	GetUserEndpoint               endpoint.Endpoint
	ConfirmSignUpEndpoint         endpoint.Endpoint
	ForgotPasswordEndpoint        endpoint.Endpoint
	ConfirmForgotPasswordEndpoint endpoint.Endpoint
}

func MakeEndpoints(s UserService) EndPoints {
	return EndPoints{
		SignUpEndpoint:                MakeSignUpEndpoint(s),
		SignInEndpoint:                MakeSignInEndpoint(s),
		GetUserEndpoint:               MakeGetUserEndpoint(s),
		ConfirmSignUpEndpoint:         MakeConfirmSignUpEndpoint(s),
		ForgotPasswordEndpoint:        MakeForgotPasswordEndpoint(s),
		ConfirmForgotPasswordEndpoint: MakeConfirmForgotPasswordEndpoint(s),
	}
}

func MakeSignUpEndpoint(s UserService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(signupRequest)
		return s.SignUp(req.Username, req.Password, req.ConfirmPass, req.Email)
	}
}

func MakeSignInEndpoint(s UserService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(signinRequest)
		return s.SignIn(req.Username, req.Password)
	}
}

func MakeGetUserEndpoint(s UserService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(getuserRequest)
		return s.GetUser(req.Username)
	}
}

func MakeConfirmSignUpEndpoint(s UserService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(confirmSignUpRequest)
		return s.ConfirmSingUp(req.Code, req.Username)
	}
}

func MakeForgotPasswordEndpoint(s UserService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(forgotPasswordRequest)
		return s.ForgotPassword(req.Username)
	}
}

func MakeConfirmForgotPasswordEndpoint(s UserService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(confirmForgotPasswordRequest)
		return s.ConfirmForgotPassword(req.NewPassword, req.ConfirmCode, req.Username)
	}
}

type signupRequest struct {
	Username    string
	Password    string
	ConfirmPass string
	Email       string
}

type signinRequest struct {
	Username string
	Password string
}

type getuserRequest struct {
	Username string
}

type confirmSignUpRequest struct {
	Code     string
	Username string
}

type forgotPasswordRequest getuserRequest // type alias

type confirmForgotPasswordRequest struct {
	NewPassword string
	ConfirmCode string
	Username    string
}
