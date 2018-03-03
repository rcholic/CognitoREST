package api

import (
	"context"

	"github.com/go-kit/kit/endpoint"
)

// type Middleware func(endpoint.Endpoint) endpoint.Endpoint

// func jwtAuthMiddleware(logger log.Logger) Middleware {
// 	return func(next endpoint.Endpoint) endpoint.Endpoint {
// 		return func(ctx context.Context, r interface{}) (interface{}, error) {
// 			logger.Log("msg from middleware: ", "calling endpoint")
// 			// ExtractToken(r.(http.Request)) // get jwt token from header
// 			defer logger.Log("msg", "called endpoint")
// 			return next(ctx, r)
// 		}
// 	}
// }

type EndPoints struct {
	SignUpEndpoint                endpoint.Endpoint
	SignInEndpoint                endpoint.Endpoint
	GetUserEndpoint               endpoint.Endpoint
	ConfirmSignUpEndpoint         endpoint.Endpoint
	ForgotPasswordEndpoint        endpoint.Endpoint
	ConfirmForgotPasswordEndpoint endpoint.Endpoint
	ChangePasswordEndpoint        endpoint.Endpoint
}

func MakeEndpoints(s UserService) EndPoints {
	return EndPoints{
		SignUpEndpoint:                MakeSignUpEndpoint(s),
		SignInEndpoint:                MakeSignInEndpoint(s),
		GetUserEndpoint:               MakeGetUserEndpoint(s),
		ConfirmSignUpEndpoint:         MakeConfirmSignUpEndpoint(s),
		ForgotPasswordEndpoint:        MakeForgotPasswordEndpoint(s),
		ConfirmForgotPasswordEndpoint: MakeConfirmForgotPasswordEndpoint(s),
		ChangePasswordEndpoint:        MakeChangePasswordEndpoint(s),
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

func MakeChangePasswordEndpoint(s UserService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(changePasswordRequest)
		return s.ChangePassword(req.AccessToken, req.PrevPassword, req.NewPassword)
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

type changePasswordRequest struct {
	AccessToken  string
	PrevPassword string
	NewPassword  string
}
