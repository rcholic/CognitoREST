package api

import (
	"context"

	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/tracing/opentracing"
	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/sirupsen/logrus"
)

type EndPoints struct {
	SignUpEndpoint                endpoint.Endpoint
	SignInEndpoint                endpoint.Endpoint
	GetUserEndpoint               endpoint.Endpoint
	ConfirmSignUpEndpoint         endpoint.Endpoint
	ForgotPasswordEndpoint        endpoint.Endpoint
	ConfirmForgotPasswordEndpoint endpoint.Endpoint
	ChangePasswordEndpoint        endpoint.Endpoint
	ValidateTokenEndpoint         endpoint.Endpoint // NOTE: for API gateway to use only(?)
}

func MakeEndpoints(s UserService, tracer stdopentracing.Tracer) EndPoints {
	return EndPoints{
		SignUpEndpoint:                opentracing.TraceServer(tracer, "POST /user/signup")(MakeSignUpEndpoint(s)),
		SignInEndpoint:                opentracing.TraceServer(tracer, "POST /user/signin")(MakeSignInEndpoint(s)),
		GetUserEndpoint:               opentracing.TraceServer(tracer, "GET /user/{username}")(MakeGetUserEndpoint(s)),
		ConfirmSignUpEndpoint:         opentracing.TraceServer(tracer, "GET /user/confirm/{username}/{code}")(MakeConfirmSignUpEndpoint(s)),
		ForgotPasswordEndpoint:        opentracing.TraceServer(tracer, "POST /user/forgot_password")(MakeForgotPasswordEndpoint(s)),
		ConfirmForgotPasswordEndpoint: opentracing.TraceServer(tracer, "POST /user/reset_password")(MakeConfirmForgotPasswordEndpoint(s)),
		ChangePasswordEndpoint:        opentracing.TraceServer(tracer, "POST /user/change_password")(MakeChangePasswordEndpoint(s)),
		ValidateTokenEndpoint:         opentracing.TraceServer(tracer, "GET /login")(MakeValidateTokenEndpoint(s)),
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
		resp, err := s.SignIn(req.Username, req.Password)

		if err == nil {
			accessT := resp.AuthenticationResult.AccessToken
			_ = resp.AuthenticationResult.IdToken
			_ = resp.AuthenticationResult.RefreshToken
			c2 := context.WithValue(ctx, ContextAccessTokenKey, *accessT)
			ctx = c2
		}

		return resp, err
	}
}

func MakeGetUserEndpoint(s UserService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		token := ctx.Value(ContextAccessTokenKey)
		logrus.Infof("token get it? %v\n", token)
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

func MakeValidateTokenEndpoint(s UserService) endpoint.Endpoint {
	return func(ctx context.Context, request interface{}) (response interface{}, err error) {
		req := request.(validateTokenRequest)
		return s.ValidateJwtToken(req.JwtToken)
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

type validateTokenRequest struct {
	JwtToken string
}
