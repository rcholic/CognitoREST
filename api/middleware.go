package api

import (
	"context"
	"time"

	cogIdp "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/rcholic/CognitoREST/models"
	"github.com/sirupsen/logrus"
)

// Middleware decorates a service.
type Middleware func(UserService) UserService

// LoggingMiddleware logs method calls, parameters, results, and elapsed time.
func LoggingMiddleware(logger log.Logger) Middleware {
	return func(next UserService) UserService {
		return loggingMiddleware{
			next:   next,
			logger: logger,
		}
	}
}

type loggingMiddleware struct {
	next   UserService
	logger log.Logger
}

/*
SignUp(username, password, confirmPass, email string) (*cogIdp.SignUpOutput, error) // register user
	SignIn(username, password string) (*cogIdp.InitiateAuthOutput, error)               // InitiateAuth or AdminInitiateAuth ? TODO: return token string
	GetUser(username string) (*cogIdp.AdminGetUserOutput, error)                        // AdminGetUser or GetUser ?
	ConfirmSingUp(code, username string) (*cogIdp.ConfirmSignUpOutput, error)
	ForgotPassword(username string) (*cogIdp.ForgotPasswordOutput, error)
	ConfirmForgotPassword(newPass, code, username string) (*cogIdp.ConfirmForgotPasswordOutput, error)
	ChangePassword(accessToken, prevPass, newPass string) (*cogIdp.ChangePasswordOutput, error)
*/

func (mw loggingMiddleware) SignUp(username, password, confirmPass, email string) (*cogIdp.SignUpOutput, error) {
	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "SignUp",
			"username", username,
			"password", "*****",
			"confirmPass", "****",
			"password =? confirmPass", password == confirmPass,
			"email", email,
			"took", time.Since(begin),
		)
	}(time.Now())

	return mw.next.SignUp(username, password, confirmPass, email)
}

func (mw loggingMiddleware) SignIn(username, password string) (*cogIdp.InitiateAuthOutput, error) {

	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "SignIn",
			"username", username,
			"password", "*****",
			"took", time.Since(begin),
		)
	}(time.Now())

	return mw.next.SignIn(username, password)
}

func (mw loggingMiddleware) GetUser(username string) (*cogIdp.AdminGetUserOutput, error) {

	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "GetUser",
			"username", username,
			"took", time.Since(begin),
		)
	}(time.Now())
	return mw.next.GetUser(username)
}

func (mw loggingMiddleware) ConfirmSingUp(code, username string) (*cogIdp.ConfirmSignUpOutput, error) {

	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "ConfirmSingUp",
			"code", code,
			"username", username,
			"took", time.Since(begin),
		)
	}(time.Now())
	return mw.next.ConfirmSingUp(code, username)
}

func (mw loggingMiddleware) ForgotPassword(username string) (*cogIdp.ForgotPasswordOutput, error) {

	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "ForgotPassword",
			"username", username,
			"took", time.Since(begin),
		)
	}(time.Now())
	return mw.next.ForgotPassword(username)
}

func (mw loggingMiddleware) ConfirmForgotPassword(newPass, code, username string) (*cogIdp.ConfirmForgotPasswordOutput, error) {

	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "ConfirmForgotPassword",
			"newPassword", "****",
			"code", code,
			"username", username,
			"took", time.Since(begin),
		)
	}(time.Now())
	return mw.next.ConfirmForgotPassword(newPass, code, username)
}

func (mw loggingMiddleware) ChangePassword(accessToken, prevPass, newPass string) (*cogIdp.ChangePasswordOutput, error) {

	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "ChangePassword",
			"accessToken", "*****",
			"prevPass", "****",
			"newPass", "****",
			"took", time.Since(begin),
		)
	}(time.Now())
	return mw.next.ChangePassword(accessToken, prevPass, newPass)
}

func (mw loggingMiddleware) ValidateJwtToken(token string) (models.AuthenticatedUser, error) {

	defer func(begin time.Time) {
		mw.logger.Log(
			"method", "ValidateJwtToken",
			"token", "*****",
			"took", time.Since(begin),
		)
	}(time.Now())

	return mw.next.ValidateJwtToken(token)
}

// TODO: instrumentation to be added

func MakeJwtCheckMiddleware() endpoint.Middleware {
	return func(next endpoint.Endpoint) endpoint.Endpoint {
		return func(ctx context.Context, request interface{}) (response interface{}, err error) {
			logrus.Infof("logging info from JwtCheckMiddleware....")
			// autho := request.(http.Request)
			// tokens := autho.Header.Get("Authorization")
			logrus.Infof("intercepted! request: %v\n", request)
			return next(ctx, request)
		}
	}
}
