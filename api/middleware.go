package api

import (
	"context"
	"time"

	cogIdp "github.com/aws/aws-sdk-go/service/cognitoidentityprovider"
	"github.com/go-kit/kit/endpoint"
	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/metrics"
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
type instrumentingService struct {
	requestCount   metrics.Counter
	requestLatency metrics.Histogram
	UserService
}

// NewInstrumentingService returns an instance of an instrumenting UserService.
func NewInstrumentingService(requestCount metrics.Counter, requestLatency metrics.Histogram, s UserService) UserService {
	return &instrumentingService{
		requestCount:   requestCount,
		requestLatency: requestLatency,
		UserService:    s,
	}
}

func (s *instrumentingService) SignUp(username, password, confirmPass, email string) (*cogIdp.SignUpOutput, error) {

	defer func(begin time.Time) {
		s.requestCount.With("method", "SignUp").Add(1)
		s.requestLatency.With("method", "SignUp").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.UserService.SignUp(username, password, confirmPass, email)
}

func (s *instrumentingService) SignIn(username, password string) (*cogIdp.InitiateAuthOutput, error) {

	defer func(begin time.Time) {
		s.requestCount.With("method", "SignIn").Add(1)
		s.requestLatency.With("method", "SignIn").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.UserService.SignIn(username, password)
}

func (s *instrumentingService) GetUser(username string) (*cogIdp.AdminGetUserOutput, error) {

	defer func(begin time.Time) {
		s.requestCount.With("method", "GetUser").Add(1)
		s.requestLatency.With("method", "GetUser").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.UserService.GetUser(username)
}

func (s *instrumentingService) ConfirmSingUp(code, username string) (*cogIdp.ConfirmSignUpOutput, error) {

	defer func(begin time.Time) {
		s.requestCount.With("method", "ConfirmSingUp").Add(1)
		s.requestLatency.With("method", "ConfirmSingUp").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.UserService.ConfirmSingUp(code, username)
}

func (s *instrumentingService) ForgotPassword(username string) (*cogIdp.ForgotPasswordOutput, error) {

	defer func(begin time.Time) {
		s.requestCount.With("method", "ForgotPassword").Add(1)
		s.requestLatency.With("method", "ForgotPassword").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.UserService.ForgotPassword(username)
}

func (s *instrumentingService) ConfirmForgotPassword(newPass, code, username string) (*cogIdp.ConfirmForgotPasswordOutput, error) {

	defer func(begin time.Time) {
		s.requestCount.With("method", "ConfirmForgotPassword").Add(1)
		s.requestLatency.With("method", "ConfirmForgotPassword").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.UserService.ConfirmForgotPassword(newPass, code, username)
}

func (s *instrumentingService) ChangePassword(accessToken, prevPass, newPass string) (*cogIdp.ChangePasswordOutput, error) {

	defer func(begin time.Time) {
		s.requestCount.With("method", "ChangePassword").Add(1)
		s.requestLatency.With("method", "ChangePassword").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.UserService.ChangePassword(accessToken, prevPass, newPass)
}

func (s *instrumentingService) ValidateJwtToken(token string) (models.AuthenticatedUser, error) {

	defer func(begin time.Time) {
		s.requestCount.With("method", "ValidateJwtToken").Add(1)
		s.requestLatency.With("method", "ValidateJwtToken").Observe(time.Since(begin).Seconds())
	}(time.Now())

	return s.UserService.ValidateJwtToken(token)
}

// FIXME: this is not being used... TO BE DELETED
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
