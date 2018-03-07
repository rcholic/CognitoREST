package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strings"

	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
	stdopentracing "github.com/opentracing/opentracing-go"
	"github.com/sirupsen/logrus"
)

type userCtxKeyType string

const (
	ContextErrorKey userCtxKeyType = "Error"
)

var (
	// ErrInvalidRequest  request error
	ErrInvalidRequest = errors.New("Invalid Request")
	// ErrContextRequest error found in context in field ContextErrorKey
	ErrContextRequest   = errors.New("Context Error")
	userServiceInstance = NewUserService()
)

// MakeHTTPHandler creates routes in the API
func MakeHTTPHandler(e EndPoints, logger log.Logger, tracer stdopentracing.Tracer) *mux.Router {
	r := mux.NewRouter().StrictSlash(false)
	options := []httptransport.ServerOption{
		httptransport.ServerErrorLogger(logger),
		httptransport.ServerErrorEncoder(encodeError),
		httptransport.ServerBefore(before),
		httptransport.ServerAfter(after),
	}

	r.Methods("POST").Path("/user/signup").Handler(httptransport.NewServer(
		e.SignUpEndpoint,
		decodeSignUpRequest,
		encodeResponse,
		options...,
	// append(options, httptransport.ServerBefore(opentracing.FromHTTPRequest(tracer, "POST /user/signup", logger)))...,
	))

	r.Methods("POST").Path("/user/signin").Handler(httptransport.NewServer(
		e.SignInEndpoint,
		decodeSignInRequest,
		encodeResponse,
		options...,
	// append(options, httptransport.ServerBefore(opentracing.FromHTTPRequest(tracer, "POST /user/signin", logger)))...,
	))

	r.Methods("GET").Path("/user/{username}").Handler(httptransport.NewServer(
		e.GetUserEndpoint,
		decodeGetUserRequest,
		encodeResponse,
		options...,
	// append(options, httptransport.ServerBefore(opentracing.FromHTTPRequest(tracer, "GET /user/{username}", logger), validateJwt))..., // require jwt in context
	))

	r.Methods("GET").Path("/user/confirm/{username}/{code}").Handler(httptransport.NewServer(
		e.ConfirmSignUpEndpoint,
		decodeConfirmSignUpRequest,
		encodeResponse,
		options...,
	))

	r.Methods("POST").Path("/user/forgot_password").Handler(httptransport.NewServer(
		e.ForgotPasswordEndpoint,
		decodeForgotPasswordRequest,
		encodeResponse,
		options...,
	))

	r.Methods("POST").Path("/user/reset_password").Handler(httptransport.NewServer(
		e.ConfirmForgotPasswordEndpoint,
		decodeConfirmForgotPasswordRequest,
		encodeResponse,
		options...,
	))

	r.Methods("POST").Path("/user/change_password").Handler(httptransport.NewServer(
		e.ChangePasswordEndpoint,
		decodeChangePasswordRequest,
		encodeResponse,
		options...,
	))

	r.Methods("POST").Path("/user/validate_token").Handler(httptransport.NewServer(
		e.ValidateTokenEndpoint,
		decodeValidateJwtTokenRequest,
		encodeResponse,
		options...,
	))

	return r
}

// ExtractToken extracts jwt token from the header "Authorization" field with Bearer
func ExtractToken(r *http.Request) (string, bool) {

	tokens := r.Header.Get("Authorization")
	if len(tokens) < 8 || !strings.EqualFold(tokens[0:7], "Bearer ") {
		return "", false // empty token
	}

	return tokens[7:], true
}

func decodeValidateJwtTokenRequest(_ context.Context, r *http.Request) (interface{}, error) {
	defer r.Body.Close()
	validateTokenReq := validateTokenRequest{}

	if err := json.NewDecoder(r.Body).Decode(&validateTokenReq); err != nil {
		logrus.Errorf("wrong decoding json in validate jwt token request: %s\n", err)
		return validateTokenReq, ErrInvalidRequest
	}

	return validateTokenReq, nil
}

func decodeChangePasswordRequest(_ context.Context, r *http.Request) (interface{}, error) {

	defer r.Body.Close()
	token, ok := ExtractToken(r)
	changePassRequest := changePasswordRequest{}

	if err := json.NewDecoder(r.Body).Decode(&changePassRequest); err != nil {
		logrus.Errorf("wrong decoding json in change password request: %s\n", err)
		return changePassRequest, ErrInvalidRequest
	}

	if ok {
		changePassRequest.AccessToken = token
	}

	return changePassRequest, nil
}

func decodeConfirmForgotPasswordRequest(_ context.Context, r *http.Request) (interface{}, error) {
	confirmForgotRequest := confirmForgotPasswordRequest{}
	defer r.Body.Close()

	if err := json.NewDecoder(r.Body).Decode(&confirmForgotRequest); err != nil {
		logrus.Errorf("wrong decoding json in confirm forgot password request: %s\n", err)
		return confirmForgotRequest, ErrInvalidRequest
	}
	return confirmForgotRequest, nil
}

func decodeForgotPasswordRequest(_ context.Context, r *http.Request) (interface{}, error) {
	forgotPassRequest := forgotPasswordRequest{}
	defer r.Body.Close()

	if err := json.NewDecoder(r.Body).Decode(&forgotPassRequest); err != nil {
		logrus.Errorf("wrong decoding json in forgot password request: %s\n", err)
		return forgotPassRequest, ErrInvalidRequest
	}
	return forgotPassRequest, nil
}

func decodeConfirmSignUpRequest(_ context.Context, r *http.Request) (interface{}, error) {
	confirmRequest := confirmSignUpRequest{}
	defer r.Body.Close()

	vars := mux.Vars(r)
	code, ok1 := vars["code"]
	username, ok2 := vars["username"]

	if !ok1 || !ok2 {
		return confirmRequest, ErrInvalidRequest
	}
	confirmRequest.Code = code
	confirmRequest.Username = username

	return confirmRequest, nil
}

func decodeGetUserRequest(ctx context.Context, r *http.Request) (interface{}, error) {
	userRequest := getuserRequest{}
	defer r.Body.Close()
	vars := mux.Vars(r)
	username, ok := vars["username"]
	if !ok {
		return userRequest, ErrInvalidRequest
	}
	if contextErr := ctx.Value(ContextErrorKey); contextErr != nil {
		logrus.Warnf("contextErr: %v\n", contextErr)
		return userRequest, ErrContextRequest
	}

	return getuserRequest{Username: username}, nil
}

func decodeSignInRequest(_ context.Context, r *http.Request) (interface{}, error) {
	signinReq := signinRequest{}
	defer r.Body.Close()

	if err := json.NewDecoder(r.Body).Decode(&signinReq); err != nil {
		logrus.Errorf("wrong decoding json in signin: %s\n", err)
		return signinReq, ErrInvalidRequest
	}
	return signinReq, nil
}

func decodeSignUpRequest(_ context.Context, r *http.Request) (interface{}, error) {
	signupReq := signupRequest{}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&signupReq); err != nil {
		logrus.Errorf("wrong decoding json: %s\n", err)
		return signupReq, ErrInvalidRequest
	}

	return signupReq, nil
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	// All of our response objects are JSON serializable, so we just do that.
	w.Header().Set("Content-Type", "application/hal+json")
	return json.NewEncoder(w).Encode(response)
}

// before processing request, make sure jwt auth token is in header
func validateJwt(ctx context.Context, r *http.Request) context.Context {
	token, ok := ExtractToken(r)
	errorMsg := ""
	if !ok {
		errorMsg = "No auth token found;"
	}
	if _, err := userServiceInstance.ValidateJwtToken(token); err != nil {
		errorMsg += fmt.Sprintf("%v;", err)
	}
	if errorMsg != "" {
		ctx = context.WithValue(ctx, ContextErrorKey, errorMsg)
	}

	return ctx
}

func before(ctx context.Context, r *http.Request) context.Context {
	// TODO: put data in ctx,
	return ctx
}

func after(ctx context.Context, w http.ResponseWriter) context.Context {

	// FIXME: how to pass error to encodeError ?
	errorMsg := ctx.Value(ContextErrorKey)
	logrus.Warnf("warning errorMsg in after: %v\n", errorMsg)

	return ctx
}

func encodeError(_ context.Context, err error, w http.ResponseWriter) {
	code := http.StatusInternalServerError
	switch err {
	case ErrUnauthorized:
		code = http.StatusUnauthorized
	}
	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/hal+json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":       err.Error(),
		"status_code": code,
		"status_text": http.StatusText(code),
	})
}

// BindJSON binds request body to the dest struct
func BindJSON(data io.Reader, dest interface{}) error {
	value := reflect.ValueOf(dest)

	if value.Kind() != reflect.Ptr {
		return errors.New("BindJSON not a pointer")
	}

	decoder := json.NewDecoder(data)

	if err := decoder.Decode(dest); err != nil {
		// l4g.Debug(err)
		logrus.Errorf("err: %v\n", err)
		return err
	}

	return nil
}
