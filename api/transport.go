package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"

	"github.com/go-kit/kit/log"
	httptransport "github.com/go-kit/kit/transport/http"
	"github.com/gorilla/mux"
)

var (
	// ErrInvalidRequest  request error
	ErrInvalidRequest = errors.New("Invalid Request")
)

func MakeHTTPHandler(e EndPoints, logger log.Logger) *mux.Router {
	r := mux.NewRouter().StrictSlash(false)
	options := []httptransport.ServerOption{
		httptransport.ServerErrorLogger(logger),
		httptransport.ServerErrorEncoder(encodeError),
	}

	r.Methods("POST").Path("/signup").Handler(httptransport.NewServer(
		e.SignUpEndpoint,
		decodeSignUpRequest,
		encodeResponse,
		options...,
	))

	r.Methods("POST").Path("/signin").Handler(httptransport.NewServer(
		e.SignInEndpoint,
		decodeSignInRequest,
		encodeResponse,
		options...,
	))

	r.Methods("GET").Path("/user/{username}").Handler(httptransport.NewServer(
		e.GetUserEndpoint,
		decodeGetUserRequest,
		encodeResponse,
		options...,
	))

	return r
}

func decodeGetUserRequest(_ context.Context, r *http.Request) (interface{}, error) {
	userRequest := getuserRequest{}
	defer r.Body.Close()
	vars := mux.Vars(r)
	username, ok := vars["username"]

	if !ok {
		// TODO: logging
		return userRequest, ErrInvalidRequest
	}

	return getuserRequest{Username: username}, nil
}

func decodeSignInRequest(_ context.Context, r *http.Request) (interface{}, error) {
	reqBody := signinRequest{}
	defer r.Body.Close()

	// if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {

	// }
	var props map[string]string

	err := BindJSON(r.Body, &props)
	if err != nil {
		return reqBody, err
	}
	email, ok1 := props["email"]
	password, ok2 := props["password"]
	if !ok1 || !ok2 {
		return reqBody, ErrInvalidRequest
	}
	reqBody.Email = email
	reqBody.Password = password

	return reqBody, err
}

func decodeSignUpRequest(_ context.Context, r *http.Request) (interface{}, error) {
	signupReq := signupRequest{}
	defer r.Body.Close()
	if err := json.NewDecoder(r.Body).Decode(&signupReq); err != nil {
		fmt.Println("wrong decoding json...")
		return signupReq, ErrInvalidRequest
	}

	return signupReq, nil
}

func encodeResponse(_ context.Context, w http.ResponseWriter, response interface{}) error {
	// All of our response objects are JSON serializable, so we just do that.
	w.Header().Set("Content-Type", "application/hal+json")
	return json.NewEncoder(w).Encode(response)
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
		fmt.Printf("err: %v\n", err)
		return err
	}

	return nil
}