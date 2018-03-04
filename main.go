package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/kit/log"
	"github.com/rcholic/CognitoREST/api"
)

var (
	port string
)

func init() {
	flag.StringVar(&port, "port", "3000", "Port on which to run")
}

func main() {
	flag.Parse()

	errc := make(chan error)

	// Log domain.
	var logger log.Logger
	{
		logger = log.NewLogfmtLogger(os.Stderr)
		logger = log.With(logger, "ts", log.DefaultTimestampUTC)
		logger = log.With(logger, "caller", log.DefaultCaller)
	}

	var service api.UserService
	{
		service = api.NewUserService()
		service = api.LoggingMiddleware(logger)(service)
		// TODO: instrumenting service
	}

	endpoints := api.MakeEndpoints(service)

	router := api.MakeHTTPHandler(endpoints, logger)

	go func() {
		logger.Log("transport", "HTTP", "port", port)
		errc <- http.ListenAndServe(fmt.Sprintf(":%v", port), router)
	}()

	// Capture interrupts.
	go func() {
		c := make(chan os.Signal)
		signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
		errc <- fmt.Errorf("%s", <-c)
	}()

	logger.Log("exit", <-errc)
}

// SPA authentication: https://onedrive.live.com/?authkey=%21AAPTU-jr3dRC4XY&cid=01965DB52C0BCA35&id=1965DB52C0BCA35%211660&parId=1965DB52C0BCA35%211658&o=OneUp
// https://github.com/IdentityServer/IdentityServer3/issues/2039
// video: https://vimeo.com/131636653
