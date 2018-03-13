package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/go-kit/kit/log"
	stdopentracing "github.com/opentracing/opentracing-go"
	stdprometheus "github.com/prometheus/client_golang/prometheus"
	"github.com/rcholic/CognitoREST/api"
)

var (
	port string
	zip  string
)

var (
	HTTPLatency = stdprometheus.NewHistogramVec(stdprometheus.HistogramOpts{
		Name:    "request_duration_seconds",
		Help:    "Time (in seconds) spent serving HTTP requests.",
		Buckets: stdprometheus.DefBuckets,
	}, []string{"method", "route", "status_code", "isWS"})
)

const (
	ServiceName = "user"
)

func init() {
	stdprometheus.MustRegister(HTTPLatency)
	// flag.StringVar(&zip, "zipkin", os.Getenv("ZIPKIN"), "Zipkin address")
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

	var tracer stdopentracing.Tracer
	{
		if zip == "" {
			tracer = stdopentracing.NoopTracer{}
		} else {
			// logger := log.With(logger, "tracer", "Zipkin")
			// logger.Log("addr", zip)
			// collector, err := zipkin.NewHTTPCollector(
			// 	zip,
			// 	zipkin.HTTPLogger(logger),
			// )
			// logger.Log("collector is: %v\n", collector)
			// if err != nil {
			// 	logger.Log("err", err)
			// 	os.Exit(1)
			// }

			// TODO: set up Zipkin tracer server here
			// tracer, err = zipkin.NewTracer(
			// 	zipkin.NewRecorder(collector, false, fmt.Sprintf("%v:%v", host, port), ServiceName),
			// )
			// if err != nil {
			// 	logger.Log("err", err)
			// 	os.Exit(1)
			// }
		}
		stdopentracing.InitGlobalTracer(tracer)
	}

	var service api.UserService
	{
		service = api.NewUserService()
		service = api.LoggingMiddleware(logger)(service)
		// TODO: instrumenting service
	}

	endpoints := api.MakeEndpoints(service, tracer)

	router := api.MakeHTTPHandler(endpoints, logger, tracer)

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
