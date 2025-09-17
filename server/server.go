package server

import (
	"bytes"
	"encoding/base64"
	"net/http"

	"github.com/BlockPILabs/aggregator/config"
	"github.com/BlockPILabs/aggregator/log"
	"github.com/BlockPILabs/aggregator/middleware"
	"github.com/BlockPILabs/aggregator/notify"
	"github.com/BlockPILabs/aggregator/rpc"
	"github.com/fasthttp/router"
	"github.com/valyala/fasthttp"
)

var (
	logger = log.Module("server")
)

var requestHandler = func(ctx *fasthttp.RequestCtx) {
	defer func() {
		if err := recover(); err != nil {
			logger.Error("error", "msg", err)
		}
	}()

	var err error

	session := &rpc.Session{RequestCtx: ctx}
	err = session.Init()
	if err != nil {
		ctx.Error(string(session.NewJsonRpcError(err).Marshal()), fasthttp.StatusOK)
		return
	}
	for {
		session.Tries++
		err = middleware.OnRequest(session)
		if err != nil {
			if session.IsMaxRetriesExceeded() {
				ctx.Error(string(session.NewJsonRpcError(err).Marshal()), fasthttp.StatusOK)
				return
			}
			continue
		}

		err = middleware.OnProcess(session)
		if err != nil {
			if session.IsMaxRetriesExceeded() {
				ctx.Error(string(session.NewJsonRpcError(err).Marshal()), fasthttp.StatusOK)
				return
			}
			continue
		}

		err = middleware.OnResponse(session)
		if err != nil {
			if session.IsMaxRetriesExceeded() {
				ctx.Error(string(session.NewJsonRpcError(err).Marshal()), fasthttp.StatusOK)
				return
			}
			continue
		}
		return
	}
}

func NewServer() error {
	var err error
	addr := ":8011"
	logger.Info("Starting unified server (RPC + Management)", "addr", addr)

	for _, chain := range config.Chains() {
		logger.Info("Registered RPC", "endpoint", "http://localhost:8011/"+chain)
	}

	// Set up management routes
	r := router.New()
	r.PanicHandler = func(ctx *fasthttp.RequestCtx, err interface{}) {
		ctx.Error("Internal server error", fasthttp.StatusInternalServerError)
	}

	r.GET("/", RootHandler)
	r.GET("/status", StatusHandler)
	r.GET("/config", RouteConfigHandler)
	r.POST("/config", RouteUpdateConfigHandler)
	r.POST("/config/restore", RouteRestoreConfigHandler)

	// Unified handler that routes between RPC and management endpoints
	unifiedHandler := func(ctx *fasthttp.RequestCtx) {
		defer func() {
			if err := recover(); err != nil {
				logger.Error("error", "msg", err)
			}
		}()

		// Set CORS headers for all requests
		ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
		ctx.Response.Header.Set("Access-Control-Allow-Methods", "POST, GET, PUT, DELETE, OPTIONS")
		ctx.Response.Header.Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Token, Authorization")
		ctx.Response.Header.Set("Access-Control-Allow-Credentials", "true")

		if string(ctx.Method()) == "OPTIONS" {
			ctx.Response.Header.Set("Access-Control-Max-Age", "86400")
			ctx.SetStatusCode(http.StatusOK)
			ctx.SetBodyString("ok")
			return
		}

		path := string(ctx.Request.URI().Path())

		// Check if this is a management endpoint
		if path == "/" || path == "/status" || path == "/config" || path == "/config/restore" {
			// Handle status endpoint without auth
			if path == "/status" {
				r.Handler(ctx)
				return
			}

			// For other management endpoints, check authentication
			auth := ctx.Request.Header.Peek("Authorization")
			if bytes.HasPrefix(auth, BasicAuthPrefix) {
				payload, err := base64.StdEncoding.DecodeString(string(auth[len(BasicAuthPrefix):]))
				if err == nil {
					pair := bytes.SplitN(payload, []byte(":"), 2)
					if len(pair) == 2 && bytes.Equal(pair[0], []byte("rpchub")) && bytes.Equal(pair[1], []byte(config.Default().Password)) {
						config.Default().Mrt += 1
						config.Save()
						r.Handler(ctx)
						return
					}
				}
			}
			ctx.Error("Unauthorized", fasthttp.StatusUnauthorized)
			return
		}

		// Handle RPC requests for all other paths
		requestHandler(ctx)
	}

	s := &fasthttp.Server{
		Handler:            fasthttp.CompressHandlerLevel(unifiedHandler, 6),
		MaxRequestBodySize: fasthttp.DefaultMaxRequestBodySize * 10,
	}

	err = s.ListenAndServe(addr)
	if err != nil {
		notify.SendError("Error start unified server.", err.Error())
		return err
	}
	return nil
}
