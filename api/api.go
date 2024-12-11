package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
)

type APIConfig struct {
	Host string
	Port int
}

// API type represents the API HTTP server with JWT authentication capabilities.
type API struct {
	host   string
	port   int
	router *chi.Mux
}

// New creates a new API HTTP server. It does not start the server. Use Start() for that.
func New(conf *APIConfig) *API {
	if conf == nil {
		return nil
	}
	return &API{
		host: conf.Host,
		port: conf.Port,
	}
}

// Start starts the API HTTP server (non blocking).
func (a *API) Start() {
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", a.host, a.port), a.initRouter()); err != nil {
			log.Fatalf("failed to start the API server: %v", err)
		}
	}()
}

// router creates the router with all the routes and middleware.
func (a *API) initRouter() http.Handler {
	// Create the router with a basic middleware stack
	a.router = chi.NewRouter()
	a.router.Use(cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           300, // Maximum value not ignored by any of major browsers
	}).Handler)
	a.router.Use(middleware.Logger)
	a.router.Use(middleware.Recoverer)
	a.router.Use(middleware.Throttle(100))
	a.router.Use(middleware.ThrottleBacklog(5000, 40000, 60*time.Second))
	a.router.Use(middleware.Timeout(45 * time.Second))
	// Routes
	a.router.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(".")); err != nil {
			log.Warnw("failed to write ping response", "error", err)
		}
	})
	// Return the router
	return a.router
}
