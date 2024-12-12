package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/vocdoni/vocdoni-z-sandbox/log"
	stg "github.com/vocdoni/vocdoni-z-sandbox/storage"
)

// APIConfig type represents the configuration for the API HTTP server.
// It includes the host, port and the data directory.
type APIConfig struct {
	Host    string
	Port    int
	DataDir string
}

// API type represents the API HTTP server with JWT authentication capabilities.
type API struct {
	router  *chi.Mux
	storage *stg.Storage
}

// New creates a new API HTTP server. It does not start the server. Use Start() for that.
func New(conf *APIConfig) (*API, error) {
	if conf == nil {
		return nil, fmt.Errorf("missing API configuration")
	}
	storage, err := stg.NewStorage(conf.DataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage in datadir %s: %w", conf.DataDir, err)
	}
	a := &API{
		storage: storage,
	}
	go func() {
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", conf.Host, conf.Port), a.initRouter()); err != nil {
			log.Fatalf("failed to start the API server: %v", err)
		}
	}()
	return a, nil
}

// registerHandlers registers all the API handlers.
func (a *API) registerHandlers() {
	a.router.Post(newProcessEndpoint, a.newProcess)
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
		httpWriteOK(w)
	})
	// Register the API handlers
	a.registerHandlers()
	// Return the router
	return a.router
}
