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
// It includes the host, port and optionally an existing storage instance.
type APIConfig struct {
	Host    string
	Port    int
	Storage *stg.Storage // Optional: use existing storage instance
}

// API type represents the API HTTP server with JWT authentication capabilities.
type API struct {
	router  *chi.Mux
	storage *stg.Storage
}

// New creates a new API instance with the given configuration.
// It also initializes the storage and starts the HTTP server.
func New(conf *APIConfig) (*API, error) {
	if conf == nil {
		return nil, fmt.Errorf("missing API configuration")
	}
	if conf.Storage == nil {
		return nil, fmt.Errorf("missing storage instance")
	}
	a := &API{
		storage: conf.Storage,
	}

	// Initialize router
	a.initRouter()
	go func() {
		log.Infow("Starting API server", "host", conf.Host, "port", conf.Port)
		if err := http.ListenAndServe(fmt.Sprintf("%s:%d", conf.Host, conf.Port), a.router); err != nil {
			log.Fatalf("failed to start the API server: %v", err)
		}
	}()
	return a, nil
}

// Router returns the chi router for testing purposes
func (a *API) Router() *chi.Mux {
	return a.router
}

// registerHandlers registers all the HTTP handlers for the API endpoints.
func (a *API) registerHandlers() {
	// The following endpoints are registered:
	// - GET /ping: No parameters
	// - POST /process: No parameters
	// - GET /process: No parameters
	// - POST /census: No parameters
	// - POST /census/participants?id=<uuid>: Parameters: id
	// - GET /census/participants?id=<uuid>: Parameters: id
	// - GET /census/root?id=<uuid>: Parameters: id
	// - GET /census/size?id=<uuid>: Parameters: id
	// - DELETE /census?id=<uuid>: Parameters: id
	// - GET /census/proof?id=<uuid>&key=<key>: Parameters: id, key
	log.Infow("register handler", "endpoint", PingEndpoint, "method", "GET")
	a.router.Get(PingEndpoint, func(w http.ResponseWriter, r *http.Request) {
		httpWriteOK(w)
	})
	log.Infow("register handler", "endpoint", ProcessEndpoint, "method", "POST")
	a.router.Post(ProcessEndpoint, a.newProcess)
	log.Infow("register handler", "endpoint", ProcessEndpoint, "method", "GET")
	a.router.Get(ProcessEndpoint, a.process)

	// Census endpoints
	log.Infow("register handler", "endpoint", NewCensusEndpoint, "method", "POST")
	a.router.Post(NewCensusEndpoint, a.newCensus)
	log.Infow("register handler", "endpoint", AddCensusParticipantsEndpoint, "method", "POST", "parameters", "id")
	a.router.Post(AddCensusParticipantsEndpoint, a.addCensusParticipants)
	log.Infow("register handler", "endpoint", GetCensusParticipantsEndpoint, "method", "GET", "parameters", "id")
	a.router.Get(GetCensusParticipantsEndpoint, a.getCensusParticipants)
	log.Infow("register handler", "endpoint", GetCensusRootEndpoint, "method", "GET", "parameters", "id")
	a.router.Get(GetCensusRootEndpoint, a.getCensusRoot)
	log.Infow("register handler", "endpoint", GetCensusSizeEndpoint, "method", "GET", "parameters", "id")
	a.router.Get(GetCensusSizeEndpoint, a.getCensusSize)
	log.Infow("register handler", "endpoint", DeleteCensusEndpoint, "method", "DELETE", "parameters", "id")
	a.router.Delete(DeleteCensusEndpoint, a.deleteCensus)
	log.Infow("register handler", "endpoint", GetCensusProofEndpoint, "method", "GET", "parameters", "id, key")
	a.router.Get(GetCensusProofEndpoint, a.getCensusProof)

}

// initRouter creates the router with all the routes and middleware.
func (a *API) initRouter() {
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

	// Register the API handlers
	a.registerHandlers()
}
