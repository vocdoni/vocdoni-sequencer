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
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
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
	db      db.Database
}

// New creates a new API instance with the given configuration.
// It also initializes the storage and starts the HTTP server.
func New(conf *APIConfig) (*API, error) {
	if conf == nil {
		return nil, fmt.Errorf("missing API configuration")
	}

	database, err := metadb.New(db.TypePebble, conf.DataDir)
	if err != nil {
		return nil, err
	}

	storage := stg.New(database)

	a := &API{
		storage: storage,
		db:      database,
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

// registerHandlers registers all the API handlers.
func (a *API) registerHandlers() {
	log.Infow("register handler", "endpoint", PingEndpoint, "method", "GET")
	a.router.Get(PingEndpoint, func(w http.ResponseWriter, r *http.Request) {
		httpWriteOK(w)
	})
	log.Infow("register handler", "endpoint", ProcessesEndpoint, "method", "POST")
	a.router.Post(ProcessEndpoint, a.newProcess)
	log.Infow("register handler", "endpoint", ProcessEndpoint, "method", "GET")
	a.router.Get(ProcessEndpoint, a.process)
	log.Infow("register handler", "endpoint", VotesEndpoint, "method", "POST")
	a.router.Post(VotesEndpoint, a.newVote)

	if testAvailable {
		log.Infow("register test handler", "endpoint", TestProcessEndpoint, "method", "POST")
		a.router.Post(TestProcessEndpoint, a.newVote)
	}
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
