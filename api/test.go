package api

import (
	"net/http"
	"os"

	"github.com/vocdoni/arbo"
	"github.com/vocdoni/arbo/memdb"
	"github.com/vocdoni/vocdoni-z-sandbox/state"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

var tree *arbo.Tree
var testAvailable bool

func init() {
	if os.Getenv("TEST_API") == "true" || os.Getenv("TEST_API") == "1" {
		var err error
		tree, err = arbo.NewTree(arbo.Config{
			Database:     memdb.New(),
			MaxLevels:    types.CensusTreeMaxLevels,
			HashFunction: state.HashFunc,
		})
		if err != nil {
			panic(err)
		}
		testAvailable = true
	}
}

func (a *API) setProcessInfoForTest(w http.ResponseWriter, r *http.Request) {
	if !testAvailable {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}
}

func (a *API) processInfoForTest(w http.ResponseWriter, r *http.Request) {
	if !testAvailable {
		http.Error(w, "not available", http.StatusServiceUnavailable)
		return
	}
}
