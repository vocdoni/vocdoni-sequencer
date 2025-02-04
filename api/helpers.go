package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vocdoni/vocdoni-z-sandbox/log"
)

// httpWriteJSON helper function allows to write a JSON response.
func httpWriteJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	jdata, err := json.Marshal(data)
	if err != nil {
		ErrMarshalingServerJSONFailed.WithErr(err).Write(w)
		return
	}
	n, err := w.Write(jdata)
	if err != nil {
		log.Warnw("failed to write http response", "error", err)
	}
	if _, err := w.Write([]byte("\n")); err != nil {
		log.Warnw("failed to write on response", "error", err)
	}
	log.Debugw("api response", "bytes", n, "data", strings.ReplaceAll(string(jdata), "\"", ""))
}

// httpWriteOK helper function allows to write an OK response.
func httpWriteOK(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("\n")); err != nil {
		log.Warnw("failed to write on response", "error", err)
	}
}
