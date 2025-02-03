package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/vocdoni/arbo"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

const (
	censusKeyMaxLen = 32
)

var (
	ErrInvalidCensusID        = Error{Code: 40010, HTTPstatus: http.StatusBadRequest, Err: fmt.Errorf("invalid census ID")}
	ErrCensusNotFound         = Error{Code: 40011, HTTPstatus: http.StatusNotFound, Err: fmt.Errorf("census not found")}
	ErrInvalidCensusKeyLength = Error{Code: 40012, HTTPstatus: http.StatusBadRequest, Err: fmt.Errorf("invalid census key length")}
)

type CensusParticipant struct {
	Key    types.HexBytes `json:"key"`
	Weight *types.BigInt  `json:"weight,omitempty"`
}

type CensusParticipants struct {
	Participants []CensusParticipant `json:"participants"`
}

func (a *API) newCensus(w http.ResponseWriter, r *http.Request) {
	censusID := uuid.New()
	_, err := a.storage.CensusDB().New(censusID)
	if err != nil {
		ErrGenericInternalServerError.WithErr(err).Write(w)
		return
	}
	var data []byte
	if data, err = json.Marshal(map[string]uuid.UUID{
		"census": censusID,
	}); err != nil {
		ErrGenericInternalServerError.WithErr(err).Write(w)
		return
	}
	httpWriteJSON(w, data)
}

func (a *API) addCensusParticipants(w http.ResponseWriter, r *http.Request) {
	censusID, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		ErrMalformedBody.WithErr(err).Write(w)
		return
	}

	var participants CensusParticipants
	if err := json.NewDecoder(r.Body).Decode(&participants); err != nil {
		ErrMalformedBody.WithErr(err).Write(w)
		return
	}

	if len(participants.Participants) == 0 {
		ErrMalformedBody.WithErr(fmt.Errorf("no participants provided")).Write(w)
		return
	}

	ref, err := a.storage.CensusDB().Load(censusID)
	if err != nil {
		ErrCensusNotFound.WithErr(err).Write(w)
		return
	}

	// build the list of keys and values that will be added to the tree
	keys := [][]byte{}
	values := [][]byte{}
	for _, p := range participants.Participants {
		if p.Weight == nil {
			p.Weight = new(types.BigInt).SetUint64(1)
		}

		leafKey := p.Key
		if len(leafKey) > censusKeyMaxLen {
			ErrInvalidCensusKeyLength.Withf("the census key cannot be longer than %d bytes", censusKeyMaxLen).Write(w)
			return
		}

		keys = append(keys, leafKey)
		values = append(values, arbo.BigIntToBytes(censusKeyMaxLen, p.Weight.MathBigInt()))
	}

	// insert the keys and values into the tree
	if err := ref.InsertBatch(keys, values); err != nil {
		ErrGenericInternalServerError.WithErr(err).Write(w)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *API) getCensusParticipants(w http.ResponseWriter, r *http.Request) {
	censusID, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		ErrMalformedBody.WithErr(err).Write(w)
		return
	}

	ref, err := a.storage.CensusDB().Load(censusID)
	if err != nil {
		ErrGenericInternalServerError.WithErr(err).Write(w)
		return
	}

	// TODO: Implement pagination properly
	keys := make([][]byte, 0)
	values := make([][]byte, 0)
	err = ref.Tree().Iterate(nil, func(k []byte, v []byte) {
		keys = append(keys, k)
		values = append(values, v)
	})
	if err != nil {
		ErrGenericInternalServerError.WithErr(err).Write(w)
		return
	}

	participants := make([]CensusParticipant, len(keys))
	for i := range keys {
		participants[i] = CensusParticipant{
			Key:    keys[i],
			Weight: (*types.BigInt)(arbo.BytesToBigInt(values[i])),
		}
	}

	data, err := json.Marshal(map[string]interface{}{
		"participants": participants,
	})
	if err != nil {
		ErrGenericInternalServerError.WithErr(err).Write(w)
		return
	}

	httpWriteJSON(w, data)
}

func (a *API) getCensusRoot(w http.ResponseWriter, r *http.Request) {
	censusID, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		ErrInvalidCensusID.WithErr(err).Write(w)
		return
	}

	ref, err := a.storage.CensusDB().Load(censusID)
	if err != nil {
		ErrGenericInternalServerError.WithErr(err).Write(w)
		return
	}

	data, err := json.Marshal(map[string]types.HexBytes{
		"root": types.HexBytes(ref.Root()),
	})
	if err != nil {
		ErrGenericInternalServerError.WithErr(err).Write(w)
		return
	}

	httpWriteJSON(w, data)
}

func (a *API) getCensusSize(w http.ResponseWriter, r *http.Request) {
	censusID, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		ErrInvalidCensusID.WithErr(err).Write(w)
		return
	}

	ref, err := a.storage.CensusDB().Load(censusID)
	if err != nil {
		ErrGenericInternalServerError.WithErr(err).Write(w)
		return
	}

	data, err := json.Marshal(map[string]int{
		"size": ref.Size(),
	})
	if err != nil {
		ErrGenericInternalServerError.WithErr(err).Write(w)
		return
	}

	httpWriteJSON(w, data)
}

func (a *API) deleteCensus(w http.ResponseWriter, r *http.Request) {
	censusID, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		ErrInvalidCensusID.WithErr(err).Write(w)
		return
	}

	if err := a.storage.CensusDB().Del(censusID); err != nil {
		ErrGenericInternalServerError.WithErr(err).Write(w)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (a *API) getCensusProof(w http.ResponseWriter, r *http.Request) {
	rootHex := r.URL.Query().Get("root")
	root, err := hex.DecodeString(rootHex)
	if err != nil {
		ErrInvalidCensusID.WithErr(err).Write(w)
		return
	}

	keyHex := r.URL.Query().Get("key")
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		ErrMalformedBody.WithErr(err).Write(w)
		return
	}

	proof, err := a.storage.CensusDB().ProofByRoot(root, key)
	if err != nil {
		ErrResourceNotFound.WithErr(err).Write(w)
		return
	}

	httpWriteJSON(w, proof)
}
