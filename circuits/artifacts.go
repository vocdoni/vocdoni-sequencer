package circuits

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// BaseDir is the path where the artifact cache is expected to be found. If the
// artifacts are not found there, they will be downloaded and stored. It can be
// set to a different path if needed from other packages. Thats why it is not a
// constant.
//
// Defaults to '.cache/circuits-artifacts'
var BaseDir = filepath.Join(".cache", "circuits-artifacts")

// Artifact is a struct that holds the remote URL, the hash of the content and
// the content itself. It provides a method to load the content from the local
// cache or download it from the remote URL provided. It also checks the hash
// of the content to ensure its integrity.
type Artifact struct {
	RemoteURL string
	Hash      []byte
	Content   []byte
}

// Load method checks if the artifact content is already loaded, if not, it will
// try to load it from the local storage. It also checks the hash of the content
// to ensure its integrity. It returns an error if the artifact is already
// loaded but the hash is not set or it does not match with the content.
func (k *Artifact) Load() error {
	// if the artifact has content, it is already loaded and it will return
	if len(k.Content) != 0 {
		return nil
	}
	// if the artifact has no content, it must have its hash set to check the
	// content when it is loaded
	if len(k.Hash) == 0 {
		return fmt.Errorf("key hash not provided")
	}
	// check if the content is already stored locally by hash and load it
	content, err := load(hex.EncodeToString(k.Hash))
	if err != nil {
		return err
	}
	// return an error if the content is nil
	if content == nil {
		return fmt.Errorf("no content found")
	}
	// check the hash of the loaded content
	if err := checkHash(content, k.Hash); err != nil {
		return err
	}
	// set the content of the artifact
	k.Content = content
	return nil
}

// Download method downloads the content of the artifact from the remote URL,
// checks the hash of the content and stores it locally. It returns an error if
// the remote URL is not provided or the content cannot be downloaded, or if the
// hash of the content does not match. If the content is already loaded, it will
// return.
func (k *Artifact) Download(ctx context.Context) error {
	// if the remote url is not provided, the artifact cannot be loaded so
	// it will return an error
	if k.RemoteURL == "" {
		return fmt.Errorf("key not loaded and remote url not provided")
	}
	// if the artifact is already loaded, it will return
	if err := k.Load(); err == nil {
		return nil
	}

	// download the content from the remote url
	content, err := download(ctx, k.RemoteURL)
	if err != nil {
		return err
	}
	// check the hash of the loaded content
	if err := checkHash(content, k.Hash); err != nil {
		return err
	}
	return store(content, hex.EncodeToString(k.Hash))
}

// CircuitArtifacts is a struct that holds the artifacts of a zkSNARK circuit
// (definition, proving and verification key). It provides a method to load the
// keys from the local cache or download them from the remote URLs provided.
type CircuitArtifacts struct {
	circuitDefinition *Artifact
	provingKey        *Artifact
	verifyingKey      *Artifact
}

// NewCircuitArtifacts creates a new CircuitArtifacts struct with the circuit
// artifacts provided. It returns the struct with the artifacts set.
func NewCircuitArtifacts(circuit, provingKey, verifyingKey *Artifact) *CircuitArtifacts {
	return &CircuitArtifacts{
		circuitDefinition: circuit,
		provingKey:        provingKey,
		verifyingKey:      verifyingKey,
	}
}

// LoadAll method loads the circuit artifacts creating a context with a timeout
// of 5 minutes. It returns an error if the proving or verifying keys cannot be
// loaded.
func (ca *CircuitArtifacts) LoadAll() error {
	if ca.circuitDefinition != nil {
		if err := ca.circuitDefinition.Load(); err != nil {
			return fmt.Errorf("error loading circuit definition: %w", err)
		}
	}
	if ca.provingKey != nil {
		if err := ca.provingKey.Load(); err != nil {
			return fmt.Errorf("error loading proving key: %w", err)
		}
	}
	if ca.verifyingKey != nil {
		if err := ca.verifyingKey.Load(); err != nil {
			return fmt.Errorf("error loading verifying key: %w", err)
		}
	}
	return nil
}

// DownloadAll method downloads the circuit artifacts with the provided context.
// It returns an error if any of the artifacts cannot be downloaded.
func (ca *CircuitArtifacts) DownloadAll(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	if err := ca.circuitDefinition.Download(ctx); err != nil {
		return fmt.Errorf("error downloading circuit definition: %w", err)
	}
	if err := ca.provingKey.Download(ctx); err != nil {
		return fmt.Errorf("error downloading proving key: %w", err)
	}
	if err := ca.verifyingKey.Download(ctx); err != nil {
		return fmt.Errorf("error downloading verifying key: %w", err)
	}
	return nil
}

// CircuitDefinition returns the content of the circuit definition as
// types.HexBytes. If the circuit definition is not loaded, it returns nil.
func (ca *CircuitArtifacts) CircuitDefinition() types.HexBytes {
	if ca.circuitDefinition == nil {
		return nil
	}
	return ca.circuitDefinition.Content
}

// ProvingKey returns the content of the proving key as types.HexBytes. If the
// proving key is not loaded, it returns nil.
func (ca *CircuitArtifacts) ProvingKey() types.HexBytes {
	if ca.provingKey == nil {
		return nil
	}
	return ca.provingKey.Content
}

// VerifyingKey returns the content of the verifying key as types.HexBytes. If the
// verifying key is not loaded, it returns nil.
func (ca *CircuitArtifacts) VerifyingKey() types.HexBytes {
	if ca.verifyingKey == nil {
		return nil
	}
	return ca.verifyingKey.Content
}

func load(name string) ([]byte, error) {
	// check if BaseDir exists and create it if it does not
	if _, err := os.Stat(BaseDir); err != nil {
		if os.IsNotExist(err) {
			if err := os.MkdirAll(BaseDir, os.ModePerm); err != nil {
				return nil, fmt.Errorf("error creating the base directory: %w", err)
			}
		} else {
			return nil, fmt.Errorf("error checking the base directory: %w", err)
		}
	}
	// append the name to the base directory and check if the file exists
	path := filepath.Join(BaseDir, name)
	if _, err := os.Stat(path); err != nil {
		// if the file does not exists return nil content and nil error, but if
		// the error is not a not exists error, return the error
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("error checking file %s: %w", path, err)
	}
	// if it exists, read the content of the file and return it
	content, err := os.ReadFile(path)
	if err != nil {
		if err == os.ErrNotExist {
			return nil, nil
		}
		return nil, fmt.Errorf("error reading file %s: %w", path, err)
	}
	return content, nil
}

func download(ctx context.Context, fileUrl string) ([]byte, error) {
	if _, err := url.Parse(fileUrl); err != nil {
		return nil, fmt.Errorf("error parsing the file URL provided: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("error creating the file request: %w", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Warnf("error closing body response %v", err)
		}
	}()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error on download file %s: http status: %d", fileUrl, res.StatusCode)
	}
	content, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading the file content from the http response: %w", err)
	}
	return content, nil
}

func checkHash(content, expected []byte) error {
	if content == nil {
		return fmt.Errorf("no content provided to check")
	}
	if expected == nil {
		return fmt.Errorf("no hash provided to compare")
	}
	hash := sha256.New()
	if _, err := hash.Write(content); err != nil {
		return fmt.Errorf("error computing hash function of %s: %w", content, err)
	}
	if !bytes.Equal(hash.Sum(nil), expected) {
		return fmt.Errorf("hash mismatch")
	}
	return nil
}

func store(content []byte, name string) error {
	path := filepath.Join(BaseDir, name)
	if content == nil {
		return fmt.Errorf("no content provided")
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		return fmt.Errorf("destination path parent folder does not exist")
	}
	fd, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error creating the artifact file: %w", err)
	}
	if _, err := fd.Write(content); err != nil {
		return fmt.Errorf("error writing the artifact file: %w", err)
	}
	return nil
}
