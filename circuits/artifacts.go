package circuits

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

const downloadCircuitsTimeout = time.Minute * 5

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
	Hash      types.HexBytes
	Content   types.HexBytes
}

// Load method checks if the key content is already loaded, if not, it will
// try to load it from the local cache or download it from the remote URL
// provided. If the content is downloaded, it will be stored locally. It also
// checks the hash of the content to ensure its integrity. If the key is not
// already loaded, it returns an error if the hash is not provided, the remote
// URL is not provided, or the content cannot be loaded locally, downloaded or
// written to a local file. It also returns an error if the hash of the content
// does not match the hash provided.
func (k *Artifact) Load(ctx context.Context) error {
	// if the key has content, it is already loaded and it will return
	if len(k.Content) != 0 {
		return nil
	}
	// if the key has no content, it must have its hash set to check the
	// content when it is loaded
	if len(k.Hash) == 0 {
		return fmt.Errorf("key hash not provided")
	}
	// create a flag to check if the content should be written to a local
	// file or not
	shouldBeWritten := false
	// check if the content is already stored locally by hash and load it
	content, err := loadLocal(k.Hash.String())
	if err != nil {
		return err
	}
	// if the content is not stored locally, it must be downloaded
	if content == nil {
		// if the remote url is not provided, the key cannot be loaded so
		// it will return an error
		if k.RemoteURL == "" {
			return fmt.Errorf("key not loaded and remote url not provided")
		}
		// download the content from the remote url
		if content, err = loadRemote(ctx, k.RemoteURL); err != nil {
			return err
		}
		// mark the content to be written to a local file
		shouldBeWritten = true
	}
	// check the hash of the loaded content
	if err := checkHash(content, k.Hash); err != nil {
		return err
	}
	k.Content = content
	// if the content should be written, store it locally
	if shouldBeWritten {
		if err := storeLocal(content, k.Hash.String()); err != nil {
			return err
		}
	}
	return nil
}

// CircuitArtifacts is a struct that holds the proving and verifying keys of a
// zkSNARK circuit. It provides a method to load the keys from the local cache
// or download them from the remote URLs provided.
type CircuitArtifacts struct {
	circuitDefinition *Artifact
	provingKey        *Artifact
	verifyingKey      *Artifact
}

// NewCircuitArtifacts creates a new CircuitArtifacts struct with the proving
// and verifying keys provided.
func NewCircuitArtifacts(circuit, provingKey, verifyingKey *Artifact) *CircuitArtifacts {
	return &CircuitArtifacts{
		circuitDefinition: circuit,
		provingKey:        provingKey,
		verifyingKey:      verifyingKey,
	}
}

// LoadAll method loads the proving and verifying keys creating a context with
// a timeout of 5 minutes. It returns an error if the proving or verifying keys
// cannot be loaded.
func (ca *CircuitArtifacts) LoadAll() error {
	ctx, cancel := context.WithTimeout(context.Background(), downloadCircuitsTimeout)
	defer cancel()
	if ca.circuitDefinition != nil {
		if err := ca.circuitDefinition.Load(ctx); err != nil {
			return fmt.Errorf("error loading circuit definition: %w", err)
		}
	}
	if ca.provingKey != nil {
		if err := ca.provingKey.Load(ctx); err != nil {
			return fmt.Errorf("error loading proving key: %w", err)
		}
	}
	if ca.verifyingKey != nil {
		if err := ca.verifyingKey.Load(ctx); err != nil {
			return fmt.Errorf("error loading verifying key: %w", err)
		}
	}
	return nil
}

// CircuitDefinition returns the content of the circuit definition as types.HexBytes.
// If the circuit definition is not loaded, it returns nil.
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

func loadLocal(name string) ([]byte, error) {
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

func loadRemote(ctx context.Context, fileUrl string) ([]byte, error) {
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

func storeLocal(content []byte, name string) error {
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
