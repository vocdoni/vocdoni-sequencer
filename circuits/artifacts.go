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
	"sync/atomic"
	"time"

	"github.com/vocdoni/vocdoni-z-sandbox/log"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

// BaseDir is the path where the artifact cache is expected to be found. If the
// artifacts are not found there, they will be downloaded and stored. It can be
// set to a different path if needed from other packages. Defaults to a cache in
// the user home directory.
var BaseDir string

func init() {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		log.Warnf("unable to access user home directory, using temporary directory: %v", err)
		BaseDir = filepath.Join(os.TempDir(), "davinci-artifacts")
	} else {
		BaseDir = filepath.Join(home, ".cache", "davinci-artifacts")
	}
}

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
	content, err := load(k.Hash)
	if err != nil {
		return err
	}
	// return an error if the content is nil
	if content == nil {
		return fmt.Errorf("no content found")
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
	// download the content of the artifact from the remote URL
	return downloadAndStore(ctx, k.Hash, k.RemoteURL)
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

// LoadAll method loads the circuit artifacts into memory.
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

func load(hash []byte) ([]byte, error) {
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
	path := filepath.Join(BaseDir, hex.EncodeToString(hash))
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

	// check if the hash of the content matches the expected hash
	fileHash := sha256.New().Sum(content)
	if !bytes.Equal(fileHash, hash) {
		return nil, fmt.Errorf("hash mismatch for file %s: expected %x, got %x", path, hash, fileHash)
	}

	return content, nil
}

// progressReader wraps an io.Reader and keeps track of the total bytes read.
type progressReader struct {
	reader        io.Reader
	total         int64 // updated atomically
	contentLength int64
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	atomic.AddInt64(&pr.total, int64(n))
	return n, err
}

// downloadAndStore downloads the content of the file from the URL provided,
// checks the hash of the content, logs the progress every 10 seconds, and stores it locally.
// If the file already exists and its hash matches, it does nothing.
func downloadAndStore(ctx context.Context, expectedHash []byte, fileUrl string) error {
	// Validate the file URL.
	if _, err := url.Parse(fileUrl); err != nil {
		return fmt.Errorf("error parsing the file URL provided: %w", err)
	}

	// Build the destination path.
	path := filepath.Join(BaseDir, hex.EncodeToString(expectedHash))
	parentDir := filepath.Dir(path)
	if _, err := os.Stat(parentDir); err != nil {
		return fmt.Errorf("destination path parent folder does not exist")
	}

	// Check if the file already exists.
	if _, err := os.Stat(path); err == nil {
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("error opening existing artifact file: %w", err)
		}
		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			f.Close()
			return fmt.Errorf("error computing hash of existing artifact file: %w", err)
		}
		f.Close()
		if bytes.Equal(h.Sum(nil), expectedHash) {
			log.Debugw("artifact already downloaded and verified", "url", fileUrl, "path", path)
			return nil
		}
		log.Warnw("artifact file exists but hash mismatch, re-downloading", "url", fileUrl, "path", path)
	}

	// Create the HTTP request.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fileUrl, nil)
	if err != nil {
		return fmt.Errorf("error creating the file request: %w", err)
	}

	// Execute the request.
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		if err := res.Body.Close(); err != nil {
			log.Warnf("error closing body response: %v", err)
		}
	}()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("error downloading file %s: http status: %d", fileUrl, res.StatusCode)
	}

	// Create the destination file (os.Create will truncate an existing file).
	fd, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("error creating the artifact file: %w", err)
	}
	defer fd.Close()

	// Create a SHA256 hasher.
	hasher := sha256.New()

	// Wrap the response body with the progressReader.
	pr := &progressReader{
		reader:        res.Body,
		contentLength: res.ContentLength,
	}

	// Write to both the file and the hasher without loading the entire content into memory.
	mw := io.MultiWriter(fd, hasher)

	// Launch the copy in a separate goroutine.
	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(mw, pr)
		done <- err
	}()

	// Set up a ticker to log progress every 10 seconds.
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	// Loop until copy is finished, logging progress periodically.
	for {
		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("error copying data to file: %w", err)
			}
			// Log final progress.
			total := atomic.LoadInt64(&pr.total)
			downloadedMiB := float64(total) / (1024 * 1024)
			var percentage float64
			if pr.contentLength > 0 {
				percentage = (float64(total) / float64(pr.contentLength)) * 100
			}
			log.Debugw("download artifacts completed", "url", fileUrl,
				"downloaded", fmt.Sprintf("%.2fMiB", downloadedMiB),
				"progress", fmt.Sprintf("%.2f%%", percentage))
			goto finished
		case <-ticker.C:
			total := atomic.LoadInt64(&pr.total)
			downloadedMiB := float64(total) / (1024 * 1024)
			var percentage float64
			if pr.contentLength > 0 {
				percentage = (float64(total) / float64(pr.contentLength)) * 100
			}
			log.Debugw("download artifacts", "url", fileUrl,
				"downloaded", fmt.Sprintf("%.2fMiB", downloadedMiB),
				"progress", fmt.Sprintf("%.2f%%", percentage))
		}
	}
finished:

	// Compare the computed hash with the expected one.
	computedHash := hasher.Sum(nil)
	if !bytes.Equal(computedHash, expectedHash) {
		return fmt.Errorf("hash for artifact %s mismatch: expected %x, got %x", fileUrl, expectedHash, computedHash)
	}

	return nil
}
