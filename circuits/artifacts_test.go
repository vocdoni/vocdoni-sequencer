package circuits

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	qt "github.com/frankban/quicktest"
)

var (
	dummyPath       = "dummy.key"
	dummyKeyContent = []byte("dummy content")
)

func testDummyKeyServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, dummyPath, time.Now(), bytes.NewReader(dummyKeyContent))
	}))
}

func TestMain(m *testing.M) {
	// set BaseDir to a temporary directory and create it
	tempDir, err := os.MkdirTemp("", "circuits_artifacts_")
	if err != nil {
		panic(fmt.Errorf("failed to create temporary base directory: %v", err))
	}
	// Set BaseDir to the unique temporary directory.
	BaseDir = tempDir

	// run the tests
	code := m.Run()
	// remove BaseDir
	if err := os.RemoveAll(BaseDir); err != nil {
		panic(err)
	}
	os.Exit(code)
}

func TestLoadArtifact(t *testing.T) {
	c := qt.New(t)
	// create a dummy key server
	server := testDummyKeyServer()
	defer server.Close()
	// get the expected hash
	hashFn := sha256.New()
	hashFn.Write(dummyKeyContent)
	expectedHash := hashFn.Sum(nil)
	// create a dummy key
	remoteURL, err := url.JoinPath(server.URL, dummyPath)
	c.Assert(err, qt.IsNil)
	dummyArtifact := &Artifact{
		RemoteURL: remoteURL,
		Hash:      expectedHash,
	}
	// test no downloaded file
	c.Assert(dummyArtifact.Load(), qt.IsNotNil)
	// test downloaded file
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c.Assert(dummyArtifact.Download(ctx), qt.IsNil)
	c.Assert([]byte(dummyArtifact.Content), qt.DeepEquals, dummyArtifact.Content)
	// test downloaded file but no locally stored file
	dummyArtifact.Content = nil
	c.Assert(dummyArtifact.Load(), qt.IsNil)
	c.Assert([]byte(dummyArtifact.Content), qt.DeepEquals, dummyArtifact.Content)
	// test wrong hash
	dummyArtifact.Content = nil
	dummyArtifact.Hash = []byte("wrong hash")
	c.Assert(dummyArtifact.Load(), qt.IsNotNil)
}
