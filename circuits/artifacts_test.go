package circuits

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	// run the tests
	code := m.Run()
	// remove BaseDir
	if err := os.RemoveAll(BaseDir); err != nil {
		panic(err)
	}
	os.Exit(code)
}

func TestLoadKey(t *testing.T) {
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
	dummyKey := &Artifact{
		RemoteURL: remoteURL,
		Hash:      expectedHash,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// test no downloaded file
	c.Assert(dummyKey.Load(ctx), qt.IsNil)
	c.Assert([]byte(dummyKey.Content), qt.DeepEquals, dummyKeyContent)
	// test downloaded file but no locally stored file
	dummyKey.Content = nil
	c.Assert(dummyKey.Load(ctx), qt.IsNil)
	c.Assert([]byte(dummyKey.Content), qt.DeepEquals, dummyKeyContent)
	// test wrong hash
	dummyKey.Content = nil
	dummyKey.Hash = []byte("wrong hash")
	c.Assert(dummyKey.Load(ctx), qt.IsNotNil)
}
