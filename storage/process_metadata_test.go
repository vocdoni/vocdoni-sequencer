package storage

import (
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	qt "github.com/frankban/quicktest"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
	"go.vocdoni.io/dvote/db"
	"go.vocdoni.io/dvote/db/metadb"
)

func TestProcessMetadata(t *testing.T) {
	c := qt.New(t)
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "db")

	db, err := metadb.New(db.TypePebble, dbPath)
	c.Assert(err, qt.IsNil)

	st := New(db)
	defer st.Close()

	// Create a test process ID
	processID := types.ProcessID{
		Address: common.Address{},
		Nonce:   42,
		ChainID: 1,
	}

	// Test 1: Get non-existent metadata
	metadata, err := st.ProcessMetadata(processID)
	c.Assert(err, qt.Equals, ErrNotFound)
	c.Assert(metadata, qt.IsNil)

	// Test 2: Set and get metadata
	testMetadata := &types.Metadata{
		Title:       map[string]string{"default": "Test Election"},
		Description: map[string]string{"default": "Test Description"},
		Media: types.MediaMetadata{
			Header: "header.jpg",
			Logo:   "logo.jpg",
		},
		Questions: []types.Question{
			{
				Title:       map[string]string{"default": "Question 1"},
				Description: map[string]string{"default": "Description 1"},
				Choices: []types.Choice{
					{
						Title: map[string]string{"default": "Choice 1"},
						Value: 0,
					},
					{
						Title: map[string]string{"default": "Choice 2"},
						Value: 1,
					},
				},
			},
		},
	}

	err = st.SetProcess(processID, testMetadata)
	c.Assert(err, qt.IsNil)

	// Get and verify metadata
	retrievedMetadata, err := st.ProcessMetadata(processID)
	c.Assert(err, qt.IsNil)
	c.Assert(retrievedMetadata, qt.Not(qt.IsNil))
	c.Assert(retrievedMetadata.Title["default"], qt.Equals, testMetadata.Title["default"])
	c.Assert(retrievedMetadata.Description["default"], qt.Equals, testMetadata.Description["default"])
	c.Assert(retrievedMetadata.Questions[0].Title["default"], qt.Equals, testMetadata.Questions[0].Title["default"])
	c.Assert(len(retrievedMetadata.Questions[0].Choices), qt.Equals, len(testMetadata.Questions[0].Choices))

	// Test 3: List processes
	processes, err := st.ListProcesses()
	c.Assert(err, qt.IsNil)
	c.Assert(len(processes), qt.Equals, 1)
	c.Assert(processes[0], qt.DeepEquals, processID.Marshal())

	// Test 4: Set another process
	anotherProcessID := types.ProcessID{
		Address: common.Address{1},
		Nonce:   43,
		ChainID: 1,
	}

	err = st.SetProcess(anotherProcessID, testMetadata)
	c.Assert(err, qt.IsNil)

	// Verify list now contains both processes
	processes, err = st.ListProcesses()
	c.Assert(err, qt.IsNil)
	c.Assert(len(processes), qt.Equals, 2)

	// Test 5: MetadataHash function
	hash1 := MetadataHash(testMetadata)
	c.Assert(hash1, qt.Not(qt.IsNil))
	c.Assert(len(hash1), qt.Equals, 32) // Ethereum hash length is 32 bytes

	// Modify metadata and verify hash changes
	testMetadata.Title["default"] = "Modified Title"
	hash2 := MetadataHash(testMetadata)
	c.Assert(hash2, qt.Not(qt.IsNil))
	c.Assert(hash2, qt.Not(qt.DeepEquals), hash1)
}
