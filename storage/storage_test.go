package storage

import (
	"testing"

	qt "github.com/frankban/quicktest"
	"go.vocdoni.io/dvote/db/metadb"
)

func TestMetadata(t *testing.T) {
	c := qt.New(t)

	stg := New(metadb.NewTest(t))

	metadata := &Metadata{
		Title: MultilingualString{
			"default": "Test",
		},
		Description: MultilingualString{
			"default": "Test description",
		},
		Media: MediaMetadata{
			Header: "https://example.com/header.png",
			Logo:   "https://example.com/logo.png",
		},
		Questions: []Question{
			{
				Title: MultilingualString{
					"default": "Question 1",
				},
				Description: MultilingualString{
					"default": "Question 1 description",
				},
				Choices: []Choice{
					{
						Title: MultilingualString{
							"default": "Choice 1",
						},
						Value: 1,
						Meta: GenericMetadata{
							"key": "value",
						},
						Results: "test",
						Answer:  1,
					},
				},
				NumAbstains: 0,
				Meta: GenericMetadata{
					"key": "value",
				},
			},
		},
		ProcessType: ProcessType{
			Name: "test",
			Properties: GenericMetadata{
				"key": "value",
			},
		},
		BallotMode: BallotMode{
			MaxCount:       1,
			MaxValue:       1,
			MinValue:       1,
			UniqueValues:   true,
			MaxTotalCost:   1,
			MinTotalCost:   1,
			CostExponent:   0,
			CostFromWeight: true,
		},
	}
	key, err := stg.SetMetadata(metadata)
	c.Assert(err, qt.IsNil)
	res, err := stg.GetMetadata(key)
	c.Assert(err, qt.IsNil)
	c.Assert(res, qt.DeepEquals, metadata)
}
