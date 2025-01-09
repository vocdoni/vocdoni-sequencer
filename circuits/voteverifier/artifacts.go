package voteverifier

import (
	"github.com/vocdoni/vocdoni-z-sandbox/circuits"
	"github.com/vocdoni/vocdoni-z-sandbox/types"
)

var Artifacts = circuits.NewCircuitArtifacts(
	&circuits.Artifact{
		RemoteURL: "https://media.githubusercontent.com/media/vocdoni/vocdoni-circuits-artifacts/main/voteverifier/voteverifier.pk",
		Hash:      types.HexStringToHexBytes("4bcb2de78562f400a3f96e5adcdcc00d32ebd0e29c7af4145f857f05281eb9e8"),
	},
	&circuits.Artifact{
		RemoteURL: "https://media.githubusercontent.com/media/vocdoni/vocdoni-circuits-artifacts/main/voteverifier/voteverifier.vk",
		Hash:      types.HexStringToHexBytes("a3a3874b6a1d4c568f6ee0d221e3213bf408f4e66d67e3f1eaf3c73f02994309"),
	},
)
